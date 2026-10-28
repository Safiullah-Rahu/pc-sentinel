"""Network monitor: per-process connections, destinations, listeners, throughput and traffic rules."""
import json
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import psutil

from .. import alerts, db, rules, state
from ..config import COMMON_PORTS, METRIC_INTERVAL, NET_INTERVAL

log = logging.getLogger("sentinel.net")
_rdns = {}
_rdns_pool = ThreadPoolExecutor(max_workers=4)
_conn_first = {}
_pending_eval = {}  # connection key -> polls waited
_blocklist_cache = {"t": 0, "v": {}}


def blocklist():
    if time.time() - _blocklist_cache["t"] > 5:
        _blocklist_cache["v"] = {r["ip"]: r["note"] for r in db.query("SELECT ip, note FROM blocklist")}
        _blocklist_cache["t"] = time.time()
    return _blocklist_cache["v"]


def invalidate_blocklist():
    _blocklist_cache["t"] = 0


def _resolve(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        host = None
    _rdns[ip] = host
    if host:
        db.execute("UPDATE destinations SET host=? WHERE ip=?", (host, ip))


def rhost(ip):
    if ip in _rdns:
        return _rdns[ip]
    _rdns[ip] = None
    _rdns_pool.submit(_resolve, ip)
    return None


def _all_connections():
    """System-wide sockets. macOS refuses that without root, so fall back to asking each process we can see."""
    try:
        return psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        out = []
        for p in psutil.process_iter(["pid"]):
            try:
                for c in p.net_connections(kind="inet"):
                    out.append(SimpleNamespace(fd=c.fd, family=c.family, type=c.type, laddr=c.laddr, raddr=c.raddr,
                                               status=c.status, pid=p.pid))
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
        return out


def _listening_ports():
    out = set()
    for c in state.listening:
        out.add(c["lport"])
    return out


def _update_dest(ip, port, app):
    now = db.now()
    row = db.query_one("SELECT ports, apps FROM destinations WHERE ip=?", (ip,))
    if row:
        ports = set(json.loads(row["ports"]))
        apps = set(json.loads(row["apps"]))
        ports.add(port)
        if app:
            apps.add(app)
        db.execute("UPDATE destinations SET last_seen=?, hits=hits+1, ports=?, apps=? WHERE ip=?",
                   (now, json.dumps(sorted(ports)[:50]), json.dumps(sorted(apps)[:20]), ip))
        return False
    db.execute("INSERT INTO destinations(ip,host,first_seen,last_seen,hits,ports,apps) VALUES(?,?,?,?,1,?,?)",
               (ip, _rdns.get(ip), now, now, json.dumps([port]), json.dumps([app] if app else [])))
    return True


def _evaluate(c, baseline_done):
    pid, exe, name = c["pid"], c["exe"], c["process"] or f"PID {c['pid']}"
    ref = state.proc_ref(pid)
    ip, port = c["raddr"], c["rport"]
    trust = c["trust"]
    remote = {"ip": ip, "port": port, "host": c["rhost"]}
    bl = blocklist()
    if ip in bl:
        c["flags"].append("blocklisted_ip")
        alerts.raise_alert(f"net|blocklisted|{ip}", "critical", "network",  # one alert per IP; repeats bump its count
                           f"Connection to blocklisted IP {ip}:{port}",
                           f"{name} ({ref.get('sig_status')}) is contacting a blocklisted address — {bl[ip]}.",
                           process=ref, remote=remote, details={"rule": "blocklisted_ip", "state": c["status"]})
        return
    if rules.is_private(ip):
        return
    if trust in ("malicious", "suspicious"):
        alerts.raise_alert(f"net|untrusted|{(exe or name).lower()}|{ip}", "critical" if trust == "malicious" else "high",
                           "network", f"{'Malicious' if trust == 'malicious' else 'Suspicious'} program on the internet: {name}",
                           f"{name} ({trust}, {ref.get('sig_status')}) connected to {c['rhost'] or ip}:{port}.",
                           process=ref, remote=remote, details={"rule": "untrusted_process_net", "state": c["status"]},
                           allow_kind="process", allow_value=exe)
    elif trust == "unsigned" and port not in COMMON_PORTS:
        c["flags"].append("odd_port")
        alerts.raise_alert(f"net|oddport|{(exe or name).lower()}|{port}", "medium", "network",
                           f"Unsigned app using unusual port {port}: {name}",
                           f"{name} is not signed and talks to {c['rhost'] or ip} on port {port}.",
                           process=ref, remote=remote, details={"rule": "unsigned_odd_port"},
                           allow_kind="process", allow_value=exe)


def run(stop_event):
    last_io = psutil.net_io_counters()
    last_io_t = time.time()
    last_metric = 0
    psutil.cpu_percent(None)
    first = True
    while not stop_event.is_set():
        t0 = time.time()
        baseline_done = bool(db.kv_get("baseline_done"))
        raw = _all_connections()
        with state.lock:
            procs = dict(state.procs)
        conns, listen = [], []
        # TCP listening sockets only — inbound = an established TCP socket whose local port is one we listen on
        tcp_listen = {(k.pid, k.laddr.port) for k in raw
                      if k.type == socket.SOCK_STREAM and k.status == psutil.CONN_LISTEN and k.laddr}
        for k in raw:
            p = procs.get(k.pid) or {}
            a = p.get("assess") or {}
            name = p.get("name") or ("System" if k.pid in (0, 4) else
                                     "(system / other user)" if k.pid is None else f"PID {k.pid}")
            base = {"pid": k.pid, "process": name, "exe": p.get("exe"), "signer": a.get("signer"),
                    "trust": a.get("trust", "known"), "sig_status": a.get("sig_status", "Unknown"),
                    "proto": "TCP" if k.type == socket.SOCK_STREAM else "UDP"}
            is_listen = (k.type == socket.SOCK_STREAM and k.status == psutil.CONN_LISTEN) or \
                        (k.type == socket.SOCK_DGRAM and not k.raddr and k.laddr and k.laddr.port < 49152)
            if k.type == socket.SOCK_DGRAM and not k.raddr and not is_listen:
                continue  # ephemeral UDP client sockets
            if is_listen:
                if not k.laddr:
                    continue
                exposed = k.laddr.ip not in ("127.0.0.1", "::1") and not k.laddr.ip.startswith("127.")
                listen.append({**base, "laddr": k.laddr.ip, "lport": k.laddr.port, "exposed": exposed})
                continue
            rip = k.raddr.ip if k.raddr else ""
            if not rip or rip == "::1" or rip.startswith(("127.", "::ffff:127.")):
                continue  # loopback (this PC talking to itself)
            ckey = (k.pid, k.laddr.port if k.laddr else 0, k.raddr.ip, k.raddr.port)
            new_conn = ckey not in _conn_first
            if new_conn:
                _conn_first[ckey] = db.now()
            direction = "in" if (k.laddr and (k.pid, k.laddr.port) in tcp_listen) else "out"
            c = {**base, "laddr": k.laddr.ip if k.laddr else None, "lport": k.laddr.port if k.laddr else None,
                 "raddr": k.raddr.ip, "rport": k.raddr.port, "rhost": rhost(k.raddr.ip),
                 "status": k.status if k.status != "NONE" else "", "direction": direction,
                 "first_seen": _conn_first[ckey], "flags": [], "_new": new_conn}
            conns.append(c)
        # forget closed connections
        live = {(c["pid"], c["lport"] or 0, c["raddr"], c["rport"]) for c in conns}
        for key in list(_conn_first):
            if key not in live:
                del _conn_first[key]
                _pending_eval.pop(key, None)

        new_dest_apps = {}
        for c in conns:
            try:
                ckey = (c["pid"], c["lport"] or 0, c["raddr"], c["rport"])
                if c["pid"] == 0:
                    c.pop("_new")
                    c["process"] = "(closed connection)"
                    continue  # TIME_WAIT leftovers: the real owner was already judged
                if c.pop("_new"):
                    # one destination "hit" per distinct connection
                    if _update_dest(c["raddr"], c["rport"], c["process"]):
                        c["flags"].append("first_seen")
                    _pending_eval[ckey] = 0
                if ckey in _pending_eval:
                    # judge once we know which program owns it and whether it is signed (max ~10 s wait)
                    _pending_eval[ckey] += 1
                    known = c["exe"] and c["sig_status"] != "Unknown"
                    # blocklisted contact is reported at once (short-lived connections must not slip through)
                    if known or _pending_eval[ckey] >= 4 or c["raddr"] in blocklist():
                        del _pending_eval[ckey]
                        _evaluate(c, baseline_done)
                elif c["raddr"] in blocklist() or c["trust"] in ("malicious", "suspicious"):
                    _evaluate(c, baseline_done)
                # inbound connections from outside (someone connected to us)
                if c["direction"] == "in" and not rules.is_private(c["raddr"]):
                    ref = state.proc_ref(c["pid"])
                    alerts.raise_alert(f"net|inbound|{c['lport']}|{c['raddr']}", "high", "network",
                                       f"Inbound connection from the internet to {c['process']}:{c['lport']}",
                                       f"{c['rhost'] or c['raddr']} is connected into {c['process']} on port {c['lport']}.",
                                       process=ref, remote={"ip": c["raddr"], "port": c["rport"], "host": c["rhost"]},
                                       details={"rule": "inbound_public"}, allow_kind="destination", allow_value=c["raddr"])
                if c["exe"]:
                    new_dest_apps.setdefault(c["exe"], c)
            except Exception:  # noqa: BLE001
                log.exception("connection evaluation failed")

        # first time an app ever goes online
        for exe, c in new_dest_apps.items():
            row = db.query_one("SELECT net_first_seen FROM seen_apps WHERE exe=?", (exe.lower(),))
            if row and row["net_first_seen"]:
                continue
            db.execute("INSERT INTO seen_apps(exe, first_seen, last_seen, net_first_seen) VALUES(?,?,?,?) "
                       "ON CONFLICT(exe) DO UPDATE SET net_first_seen=excluded.net_first_seen",
                       (exe.lower(), db.now(), db.now(), db.now()))
            if baseline_done and not first:
                if c["trust"] == "trusted":
                    alerts.log_event("info", "network", f"App went online for the first time: {c['process']}",
                                     f"{exe} → {c['rhost'] or c['raddr']}:{c['rport']}")
                else:
                    alerts.raise_alert(f"net|newapp|{exe.lower()}", "low" if c["trust"] == "known" else "medium",
                                       "network", f"New app went online: {c['process']}",
                                       f"First network activity seen from {exe} ({c['trust']}) → "
                                       f"{c['rhost'] or c['raddr']}:{c['rport']}.",
                                       process=state.proc_ref(c["pid"]),
                                       remote={"ip": c["raddr"], "port": c["rport"], "host": c["rhost"]},
                                       details={"rule": "new_app_online"}, allow_kind="process", allow_value=exe)

        # newly exposed listening ports
        for lis in listen:
            lkey = f"{lis['proto']}|{(lis['exe'] or lis['process'] or lis['pid'])}|{lis['lport']}".lower()
            row = db.query_one("SELECT first_seen FROM listeners WHERE key=?", (lkey,))
            if row:
                lis["first_seen"] = row["first_seen"]
                db.execute("UPDATE listeners SET last_seen=? WHERE key=?", (db.now(), lkey))
                continue
            db.execute("INSERT INTO listeners(key, first_seen, last_seen) VALUES(?,?,?)", (lkey, db.now(), db.now()))
            lis["first_seen"] = db.now()
            if baseline_done and not first and lis["exposed"] and lis["proto"] == "TCP":
                alerts.raise_alert(f"net|listen|{lkey}", "medium", "network",
                                   f"New open port {lis['lport']} by {lis['process']}",
                                   f"{lis['process']} started accepting connections on {lis['laddr']}:{lis['lport']} "
                                   f"(reachable from other machines).",
                                   process=state.proc_ref(lis["pid"]), details={"rule": "new_exposed_listener"},
                                   allow_kind="process", allow_value=lis["exe"])

        with state.lock:
            state.connections = conns
            state.listening = listen
            state.coverage["network"] = True

        # throughput + cpu metrics
        now = time.time()
        io = psutil.net_io_counters()
        dt = max(0.5, now - last_io_t)
        rx = max(0.0, (io.bytes_recv - last_io.bytes_recv) / dt)
        tx = max(0.0, (io.bytes_sent - last_io.bytes_sent) / dt)
        last_io, last_io_t = io, now
        cpu = psutil.cpu_percent(None)
        point = {"t": db.now(), "rx_bps": round(rx), "tx_bps": round(tx), "cpu": round(cpu, 1), "conns": len(conns)}
        with state.lock:
            state.throughput = point
        if now - last_metric >= METRIC_INTERVAL:
            last_metric = now
            db.execute("INSERT OR REPLACE INTO metrics(t,rx_bps,tx_bps,cpu,conns) VALUES(?,?,?,?,?)",
                       (point["t"], point["rx_bps"], point["tx_bps"], point["cpu"], point["conns"]))
            alerts.broadcast("metric", point)
        first = False
        stop_event.wait(max(0.2, NET_INTERVAL - (time.time() - t0)))
