"""FastAPI app: dashboard + JSON API + live SSE stream (localhost only, token-protected)."""
import asyncio
import json
from contextlib import asynccontextmanager
import os
import platform
import secrets
import time
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import actions, alerts, autostart, db, osinfo, rules, state
from .config import DASHBOARD_DIR, HOST, PORT, SEVERITY_ORDER, TOKEN_PATH, VERSION, WATCHLIST_PATH

OS_LABEL = osinfo.os_label()
_ui_callbacks = {}  # set by the desktop app: {"show": callable}


def register_ui(show=None):
    if show:
        _ui_callbacks["show"] = show


def load_token():
    if TOKEN_PATH.exists():
        t = TOKEN_PATH.read_text().strip()
        if len(t) >= 32:
            return t
    t = secrets.token_urlsafe(32)
    # create the file readable by this user only (0600 on macOS/Linux; per-user profile ACL on Windows)
    fd = os.open(TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(t)
    return t


TOKEN = load_token()
ALLOWED_HOSTS = {f"{HOST}:{PORT}", f"localhost:{PORT}"}


@asynccontextmanager
async def _lifespan(_app):
    alerts.bind_loop(asyncio.get_running_loop())  # lets collector threads push live events to SSE clients
    yield


app = FastAPI(title="PC Sentinel", docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)


MAX_BODY = 64 * 1024


@app.middleware("http")
async def guard(request: Request, call_next):
    """Defence in depth for a localhost API that can kill processes and change firewall rules:
    Host allow-list (DNS rebinding), per-install secret token (other local apps / web pages), small bodies."""
    if request.headers.get("host", "") not in ALLOWED_HOSTS:
        return JSONResponse({"error": "forbidden host"}, status_code=403)
    path = request.url.path
    if path.startswith("/api/"):
        tok = request.headers.get("x-sentinel-token")
        if path == "/api/stream":  # EventSource cannot send headers; the token may only travel in the URL here
            tok = tok or request.query_params.get("token")
        if not tok or not secrets.compare_digest(tok.encode(), TOKEN.encode()):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if request.method not in ("GET", "POST"):
            return JSONResponse({"error": "method not allowed"}, status_code=405)
        try:
            if int(request.headers.get("content-length") or 0) > MAX_BODY:
                return JSONResponse({"error": "request too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"error": "bad content-length"}, status_code=400)
    resp = await call_next(request)
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                               "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                                               "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    if path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------- dashboard
def _index():
    try:
        html = (DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")
    except OSError:
        return HTMLResponse("<h1>PC Sentinel</h1><p>Dashboard files are missing from this install.</p>", status_code=503)
    return HTMLResponse(html.replace("__SENTINEL_TOKEN__", TOKEN), headers={"Cache-Control": "no-store"})


@app.get("/", include_in_schema=False)
def index():
    return _index()


@app.get("/index.html", include_in_schema=False)
def index2():
    return _index()


# ---------------------------------------------------------------- helpers
def risk(open_counts, cov):
    s = open_counts.get("critical", 0) * 30 + open_counts.get("high", 0) * 12 + \
        open_counts.get("medium", 0) * 4 + open_counts.get("low", 0) * 1
    s = min(100, s)
    label = "Low" if s < 10 else "Guarded" if s < 25 else "Elevated" if s < 50 else "High" if s < 75 else "Severe"
    return {"score": s, "label": label}


def compute_summary():
    counts = {r["severity"]: r["n"] for r in db.query(
        "SELECT severity, COUNT(*) n FROM alerts WHERE status='open' GROUP BY severity")}
    with state.lock:
        procs = len(state.procs)
        conns = list(state.connections)
        listen = list(state.listening)
        thr = dict(state.throughput)
        priv = json.loads(json.dumps(state.privacy))
        cov = dict(state.coverage)
        dfd = {k: v for k, v in state.defender.items() if k != "exclusions"}
    remote24 = db.query_one("SELECT COUNT(*) n FROM destinations WHERE last_seen >= ?", (db.ago(hours=24),))["n"]
    return {
        "engine": {"version": VERSION, "started": datetime.fromtimestamp(state.started).isoformat(timespec="seconds"),
                   "uptime_s": int(time.time() - state.started), "host": platform.node(),
                   "user": os.environ.get("USERNAME") or os.environ.get("USER"), "elevated": state.elevated,
                   "platform": osinfo.PLATFORM, "os": OS_LABEL},
        "coverage": {k: (v if osinfo.COVERAGE_SUPPORTED.get(k, True) else False) for k, v in cov.items()},
        "coverage_supported": dict(osinfo.COVERAGE_SUPPORTED),
        "defender": dfd,
        "kpis": {"alerts_open": {k: counts.get(k, 0) for k in ("critical", "high", "medium", "low")},
                 "processes": procs, "connections": len(conns),
                 "listening_exposed": len({(lis["lport"], lis["proto"]) for lis in listen if lis["exposed"]}),
                 "remote_hosts_24h": remote24, "apps_online": len({c["exe"] or c["process"] for c in conns}),
                 "camera_in_use": priv["webcam"]["in_use"], "mic_in_use": priv["microphone"]["in_use"]},
        "throughput": {"rx_bps": thr.get("rx_bps", 0), "tx_bps": thr.get("tx_bps", 0)},
        "risk": risk(counts, cov),
    }


def _alert_rows(sql, params):
    out = []
    for r in db.query(sql, params):
        for k in ("process", "remote", "details"):
            r[k] = json.loads(r[k]) if r.get(k) else None
        r.pop("key", None)
        out.append(r)
    return out


# ---------------------------------------------------------------- API
@app.get("/api/summary")
def api_summary():
    return compute_summary()


@app.get("/api/metrics")
def api_metrics(minutes: int = 60):
    minutes = max(1, min(minutes, 1440))
    return {"points": db.query("SELECT t, rx_bps, tx_bps, cpu, conns FROM metrics WHERE t >= ? ORDER BY t",
                               (db.ago(minutes=minutes),))}


@app.get("/api/alerts")
def api_alerts(status: str = "open", severity: str = "", category: str = "", q: str = "", limit: int = 200):
    # every user value goes in as a bound parameter; only fixed SQL fragments and '?' placeholders are joined
    where, params = [], []
    if status != "all":
        where.append("status=?")
        params.append(status)
    if severity:
        sev = [s for s in severity.split(",") if s in SEVERITY_ORDER]
        if sev:
            where.append("severity IN (" + ",".join("?" * len(sev)) + ")")
            params += sev
    if category:
        where.append("category=?")
        params.append(category)
    if q:
        where.append("(title LIKE ? OR summary LIKE ? OR process LIKE ? OR remote LIKE ?)")
        params += [f"%{q}%"] * 4
    sql = ("SELECT * FROM alerts" + (" WHERE " + " AND ".join(where) if where else "")  # nosec B608 (bound placeholders only) # noqa: S608 (placeholders only)
           + " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3"
           + " ELSE 4 END, last_ts DESC LIMIT ?")
    return {"items": _alert_rows(sql, params + [max(1, min(limit, 2000))])}


@app.post("/api/alerts/{alert_id}/ack")
def api_ack(alert_id: int):
    alerts.ack(alert_id)
    return {"ok": True}


@app.post("/api/alerts/ack_all")
async def api_ack_all(request: Request):
    body = await _json(request)
    n = alerts.ack_all(body.get("severity"))
    return {"ok": True, "count": n}


@app.get("/api/network/connections")
def api_connections():
    with state.lock:
        return {"items": list(state.connections)}


@app.get("/api/network/apps")
def api_apps():
    with state.lock:
        conns = list(state.connections)
    apps = {}
    for c in conns:
        k = (c["exe"] or c["process"] or str(c["pid"])).lower()
        a = apps.setdefault(k, {"process": c["process"], "exe": c["exe"], "signer": c["signer"], "trust": c["trust"],
                                "conns": 0, "_hosts": set(), "_ports": set(), "_flags": set()})
        a["conns"] += 1
        a["_hosts"].add(c["raddr"])
        a["_ports"].add(c["rport"])
        a["_flags"].update(c["flags"])
    out = []
    for k, a in apps.items():
        row = db.query_one("SELECT first_seen, net_first_seen FROM seen_apps WHERE exe=?", (k,)) or {}
        out.append({"process": a["process"], "exe": a["exe"], "signer": a["signer"], "trust": a["trust"],
                    "conns": a["conns"], "remote_hosts": len(a["_hosts"]), "ports": sorted(a["_ports"])[:20],
                    "first_seen": row.get("net_first_seen") or row.get("first_seen"), "last_seen": db.now(),
                    "flags": sorted(a["_flags"])})
    out.sort(key=lambda x: -x["conns"])
    return {"items": out}


@app.get("/api/network/destinations")
def api_destinations(hours: int = 24):
    bl = {r["ip"] for r in db.query("SELECT ip FROM blocklist")}
    rows = db.query("SELECT * FROM destinations WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT 1500",
                    (db.ago(hours=max(1, min(hours, 720))),))
    for r in rows:
        r["ports"] = json.loads(r["ports"])
        r["apps"] = json.loads(r["apps"])
        r["blocklisted"] = r["ip"] in bl
        r["private"] = rules.is_private(r["ip"])
    return {"items": rows}


@app.get("/api/network/listening")
def api_listening():
    with state.lock:
        items = [dict(lis) for lis in state.listening]
    seen = set()
    out = []
    for lis in items:
        k = (lis["proto"], lis["laddr"], lis["lport"], lis["pid"])
        if k in seen:
            continue
        seen.add(k)
        out.append(lis)
    out.sort(key=lambda x: (not x["exposed"], x["lport"]))
    return {"items": out}


@app.get("/api/dns")
def api_dns(limit: int = 300):
    with state.lock:
        enabled = state.coverage.get("dns_log", False)
    return {"enabled": enabled,
            "items": db.query("SELECT ts, pid, process, query, type, result FROM dns ORDER BY id DESC LIMIT ?",
                              (max(1, min(limit, 5000)),))}


@app.get("/api/processes")
def api_processes(filter: str = "all"):  # noqa: A002
    with state.lock:
        procs = [dict(p) for p in state.procs.values()]
        nconn = {}
        for c in state.connections:
            nconn[c["pid"]] = nconn.get(c["pid"], 0) + 1
    out = []
    for p in procs:
        a = p.get("assess") or {}
        item = {k: p.get(k) for k in ("pid", "ppid", "parent", "name", "exe", "cmdline", "user", "started", "cpu", "mem_mb")}
        item.update({"signer": a.get("signer"), "sig_status": a.get("sig_status", "Unknown"),
                     "trust": a.get("trust", "known"), "flags": a.get("flags", []), "net_conns": nconn.get(p["pid"], 0)})
        if filter == "flagged" and not (item["flags"] and item["flags"] != ["unsigned"]) and item["trust"] not in ("malicious", "suspicious"):
            continue
        if filter == "unsigned" and item["trust"] not in ("unsigned", "suspicious", "malicious"):
            continue
        out.append(item)
    order = {"malicious": 0, "suspicious": 1, "unsigned": 2, "known": 3, "trusted": 4}
    out.sort(key=lambda x: (order.get(x["trust"], 5), -(x["cpu"] or 0)))
    return {"items": out}


@app.get("/api/privacy")
def api_privacy():
    with state.lock:
        devices = json.loads(json.dumps(state.privacy))
    hist = db.query("SELECT device, app, path, start, stop, packaged FROM privacy_hist ORDER BY start DESC LIMIT 400")
    for h in hist:
        if h["packaged"]:
            h["trust"] = "known"
        else:
            h["trust"] = rules.assess(h["path"])["trust"] if os.path.exists(h["path"]) else "unknown (file gone)"
        h["in_use"] = h["stop"] is None
        h["allowed"] = rules.allowlisted("privacy", h["path"])
        h.pop("packaged")
    return {"devices": devices, "history": hist}


@app.get("/api/persistence")
def api_persistence():
    rows = db.query("SELECT kind, location, name, command, exe, first_seen, last_seen, status FROM persistence "
                    "ORDER BY CASE status WHEN 'new' THEN 0 WHEN 'changed' THEN 1 WHEN 'removed' THEN 3 ELSE 2 END, kind, name")
    for r in rows:
        a = rules.assess(r["exe"]) if r["exe"] and os.path.exists(r["exe"]) else \
            {"signer": None, "sig_status": "Unknown", "trust": "known" if r["exe"] else "known", "flags": []}
        if r["exe"] and not os.path.exists(r["exe"]):
            a["flags"] = ["missing_file"]
        r.update({"signer": a.get("signer"), "sig_status": a.get("sig_status"), "trust": a.get("trust"),
                  "flags": a.get("flags", [])})
    return {"items": rows}


@app.get("/api/files")
def api_files():
    try:
        watched = json.loads(WATCHLIST_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        watched = []
    with state.lock:
        audit = state.coverage.get("file_audit", False)
    w_out = [{"path": w["path"], "label": w["label"], "kind": w["kind"], "audited": audit,
              "exists": os.path.exists(w["path"])} for w in watched]
    acc = db.query("SELECT ts, path, label, kind, process, pid, exe, access, expected FROM file_access ORDER BY id DESC LIMIT 500")
    for a in acc:
        a["expected"] = bool(a["expected"])
    return {"audit_enabled": audit, "watched": w_out, "access": acc}


@app.get("/api/events")
def api_events(category: str = "", limit: int = 300):
    if category:
        rows = db.query("SELECT id, ts, severity, category, title, summary FROM events WHERE category=? ORDER BY id DESC LIMIT ?",
                        (category, max(1, min(limit, 5000))))
    else:
        rows = db.query("SELECT id, ts, severity, category, title, summary FROM events ORDER BY id DESC LIMIT ?",
                        (max(1, min(limit, 5000)),))
    return {"items": rows}


@app.get("/api/settings")
def api_settings():
    return {"allowlist": db.query("SELECT id, kind, value, note, ts FROM allowlist ORDER BY id DESC"),
            "blocklist": db.query("SELECT id, ip, note, ts FROM blocklist ORDER BY id DESC"),
            "notify": alerts.notify_settings(),
            "autostart": autostart.status()}


@app.post("/api/app/show")
def api_app_show():
    """Used by a second launch of the desktop app to bring the existing window forward."""
    fn = _ui_callbacks.get("show")
    if fn:
        fn()
        return {"ok": True}
    return {"ok": False, "message": "no window attached"}


@app.get("/api/graph")
def api_graph():
    """Live Map: this PC -> processes (grouped per exe) -> remote destinations, plus parent->child spawn links."""
    with state.lock:
        procs = {pid: dict(p) for pid, p in state.procs.items()}
        conns = list(state.connections)
        listen = list(state.listening)
    bl = {r["ip"] for r in db.query("SELECT ip FROM blocklist")}

    def pid_key(pid):
        p = procs.get(pid) or {}
        return "p:" + ((p.get("exe") or p.get("name") or f"pid{pid}").lower())

    nodes = {"host": {"id": "host", "type": "host", "label": platform.node()}}
    edges = {}

    def add_proc(pid):
        k = pid_key(pid)
        p = procs.get(pid) or {}
        a = p.get("assess") or {}
        n = nodes.get(k)
        if not n:
            label = p.get("name") or ("(system / other user)" if pid is None else f"PID {pid}")
            n = nodes[k] = {"id": k, "type": "process", "label": label, "exe": p.get("exe"),
                            "pids": [], "trust": a.get("trust", "known"), "signer": a.get("signer"),
                            "sig_status": a.get("sig_status", "Unknown"), "conns": 0, "cpu": 0.0, "mem_mb": 0.0,
                            "flags": list(a.get("flags", [])), "parent": p.get("parent")}
            edges[("host", k, "host")] = {"source": "host", "target": k, "kind": "host"}
        if pid not in n["pids"]:
            n["pids"].append(pid)
            n["cpu"] = round(n["cpu"] + (p.get("cpu") or 0), 1)
            n["mem_mb"] = round(n["mem_mb"] + (p.get("mem_mb") or 0), 1)
        return k

    for c in conns:
        if c["pid"] == 0 or not c.get("raddr"):
            continue
        pk = add_proc(c["pid"])
        nodes[pk]["conns"] += 1
        rk = "r:" + c["raddr"]
        if rk not in nodes:
            nodes[rk] = {"id": rk, "type": "remote", "label": c.get("rhost") or c["raddr"], "ip": c["raddr"],
                         "host": c.get("rhost"), "ports": [], "blocklisted": c["raddr"] in bl,
                         "private": rules.is_private(c["raddr"])}
        if c["rport"] not in nodes[rk]["ports"]:
            nodes[rk]["ports"].append(c["rport"])
        ek = (pk, rk, "net")
        e = edges.get(ek)
        if not e:
            e = edges[ek] = {"source": pk, "target": rk, "kind": "net", "count": 0, "ports": [], "direction": c["direction"],
                             "states": [], "danger": False}
        e["count"] += 1
        if c["rport"] not in e["ports"]:
            e["ports"].append(c["rport"])
        if c["status"] and c["status"] not in e["states"]:
            e["states"].append(c["status"])
        if c["direction"] == "in":
            e["direction"] = "in"
        if nodes[rk]["blocklisted"] or nodes[pk]["trust"] in ("malicious", "suspicious"):
            e["danger"] = True
    for lis in listen:
        if lis["exposed"] and lis["pid"]:
            add_proc(lis["pid"])
    # parent -> child spawn links between processes already on the map (adds the parent if needed)
    for k, n in list(nodes.items()):
        if n["type"] != "process":
            continue
        for pid in n["pids"]:
            ppid = (procs.get(pid) or {}).get("ppid")
            if ppid and ppid in procs and ppid != pid:
                pk = add_proc(ppid)
                if pk != k:
                    edges[(pk, k, "spawn")] = {"source": pk, "target": k, "kind": "spawn"}
                break
    return {"generated": db.now(), "nodes": list(nodes.values()), "edges": list(edges.values())}


async def _json(request):
    try:
        return await request.json()
    except Exception:  # noqa: BLE001
        return {}


@app.post("/api/actions/{name}")
async def api_action(name: str, request: Request):
    b = await _json(request)
    fn = {
        "kill": lambda: actions.kill(b.get("pid")),
        "block_ip": lambda: actions.block_ip(str(b.get("ip", "")).strip(), b.get("note", "")),
        "allow": lambda: actions.allow(b.get("kind"), b.get("value"), b.get("note", "")),
        "unallow": lambda: actions.unallow(b.get("id")),
        "blocklist": lambda: actions.add_blocklist(str(b.get("ip", "")).strip(), b.get("note", "")),
        "unblocklist": lambda: actions.remove_blocklist(b.get("id")),
        "notify": lambda: actions.set_notify(b.get("enabled", False), b.get("min_severity", "high")),
        "autostart": lambda: actions.set_autostart(bool(b.get("enabled", False))),
    }.get(name)
    if not fn:
        return JSONResponse({"ok": False, "message": "unknown action"}, status_code=404)
    return await asyncio.to_thread(fn)


@app.get("/api/stream")
async def api_stream(request: Request):
    q = alerts.subscribe()

    async def gen():
        try:
            yield "retry: 3000\n\n"
            yield f"event: summary\ndata: {json.dumps(compute_summary(), default=str)}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event, data = await asyncio.wait_for(q.get(), timeout=15)
                    yield f"event: {event}\ndata: {data}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            alerts.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# static assets (styles.css, app.js, …) — mounted last so the routes above win
app.mount("/", StaticFiles(directory=str(DASHBOARD_DIR), html=False, check_dir=False), name="dashboard")
