"""Process monitor: new processes, signature/trust assessment, suspicious traits."""
import logging
import os
import time
from datetime import datetime

import psutil

from .. import alerts, db, rules, signatures, state
from ..config import PROC_INTERVAL

log = logging.getLogger("sentinel.proc")
_alerted = set()  # (pid, create_time, rule)


def _iso(ts):
    try:
        return datetime.fromtimestamp(ts).isoformat(timespec="seconds")
    except (OSError, OverflowError, ValueError):
        return None


def evaluate(p, first_pass=False):
    """Raise alerts for one process dict. Called on start and again once its signature is known."""
    a = rules.assess(p["exe"], p.get("cmdline") or "")
    p["assess"] = a
    flags, trust = a["flags"], a["trust"]
    if not p["exe"] or a["sig_status"] == "Unknown":
        return
    ref = state.proc_ref(p["pid"])
    ident = (p["pid"], p["create_time"])
    exe = p["exe"]
    name = p["name"]

    def fire(rule, severity, title, summary, extra=None):
        if (ident, rule) in _alerted:
            return
        _alerted.add((ident, rule))
        alerts.raise_alert(f"proc|{rule}|{exe.lower()}", severity, "process", title, summary, process=ref,
                           details={"rule": rule, "cmdline": p.get("cmdline"), "parent": p.get("parent"),
                                    "sha256": a.get("sha256"), **(extra or {})},
                           allow_kind=None if rule in ("known_bad_hash", "sig_mismatch") else "process",
                           allow_value=exe)

    if "known_bad_hash" in flags:
        fire("known_bad_hash", "critical", f"Known malware running: {name}",
             f"{name} matches a known-bad sample ({a.get('note')}). Path: {exe}")
    elif "sig_mismatch" in flags:
        fire("sig_mismatch", "critical", f"Tampered/forged signature: {name}",
             f"{name} carries a digital signature that does not match its contents (claims {a.get('signer')}). "
             f"This is a classic malware disguise. Path: {exe}")
    if "padded_binary" in flags:
        fire("padded_binary", "high", f"Oversized unsigned program: {name}",
             f"{name} is {os.path.getsize(exe) // (1024 * 1024)} MB and not validly signed — malware pads files "
             f"to dodge antivirus size limits. Path: {exe}")
    if "hidden_dir" in flags:
        fire("hidden_dir", "high", f"Program running from a hidden folder: {name}",
             f"{name} runs from a folder marked Hidden inside your profile. Path: {exe}")
    if trust == "suspicious" and "user_writable_path" in flags and "unsigned" in flags:
        fire("unsigned_odd_path", "high", f"Unsigned program in {a.get('note')}: {name}",
             f"{name} is not signed and runs from a location legitimate software rarely uses ({a.get('note')}). "
             f"Path: {exe}")
    if "lolbin" in flags:
        fire("lolbin", "high", f"Suspicious command line: {name}",
             f"A built-in Windows tool was started with arguments typical of malware: {(p.get('cmdline') or '')[:300]}")

    # first ever run of a program we have never seen (after the baseline)
    seen = db.query_one("SELECT exe FROM seen_apps WHERE exe=?", (exe.lower(),))
    if not seen:
        db.execute("INSERT OR IGNORE INTO seen_apps(exe, first_seen, last_seen) VALUES(?,?,?)",
                   (exe.lower(), db.now(), db.now()))
        if db.kv_get("baseline_done") and not first_pass:
            sev = "low" if trust in ("unsigned", "known") else ("info" if trust == "trusted" else "medium")
            if sev == "info":
                alerts.log_event("info", "process", f"New program first run: {name}", exe)
            else:
                fire("first_run", sev, f"New program first run: {name}",
                     f"First time this program has run on this PC ({trust}). Path: {exe}")


def _on_sig(path, status, signer, sha):
    key = path.lower()
    with state.lock:
        targets = [p for p in state.procs.values() if (p.get("exe") or "").lower() == key]
    for p in targets:
        try:
            evaluate(p)
        except Exception:  # noqa: BLE001
            log.exception("evaluate after signature failed")


signatures.on_result(_on_sig)


def run(stop_event):
    first = True
    last_cpu = {}
    ncpu = psutil.cpu_count() or 1
    while not stop_event.is_set():
        t0 = time.time()
        current = {}
        for pr in psutil.process_iter(["pid", "ppid", "name", "exe", "create_time", "username", "cmdline",
                                       "memory_info", "cpu_times"]):
            info = pr.info
            pid = info["pid"]
            ct = info.get("create_time") or 0
            cmd = info.get("cmdline")
            cmdline = " ".join(cmd) if isinstance(cmd, list) else (cmd or "")
            ctimes = info.get("cpu_times")
            total_cpu = (ctimes.user + ctimes.system) if ctimes else 0.0
            prev = last_cpu.get((pid, ct))
            cpu = 0.0
            if prev:
                dt = t0 - prev[1]
                if dt > 0:
                    cpu = max(0.0, (total_cpu - prev[0]) / dt * 100 / ncpu)
            last_cpu[(pid, ct)] = (total_cpu, t0)
            mem = info.get("memory_info")
            current[pid] = {
                "pid": pid, "ppid": info.get("ppid"), "name": info.get("name"), "exe": info.get("exe"),
                "cmdline": cmdline, "user": (info.get("username") or "").split("\\")[-1] or None,
                "create_time": ct, "started": _iso(ct), "cpu": round(cpu, 1),
                "mem_mb": round(mem.rss / 1048576, 1) if mem else None,
            }
        with state.lock:
            old = state.procs
            new_pids = [pid for pid, p in current.items()
                        if pid not in old or old[pid]["create_time"] != p["create_time"]]
            for pid, p in current.items():
                if pid in old and old[pid]["create_time"] == p["create_time"]:
                    p["assess"] = old[pid].get("assess")
                parent = current.get(p["ppid"]) or old.get(p["ppid"])
                p["parent"] = parent["name"] if parent else None
            state.procs = current
            state.coverage["processes"] = True
        for pid in new_pids:
            p = current[pid]
            try:
                evaluate(p, first_pass=first)
                a = p.get("assess") or {}
                if not first and a.get("trust") not in ("trusted",) and p.get("exe"):
                    alerts.log_event("info", "process", f"Process started: {p['name']}",
                                     f"PID {pid} · {p['exe']} · parent {p.get('parent')}")
            except Exception:  # noqa: BLE001
                log.exception("evaluate failed for %s", p.get("exe"))
        # forget cpu samples of exited processes
        live = {(pid, p["create_time"]) for pid, p in current.items()}
        for k in list(last_cpu):
            if k not in live:
                del last_cpu[k]
        if first:
            db.executemany("INSERT OR IGNORE INTO seen_apps(exe, first_seen, last_seen) VALUES(?,?,?)",
                           [((p["exe"] or "").lower(), db.now(), db.now()) for p in current.values() if p["exe"]])
            first = False
        stop_event.wait(max(0.2, PROC_INTERVAL - (time.time() - t0)))
