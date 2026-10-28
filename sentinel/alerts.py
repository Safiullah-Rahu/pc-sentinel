"""Alert de-duplication, timeline events, live broadcast (SSE) and Windows toast notifications."""
import asyncio
import json
import logging
import threading

from . import db

log = logging.getLogger("sentinel.alerts")

# ---------------------------------------------------------------- live broadcast to SSE clients
_loop = None
_subscribers = set()
_sub_lock = threading.Lock()


def bind_loop(loop):
    global _loop
    _loop = loop


def subscribe():
    q = asyncio.Queue(maxsize=500)
    with _sub_lock:
        _subscribers.add(q)
    return q


def unsubscribe(q):
    with _sub_lock:
        _subscribers.discard(q)


def broadcast(event, data):
    if not _loop:
        return
    msg = (event, json.dumps(data, default=str))

    def _put():
        with _sub_lock:
            subs = list(_subscribers)
        for q in subs:
            if q.full():
                continue
            q.put_nowait(msg)
    _loop.call_soon_threadsafe(_put)


# ---------------------------------------------------------------- opt-in desktop notifications (default OFF)
_toast_times = []
_toast_lock = threading.Lock()
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def notify_settings():
    cfg = db.kv_get("notify", {}) or {}
    return {"enabled": bool(cfg.get("enabled", False)), "min_severity": cfg.get("min_severity", "high")}


def _toast(severity, title, summary):
    cfg = notify_settings()
    if not cfg["enabled"] or SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(cfg["min_severity"], 3):
        return
    import time
    with _toast_lock:
        now = time.time()
        _toast_times[:] = [t for t in _toast_times if now - t < 60]
        if len(_toast_times) >= 5:  # never flood the desktop
            return
        _toast_times.append(now)

    head = f"[{severity.upper()}] {title}"[:120]
    body = (summary or "")[:240]

    def _show():
        import shutil
        import subprocess
        import sys

        from .config import FROZEN, ICON_PATH
        from .osinfo import IS_MAC, IS_WIN
        try:
            if IS_WIN:
                from winotify import Notification, audio
                n = Notification(app_id="PC Sentinel", title=head, msg=body,
                                 icon=str(ICON_PATH) if ICON_PATH.exists() else "",
                                 duration="long" if severity == "critical" else "short",
                                 launch=sys.executable if FROZEN else "")  # click opens the app window
                n.set_audio(audio.Default, loop=False)
                n.show()
            elif IS_MAC:
                # alert text travels as osascript arguments (argv), never spliced into the script source
                script = 'on run argv\ndisplay notification (item 2 of argv) with title "PC Sentinel" subtitle (item 1 of argv)\nend run'
                subprocess.run(["osascript", "-e", script, head, body], timeout=10, capture_output=True)
            elif shutil.which("notify-send"):
                subprocess.run(["notify-send", "--app-name=PC Sentinel",
                                "--urgency=critical" if severity == "critical" else "--urgency=normal", head, body],
                               timeout=10, capture_output=True)
        except Exception as e:  # noqa: BLE001
            log.debug("toast failed: %s", e)
    threading.Thread(target=_show, daemon=True).start()

# ---------------------------------------------------------------- public API
def _row_to_alert(r):
    if not r:
        return None
    a = dict(r)
    for k in ("process", "remote", "details"):
        a[k] = json.loads(a[k]) if a.get(k) else None
    a.pop("key", None)
    return a


def get_alert(alert_id):
    return _row_to_alert(db.query_one("SELECT * FROM alerts WHERE id=?", (alert_id,)))


def log_event(severity, category, title, summary="", alert_id=None):
    db.execute("INSERT INTO events(ts,severity,category,title,summary,alert_id) VALUES(?,?,?,?,?,?)",
               (db.now(), severity, category, title, summary, alert_id))


def raise_alert(key, severity, category, title, summary="", process=None, remote=None, details=None,
                allow_kind=None, allow_value=None):
    """Create or bump an alert. Returns the alert id (or None when suppressed by the allowlist)."""
    from .rules import allowlisted
    if allow_kind and allow_value and allowlisted(allow_kind, allow_value):
        return None
    ts = db.now()
    row = db.query_one("SELECT id, status, count FROM alerts WHERE key=?", (key,))
    if row:
        if row["status"] == "allowed":
            return None
        db.execute("UPDATE alerts SET last_ts=?, count=count+1, ts=? WHERE id=?", (ts, ts, row["id"]))
        if (row["count"] + 1) in (10, 100, 1000):
            broadcast("alert", get_alert(row["id"]))
        return row["id"]
    cur = db.execute(
        "INSERT INTO alerts(key,ts,first_ts,last_ts,count,severity,category,title,summary,process,remote,details,status)"
        " VALUES(?,?,?,?,1,?,?,?,?,?,?,?,'open')",
        (key, ts, ts, ts, severity, category, title, summary,
         json.dumps(process) if process else None, json.dumps(remote) if remote else None,
         json.dumps(details) if details else None))
    alert_id = cur.lastrowid
    log_event(severity, category, title, summary, alert_id)
    log.warning("ALERT [%s] %s — %s", severity, title, summary)
    broadcast("alert", get_alert(alert_id))
    _toast(severity, title, summary)
    return alert_id


def ack(alert_id):
    db.execute("UPDATE alerts SET status='acknowledged' WHERE id=? AND status='open'", (alert_id,))


def ack_all(severity=None):
    if severity:
        cur = db.execute("UPDATE alerts SET status='acknowledged' WHERE status='open' AND severity=?", (severity,))
    else:
        cur = db.execute("UPDATE alerts SET status='acknowledged' WHERE status='open'")
    return cur.rowcount


def mark_allowed_where(kind, value):
    """When the user allowlists something, close matching open alerts."""
    v = (value or "").lower()
    rows = db.query("SELECT id, process, remote FROM alerts WHERE status!='allowed'")
    n = 0
    for r in rows:
        p = json.loads(r["process"]) if r["process"] else {}
        rem = json.loads(r["remote"]) if r["remote"] else {}
        hit = (kind in ("process", "privacy", "persistence") and (p.get("exe") or "").lower() == v) or \
              (kind == "destination" and (rem.get("ip") or "").lower() == v)
        if hit:
            db.execute("UPDATE alerts SET status='allowed' WHERE id=?", (r["id"],))
            n += 1
    return n
