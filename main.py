"""PC Sentinel engine: collectors + localhost dashboard server.

Normally started by the desktop app (desktop.py / the packaged app). Can also run headless on any OS:
    python main.py            (then open http://127.0.0.1:8777 — the token is in the data folder)
"""
import logging
import logging.handlers
import os
import sys
import threading
import time

import uvicorn

from sentinel import alerts, db, osinfo, signatures, singleton, state
from sentinel.collectors import eventlogs, network, persistence, privacy, processes
from sentinel.config import DEFAULT_BLOCKLIST, HOST, LOG_PATH, PORT

_engine = {}


def setup_logging():
    if sys.stdout is None or sys.stderr is None:  # windowed exe / pythonw: no console
        sink = open(os.devnull, "w", encoding="utf-8")
        sys.stdout = sys.stdout or sink
        sys.stderr = sys.stderr or sink
    root = logging.getLogger()
    if root.handlers:
        return
    root.setLevel(logging.INFO)
    fh = logging.handlers.RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(fh)
    if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
        root.addHandler(logging.StreamHandler(sys.stdout))


def engine_mutex():
    """Only one engine per user session. Returns a handle, or None if another engine runs."""
    return singleton.acquire("PCSentinelEngine")


def maintenance(stop):
    from sentinel.server import compute_summary
    last_prune = 0
    while not stop.is_set():
        try:
            alerts.broadcast("summary", compute_summary())
            if time.time() - last_prune > 3600:
                last_prune = time.time()
                db.prune()
        except Exception:  # noqa: BLE001
            logging.getLogger("sentinel").exception("maintenance failed")
        stop.wait(10)


def baseline_timer(stop):
    """First ever run: learn what is normal for 2 minutes before 'first seen' rules start alerting."""
    if db.kv_get("baseline_done"):
        return
    if not stop.wait(120):
        db.kv_set("baseline_done", db.now())
        alerts.log_event("info", "system", "Baseline learned", "PC Sentinel now alerts on new programs, apps and ports.")


def _guard(fn, name, stop):
    """Restart a collector if it crashes, so one bug never silences monitoring."""
    def runner():
        log = logging.getLogger(f"sentinel.{name}")
        while not stop.is_set():
            try:
                fn(stop)
                return
            except Exception:  # noqa: BLE001
                log.exception("collector crashed; restarting in 10 s")
                stop.wait(10)
    return runner


def start_engine(block=False):
    """Start collectors and the API server. Returns False if an engine is already running."""
    setup_logging()
    log = logging.getLogger("sentinel")
    mutex = engine_mutex()
    if mutex is None:
        log.info("engine already running in this session")
        return False
    _engine["mutex"] = mutex
    state.elevated = osinfo.is_elevated()
    for ip, note in DEFAULT_BLOCKLIST:
        db.execute("INSERT OR IGNORE INTO blocklist(ip, note, ts) VALUES(?,?,?)", (ip, note, db.now()))
    if getattr(sys, "frozen", False):  # never flag ourselves (the packaged exe is not code-signed)
        db.execute("INSERT OR IGNORE INTO allowlist(kind, value, note, ts) VALUES('process',?,?,?)",
                   (sys.executable, "PC Sentinel itself", db.now()))
    alerts.log_event("info", "system", "PC Sentinel started", f"elevated={state.elevated}")
    log.info("PC Sentinel starting (elevated=%s) on http://%s:%s", state.elevated, HOST, PORT)

    stop = threading.Event()
    _engine["stop"] = stop
    workers = [("sig", signatures.worker), ("proc", processes.run), ("net", network.run), ("privacy", privacy.run),
               ("persist", persistence.run), ("evt", eventlogs.run), ("maint", maintenance), ("baseline", baseline_timer)]
    for name, fn in workers:
        threading.Thread(target=_guard(fn, name, stop), name=name, daemon=True).start()

    from sentinel.server import app
    server = uvicorn.Server(uvicorn.Config(app, host=HOST, port=PORT, log_level="warning", access_log=False,
                                           log_config=None))
    _engine["server"] = server
    if block:
        try:
            server.run()
        finally:
            stop.set()
    else:
        threading.Thread(target=server.run, name="api", daemon=True).start()
    return True


def stop_engine():
    if "server" in _engine:
        _engine["server"].should_exit = True
    if "stop" in _engine:
        _engine["stop"].set()


if __name__ == "__main__":
    start_engine(block=True)
