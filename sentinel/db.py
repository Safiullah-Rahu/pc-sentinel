"""SQLite storage (WAL) shared by all collector threads."""
import json
import sqlite3
import threading
from datetime import datetime, timedelta

from .config import DB_PATH

_lock = threading.RLock()
_conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
_conn.row_factory = sqlite3.Row
_conn.execute("PRAGMA journal_mode=WAL")
_conn.execute("PRAGMA synchronous=NORMAL")

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY, key TEXT UNIQUE, ts TEXT, first_ts TEXT, last_ts TEXT, count INTEGER DEFAULT 1,
  severity TEXT, category TEXT, title TEXT, summary TEXT, process TEXT, remote TEXT, details TEXT,
  status TEXT DEFAULT 'open');
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status, last_ts);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts TEXT, severity TEXT, category TEXT, title TEXT, summary TEXT, alert_id INTEGER);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS sigcache (path TEXT PRIMARY KEY, size INTEGER, mtime REAL, status TEXT, signer TEXT,
  sha256 TEXT, checked TEXT);
CREATE TABLE IF NOT EXISTS seen_apps (exe TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, net_first_seen TEXT);
CREATE TABLE IF NOT EXISTS destinations (ip TEXT PRIMARY KEY, host TEXT, first_seen TEXT, last_seen TEXT,
  hits INTEGER DEFAULT 0, ports TEXT DEFAULT '[]', apps TEXT DEFAULT '[]');
CREATE TABLE IF NOT EXISTS listeners (key TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS persistence (key TEXT PRIMARY KEY, kind TEXT, location TEXT, name TEXT, command TEXT,
  exe TEXT, first_seen TEXT, last_seen TEXT, status TEXT, baseline INTEGER);
CREATE TABLE IF NOT EXISTS privacy_hist (key TEXT PRIMARY KEY, device TEXT, app TEXT, path TEXT, start TEXT,
  stop TEXT, packaged INTEGER);
CREATE TABLE IF NOT EXISTS file_access (id INTEGER PRIMARY KEY, ts TEXT, path TEXT, label TEXT, kind TEXT,
  process TEXT, pid INTEGER, exe TEXT, access TEXT, expected INTEGER);
CREATE TABLE IF NOT EXISTS dns (id INTEGER PRIMARY KEY, ts TEXT, pid INTEGER, process TEXT, query TEXT,
  type TEXT, result TEXT);
CREATE INDEX IF NOT EXISTS ix_dns_ts ON dns(ts);
CREATE TABLE IF NOT EXISTS metrics (t TEXT PRIMARY KEY, rx_bps REAL, tx_bps REAL, cpu REAL, conns INTEGER);
CREATE TABLE IF NOT EXISTS allowlist (id INTEGER PRIMARY KEY, kind TEXT, value TEXT, note TEXT, ts TEXT,
  UNIQUE(kind, value));
CREATE TABLE IF NOT EXISTS blocklist (id INTEGER PRIMARY KEY, ip TEXT UNIQUE, note TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT);
"""
with _lock:
    _conn.executescript(SCHEMA)


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def ago(**kw) -> str:
    return (datetime.now() - timedelta(**kw)).isoformat(timespec="seconds")


def execute(sql, params=()):
    with _lock:
        return _conn.execute(sql, params)


def executemany(sql, rows):
    with _lock:
        _conn.execute("BEGIN")
        try:
            _conn.executemany(sql, rows)
            _conn.execute("COMMIT")
        except Exception:
            _conn.execute("ROLLBACK")
            raise


def query(sql, params=()):
    with _lock:
        return [dict(r) for r in _conn.execute(sql, params).fetchall()]


def query_one(sql, params=()):
    with _lock:
        r = _conn.execute(sql, params).fetchone()
        return dict(r) if r else None


def kv_get(key, default=None):
    r = query_one("SELECT value FROM kv WHERE key=?", (key,))
    if not r:
        return default
    try:
        return json.loads(r["value"])
    except ValueError:
        return r["value"]


def kv_set(key, value):
    execute("INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)))


def prune():
    """Retention: metrics 24 h, DNS 7 days, timeline 30 days, acknowledged alerts 60 days."""
    execute("DELETE FROM metrics WHERE t < ?", (ago(hours=24),))
    execute("DELETE FROM dns WHERE ts < ?", (ago(days=7),))
    execute("DELETE FROM events WHERE ts < ?", (ago(days=30),))
    execute("DELETE FROM alerts WHERE status != 'open' AND last_ts < ?", (ago(days=60),))
    execute("DELETE FROM file_access WHERE ts < ?", (ago(days=90),))
