"""In-memory snapshots shared between collectors and the API (guarded by one lock)."""
import threading
import time

lock = threading.RLock()
started = time.time()

procs = {}          # pid -> dict(pid, ppid, name, exe, cmdline, user, started, create_time, cpu, mem_mb, assess)
connections = []    # list of connection dicts (see network collector)
listening = []      # list of listener dicts
throughput = {"rx_bps": 0.0, "tx_bps": 0.0, "cpu": 0.0, "conns": 0}
privacy = {"webcam": {"in_use": False, "by": []}, "microphone": {"in_use": False, "by": []},
           "location": {"in_use": False, "by": []}, "screen_capture": {"in_use": False, "by": []}}
defender = {"realtime": None, "tamper": None, "signatures": None, "signatures_age_h": None,
            "exclusions_known": None, "exclusions": [], "last_detection": None}
coverage = {"processes": False, "network": False, "privacy": False, "persistence": False,
            "defender_log": False, "security_log": False, "dns_log": False, "file_audit": False, "canaries": 0}
elevated = False


def proc_ref(pid):
    """ProcessRef for API payloads (works for exited processes too, if we still know them)."""
    with lock:
        p = procs.get(pid)
    if not p:
        return {"pid": pid, "name": None, "exe": None, "signer": None, "sig_status": "Unknown", "trust": "known"}
    a = p.get("assess") or {}
    return {"pid": pid, "name": p.get("name"), "exe": p.get("exe"), "signer": a.get("signer"),
            "sig_status": a.get("sig_status", "Unknown"), "trust": a.get("trust", "known"),
            "flags": a.get("flags", [])}
