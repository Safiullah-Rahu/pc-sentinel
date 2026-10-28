"""Camera / microphone / location / screen-capture use.

Windows: the OS's own capability-access record (ConsentStore), shown exactly as Windows records it.
Linux:   live — which process has /dev/video* open (camera) and which app records audio (PulseAudio/PipeWire,
         falling back to ALSA). macOS: not available without special entitlements (reported as n/a).
"""
import glob
import logging
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta

from .. import alerts, db, rules, state
from ..config import PRIVACY_INTERVAL
from ..osinfo import IS_LINUX, IS_WIN

if IS_WIN:
    import winreg

log = logging.getLogger("sentinel.privacy")
BASE = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
CAPS = {"webcam": "webcam", "microphone": "microphone", "location": "location",
        "graphicsCaptureProgrammatic": "screen_capture"}
LABEL = {"webcam": "camera", "microphone": "microphone", "location": "location", "screen_capture": "screen capture"}


def _ft(v):
    if not v:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=int(v) // 10)
    except (OverflowError, ValueError):
        return None


def _read_app(hive, path):
    try:
        with winreg.OpenKey(hive, path) as k:
            vals = {}
            for name in ("LastUsedTimeStart", "LastUsedTimeStop"):
                try:
                    vals[name] = winreg.QueryValueEx(k, name)[0]
                except OSError:
                    vals[name] = None
            return vals
    except OSError:
        return None


def _subkeys(hive, path):
    try:
        with winreg.OpenKey(hive, path) as k:
            i = 0
            while True:
                try:
                    yield winreg.EnumKey(k, i)
                except OSError:
                    return
                i += 1
    except OSError:
        return


def scan():
    """Yield (device, app_display, path, packaged, start_dt, stop_dt)."""
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for cap, device in CAPS.items():
            capkey = f"{BASE}\\{cap}"
            for sub in _subkeys(hive, capkey):
                if sub == "NonPackaged":
                    for np in _subkeys(hive, f"{capkey}\\NonPackaged"):
                        v = _read_app(hive, f"{capkey}\\NonPackaged\\{np}")
                        if v and v["LastUsedTimeStart"]:
                            path = np.replace("#", "\\")
                            yield device, os.path.basename(path), path, False, _ft(v["LastUsedTimeStart"]), _ft(v["LastUsedTimeStop"])
                else:
                    v = _read_app(hive, f"{capkey}\\{sub}")
                    if v and v["LastUsedTimeStart"]:
                        yield device, sub.split("_")[0], sub, True, _ft(v["LastUsedTimeStart"]), _ft(v["LastUsedTimeStop"])


def _alert_session(device, app, path, start, packaged=False):
    if packaged:
        a = {"sig_status": "Valid", "signer": "Microsoft Store package", "trust": "known", "flags": []}
    else:
        a = rules.assess(path)
    trust = a["trust"]
    sev = {"malicious": "critical", "suspicious": "critical", "unsigned": "high"}.get(trust, "medium")
    ref = {"pid": None, "name": app, "exe": path, "signer": a.get("signer"),
           "sig_status": a.get("sig_status"), "trust": trust, "flags": a.get("flags", [])}
    alerts.raise_alert(f"privacy|{device}|{path.lower()}|{start.isoformat() if start else ''}", sev, "privacy",
                       f"{LABEL[device].capitalize()} used by {app}",
                       f"{app} started using your {LABEL[device]} ({trust}). Path: {path}",
                       process=ref, details={"rule": "device_access", "device": device,
                                            "start": start.isoformat(timespec='seconds') if start else None},
                       allow_kind="privacy", allow_value=path)


# ---------------------------------------------------------------- Linux (live)
def _proc_info(pid):
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = None
    try:
        with open(f"/proc/{pid}/comm", encoding="utf-8") as f:
            name = f.read().strip()
    except OSError:
        name = os.path.basename(exe or "") or f"PID {pid}"
    return name, exe or name


def _linux_camera_users():
    users = {}
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        if re.match(r"^/dev/video\d+$", target):
            pid = int(fd.split("/")[2])
            users[pid] = _proc_info(pid)
    return list(users.values())


def _linux_mic_users():
    users = {}
    if shutil.which("pactl"):
        try:
            out = subprocess.run(["pactl", "list", "source-outputs"], capture_output=True, text=True, timeout=5).stdout
            for block in out.split("Source Output #")[1:]:
                pid = re.search(r'application\.process\.id = "(\d+)"', block)
                binary = re.search(r'application\.process\.binary = "([^"]+)"', block)
                if pid:
                    users[int(pid.group(1))] = _proc_info(int(pid.group(1)))
                elif binary:
                    users[binary.group(1)] = (binary.group(1), binary.group(1))
        except (OSError, subprocess.TimeoutExpired):
            pass
    if not users:  # plain ALSA: capture streams that are running
        for st in glob.glob("/proc/asound/card*/pcm*c/sub*/status"):
            try:
                with open(st, encoding="utf-8") as f:
                    txt = f.read()
            except OSError:
                continue
            m = re.search(r"owner_pid\s*:\s*(\d+)", txt)
            if "RUNNING" in txt and m:
                users[int(m.group(1))] = _proc_info(int(m.group(1)))
    return list(users.values())


def run_linux(stop_event):
    active = {}  # (device, path) -> (key, app, start)
    while not stop_event.is_set():
        devices = {d: {"in_use": False, "by": []} for d in LABEL}
        now = datetime.now().replace(microsecond=0)
        current = set()
        try:
            for device, users in (("webcam", _linux_camera_users()), ("microphone", _linux_mic_users())):
                for app, path in users:
                    devices[device]["in_use"] = True
                    devices[device]["by"].append(app)
                    current.add((device, path))
                    if (device, path) not in active:
                        key = f"{device}|{path}|{now.isoformat()}"
                        db.execute("INSERT OR IGNORE INTO privacy_hist(key,device,app,path,start,stop,packaged) VALUES(?,?,?,?,?,?,0)",
                                   (key, device, app, path, now.isoformat(), None))
                        active[(device, path)] = (key, app, now)
                        _alert_session(device, app, path, now)
            for k in list(active):
                if k not in current:
                    db.execute("UPDATE privacy_hist SET stop=? WHERE key=?", (now.isoformat(), active[k][0]))
                    del active[k]
        except Exception:  # noqa: BLE001
            log.exception("privacy scan failed")
        with state.lock:
            state.privacy = devices
            state.coverage["privacy"] = True
        stop_event.wait(PRIVACY_INTERVAL)


def run(stop_event):
    if IS_LINUX:
        return run_linux(stop_event)
    if not IS_WIN:
        with state.lock:
            state.coverage["privacy"] = False
        return None  # macOS: not available (needs Apple-granted entitlements)
    return run_windows(stop_event)


def run_windows(stop_event):
    first = True
    seen_start = {}
    while not stop_event.is_set():
        devices = {d: {"in_use": False, "by": []} for d in LABEL}
        try:
            for device, app, path, packaged, start, stop in scan():
                # shown exactly as Windows records it (an app that crashed mid-use can stay "in use")
                in_use = bool(start and (not stop or stop < start))
                if in_use:
                    devices[device]["in_use"] = True
                    devices[device]["by"].append(app)
                key = f"{device}|{path.lower()}|{start.isoformat(timespec='seconds') if start else ''}"
                exists = db.query_one("SELECT key FROM privacy_hist WHERE key=?", (key,))
                stop_iso = stop.isoformat(timespec="seconds") if stop and not in_use else None
                if exists:
                    db.execute("UPDATE privacy_hist SET stop=? WHERE key=?", (stop_iso, key))
                else:
                    db.execute("INSERT INTO privacy_hist(key,device,app,path,start,stop,packaged) VALUES(?,?,?,?,?,?,?)",
                               (key, device, app, path, start.isoformat(timespec="seconds") if start else None,
                                stop_iso, int(packaged)))
                prev = seen_start.get((device, path.lower()))
                seen_start[(device, path.lower())] = start
                if first or (prev and start and start <= prev):
                    continue
                _alert_session(device, app, path, start, packaged)  # a new access session started
        except Exception:  # noqa: BLE001
            log.exception("privacy scan failed")
        with state.lock:
            state.privacy = devices
            state.coverage["privacy"] = True
        first = False
        stop_event.wait(PRIVACY_INTERVAL)
