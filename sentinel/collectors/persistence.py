"""Autostart / persistence monitor.

Windows: Run keys, Startup folders, scheduled tasks, services, Winlogon/IFEO/AppInit hooks.
macOS:   LaunchAgents / LaunchDaemons, cron, shell startup files.
Linux:   systemd units (system + user), XDG autostart, cron, shell startup files.
"""
import glob
import hashlib
import json
import logging
import os
import plistlib
import re
import shlex
import shutil
import subprocess

import psutil

from .. import alerts, db, rules, state
from ..config import PERSIST_INTERVAL
from ..osinfo import IS_MAC, IS_WIN

log = logging.getLogger("sentinel.persist")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

if IS_WIN:
    import winreg
    RUN_KEYS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    ]
    HIVE = {winreg.HKEY_CURRENT_USER: "HKCU", winreg.HKEY_LOCAL_MACHINE: "HKLM"}
    STARTUP_DIRS = [os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
                    os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp")]
HOME = os.path.expanduser("~")
SHELL_RC = [os.path.join(HOME, f) for f in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv")]
TASKS_PS = r"""
$ErrorActionPreference='SilentlyContinue'
@(Get-ScheduledTask | ForEach-Object { [pscustomobject]@{ p=$_.TaskPath; n=$_.TaskName; s=[string]$_.State;
  a=(($_.Actions | ForEach-Object { (($_.Execute + ' ' + $_.Arguments).Trim()) }) -join ' | ') } }) | ConvertTo-Json -Compress
"""


def parse_exe(cmd):
    """Best-effort executable path from a command line."""
    if not cmd:
        return None
    c = os.path.expandvars(cmd.strip())
    if not IS_WIN:
        try:
            parts = shlex.split(c)
        except ValueError:
            parts = c.split()
        parts = [p for p in parts if not re.match(r"^[A-Z_][A-Z0-9_]*=", p)]  # skip VAR=value prefixes
        if parts and os.path.basename(parts[0]) == "env" and len(parts) > 1:
            parts = parts[1:]
        if not parts:
            return None
        exe = parts[0]
        if not os.path.isabs(exe):
            exe = shutil.which(exe) or exe
        return exe
    if c.startswith('"'):
        end = c.find('"', 1)
        if end > 1:
            return c[1:end]
    m = re.match(r"(.+?\.(exe|com|bat|cmd|vbs|js|ps1|scr|dll))(\s|$|,)", c, re.I)
    if m:
        p = m.group(1)
        if not os.path.isabs(p):
            for base in (os.path.expandvars(r"%SystemRoot%\System32"), os.path.expandvars(r"%SystemRoot%")):
                if os.path.exists(os.path.join(base, p)):
                    return os.path.join(base, p)
        return p
    return c.split(" ")[0]


def _reg_values(hive, path):
    try:
        with winreg.OpenKey(hive, path) as k:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                except OSError:
                    return
                yield name, str(val)
                i += 1
    except OSError:
        return


def _lnk_target(path):
    try:
        import pythoncom  # noqa: F401
        from win32com.client import Dispatch
        sc = Dispatch("WScript.Shell").CreateShortcut(path)
        return f'"{sc.TargetPath}" {sc.Arguments}'.strip() if sc.TargetPath else ""
    except Exception:  # noqa: BLE001
        return ""


def _shell_rc_items():
    """Shell startup files: report a fingerprint so any edit shows up as 'changed'."""
    items = []
    for f in SHELL_RC:
        try:
            data = open(f, "rb").read()
        except OSError:
            continue
        lines = data.decode("utf-8", "replace").count("\n")
        items.append({"kind": "shell_rc", "location": os.path.dirname(f), "name": os.path.basename(f),
                      "command": f"{f} · sha256:{hashlib.sha256(data).hexdigest()[:16]} · {lines} lines",
                      "no_exe": True})
    return items


def _cron_items():
    items = []
    if shutil.which("crontab"):
        try:
            cp = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
            for i, line in enumerate(cp.stdout.splitlines()):
                s = line.strip()
                if s and not s.startswith("#") and not re.match(r"^[A-Z_]+=", s):
                    fields = s.split(None, 5)
                    cmd = fields[5] if len(fields) == 6 else (s.split(None, 1)[1] if s.startswith("@") else s)
                    items.append({"kind": "cron", "location": "user crontab", "name": f"line {i + 1}", "command": cmd})
        except (OSError, subprocess.TimeoutExpired):
            pass
    for f in ["/etc/crontab"] + glob.glob("/etc/cron.d/*"):
        try:
            for i, line in enumerate(open(f, encoding="utf-8", errors="replace")):
                s = line.strip()
                if s and not s.startswith("#") and not re.match(r"^[A-Z_]+=", s):
                    fields = s.split(None, 6)
                    if len(fields) == 7:
                        items.append({"kind": "cron", "location": f, "name": f"line {i + 1}", "command": fields[6]})
        except OSError:
            continue
    return items


def collect_macos():
    items = []
    dirs = [(os.path.join(HOME, "Library/LaunchAgents"), "launch_agent"), ("/Library/LaunchAgents", "launch_agent"),
            ("/Library/LaunchDaemons", "launch_daemon")]
    for d, kind in dirs:
        for f in sorted(glob.glob(os.path.join(d, "*.plist"))):
            try:
                with open(f, "rb") as fh:
                    pl = plistlib.load(fh)
            except Exception:  # noqa: BLE001  (unreadable or malformed plist is itself worth listing)
                items.append({"kind": kind, "location": d, "name": os.path.basename(f), "command": f"(unreadable) {f}"})
                continue
            args = pl.get("ProgramArguments") or ([pl["Program"]] if pl.get("Program") else [])
            cmd = " ".join(shlex.quote(str(a)) for a in args) or f
            items.append({"kind": kind, "location": d, "name": pl.get("Label") or os.path.basename(f),
                          "command": cmd, "disabled": bool(pl.get("Disabled"))})
    return items + _cron_items() + _shell_rc_items()


def collect_linux():
    items = []
    unit_dirs = ["/etc/systemd/system", os.path.join(HOME, ".config/systemd/user")]
    seen = set()
    for d in unit_dirs:
        for f in glob.glob(os.path.join(d, "**", "*.service"), recursive=True):
            real = os.path.realpath(f)
            name = os.path.basename(f)
            if (d, name) in seen:
                continue
            seen.add((d, name))
            try:
                text = open(real, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            m = re.search(r"^ExecStart=\s*[-@:+!]*(.+)$", text, re.M)
            if m:
                items.append({"kind": "systemd_unit", "location": d, "name": name, "command": m.group(1).strip()})
    for d in (os.path.join(HOME, ".config/autostart"), "/etc/xdg/autostart"):
        for f in sorted(glob.glob(os.path.join(d, "*.desktop"))):
            try:
                text = open(f, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            m = re.search(r"^Exec=(.+)$", text, re.M)
            hidden = re.search(r"^(Hidden|X-GNOME-Autostart-enabled)=(true|false)$", text, re.M)
            disabled = bool(hidden and ((hidden.group(1) == "Hidden" and hidden.group(2) == "true") or
                                        (hidden.group(1) != "Hidden" and hidden.group(2) == "false")))
            if m:
                cmd = re.sub(r"\s%[fFuUdDnNickvm]", "", m.group(1)).strip()
                items.append({"kind": "xdg_autostart", "location": d, "name": os.path.basename(f), "command": cmd,
                              "disabled": disabled})
    return items + _cron_items() + _shell_rc_items()


def collect():
    if IS_WIN:
        return collect_windows()
    if IS_MAC:
        return collect_macos()
    return collect_linux()


def collect_windows():
    items = []
    for hive, path in RUN_KEYS:
        for name, val in _reg_values(hive, path):
            items.append({"kind": "run_key", "location": f"{HIVE[hive]}\\{path}", "name": name, "command": val})
    for d in STARTUP_DIRS:
        try:
            for f in os.listdir(d):
                if f.lower() == "desktop.ini":
                    continue
                full = os.path.join(d, f)
                cmd = _lnk_target(full) if f.lower().endswith(".lnk") else f'"{full}"'
                items.append({"kind": "startup_folder", "location": d, "name": f, "command": cmd or f'"{full}"'})
        except OSError:
            pass
    try:
        cp = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", TASKS_PS],
                            capture_output=True, text=True, timeout=120, creationflags=subprocess.CREATE_NO_WINDOW)
        tasks = json.loads(cp.stdout or "[]")
        tasks = [tasks] if isinstance(tasks, dict) else tasks
        for t in tasks:
            if not t.get("a"):
                continue
            items.append({"kind": "scheduled_task", "location": t["p"], "name": t["n"], "command": t["a"],
                          "disabled": t.get("s") == "Disabled"})
    except Exception as e:  # noqa: BLE001
        log.warning("scheduled task scan failed: %s", e)
    for svc in psutil.win_service_iter():
        try:
            d = svc.as_dict()
        except Exception:  # noqa: BLE001
            continue
        if d.get("start_type") not in ("automatic", "manual"):
            continue
        items.append({"kind": "service", "location": f"Service ({d.get('start_type')})", "name": d.get("name"),
                      "command": d.get("binpath") or "", "display": d.get("display_name")})
    # hijack points that should never change
    for name, expected in (("Shell", "explorer.exe"), ("Userinit", r"C:\Windows\system32\userinit.exe,")):
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for vname, val in _reg_values(hive, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"):
                if vname == name:
                    items.append({"kind": "hijack", "location": f"{HIVE[hive]}\\Winlogon", "name": name, "command": val,
                                  "tampered": val.strip().lower().rstrip(",") != expected.lower().rstrip(",")})
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options") as k:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                for vname, val in _reg_values(winreg.HKEY_LOCAL_MACHINE,
                                              rf"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{sub}"):
                    if vname == "Debugger":
                        items.append({"kind": "hijack", "location": "IFEO", "name": f"{sub} debugger", "command": val, "tampered": True})
    except OSError:
        pass
    for vname, val in _reg_values(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows"):
        if vname == "AppInit_DLLs" and val.strip():
            items.append({"kind": "hijack", "location": "AppInit_DLLs", "name": "AppInit_DLLs", "command": val, "tampered": True})
    return items


def run(stop_event):
    try:
        import pythoncom
        pythoncom.CoInitialize()
    except Exception:  # noqa: BLE001
        pass
    while not stop_event.is_set():
        try:
            items = collect()
            baseline = not db.kv_get("persistence_baseline")
            now = db.now()
            seen_keys = set()
            for it in items:
                key = f"{it['kind']}|{it['location']}|{it['name']}".lower()
                seen_keys.add(key)
                exe = None if it.get("no_exe") else parse_exe(it["command"])
                a = rules.assess(exe) if exe else {"trust": "known", "sig_status": "Unknown", "signer": None, "flags": []}
                row = db.query_one("SELECT command, status, baseline FROM persistence WHERE key=?", (key,))
                ref = {"pid": None, "name": os.path.basename(exe or it["name"] or ""), "exe": exe,
                       "signer": a.get("signer"), "sig_status": a.get("sig_status"), "trust": a["trust"],
                       "flags": a.get("flags", [])}
                kind_label = {"run_key": "Run key", "startup_folder": "Startup folder", "scheduled_task": "Scheduled task",
                              "service": "Service", "hijack": "System hook", "launch_agent": "LaunchAgent",
                              "launch_daemon": "LaunchDaemon", "login_item": "Login item", "systemd_unit": "systemd unit",
                              "xdg_autostart": "XDG autostart", "cron": "cron job",
                              "shell_rc": "Shell startup file"}.get(it["kind"], it["kind"])
                if not row:
                    if not baseline and a["sig_status"] == "Unknown" and exe and os.path.exists(exe):
                        continue  # judge it on the next pass, once its signature has been checked
                    status = "baseline" if baseline else "new"
                    db.execute("INSERT INTO persistence(key,kind,location,name,command,exe,first_seen,last_seen,status,baseline)"
                               " VALUES(?,?,?,?,?,?,?,?,?,?)",
                               (key, it["kind"], it["location"], it["name"], it["command"], exe, now, now, status, int(baseline)))
                    if not baseline:
                        trusted_ms = a["trust"] == "trusted" and (a.get("signer") or "").startswith("Microsoft")
                        sev = {"malicious": "critical", "suspicious": "critical", "unsigned": "high"}.get(
                            a["trust"], "info" if trusted_ms else "medium")
                        if sev == "info":
                            alerts.log_event("info", "persistence", f"New {kind_label}: {it['name']}", it["command"][:300])
                        else:
                            alerts.raise_alert(f"persist|new|{key}", sev, "persistence",
                                               f"New autostart entry ({kind_label}): {it['name']}",
                                               f"Something added a program that starts automatically: {it['command'][:300]}",
                                               process=ref, details={"rule": "new_autostart", "kind": it["kind"],
                                                                    "location": it["location"], "command": it["command"]},
                                               allow_kind="persistence", allow_value=exe)
                elif row["command"] != it["command"]:
                    db.execute("UPDATE persistence SET command=?, exe=?, last_seen=?, status='changed' WHERE key=?",
                               (it["command"], exe, now, key))
                    sev = {"malicious": "critical", "suspicious": "critical", "unsigned": "high"}.get(a["trust"], "medium")
                    alerts.raise_alert(f"persist|changed|{key}|{it['command'][:80]}", sev, "persistence",
                                       f"Autostart entry changed ({kind_label}): {it['name']}",
                                       f"Was: {row['command'][:200]} → now: {it['command'][:200]}",
                                       process=ref, details={"rule": "changed_autostart", "kind": it["kind"],
                                                            "location": it["location"], "old": row["command"], "new": it["command"]},
                                       allow_kind="persistence", allow_value=exe)
                else:
                    db.execute("UPDATE persistence SET last_seen=?, status=CASE WHEN status='removed' THEN 'new' ELSE status END WHERE key=?",
                               (now, key))
                # anything malicious/suspicious that autostarts is an alert even if it was there at baseline
                if a["trust"] in ("malicious", "suspicious") and not it.get("disabled"):
                    alerts.raise_alert(f"persist|bad|{key}", "critical", "persistence",
                                       f"Untrusted program set to autostart: {ref['name']}",
                                       f"{kind_label} '{it['name']}' starts {exe} ({a['trust']}, {a.get('sig_status')}).",
                                       process=ref, details={"rule": "untrusted_autostart", "kind": it["kind"],
                                                            "location": it["location"], "command": it["command"]},
                                       allow_kind="persistence", allow_value=exe)
                if it.get("tampered"):
                    alerts.raise_alert(f"persist|hijack|{key}|{it['command'][:80]}", "critical", "persistence",
                                       f"System hook modified: {it['location']} {it['name']}",
                                       f"Value is '{it['command'][:200]}' — this is used by malware to run at every logon or app start.",
                                       process=ref, details={"rule": "hijack_point", "location": it["location"]})
            for r in db.query("SELECT key, name, kind, command FROM persistence WHERE status != 'removed'"):
                if r["key"] not in seen_keys:
                    db.execute("UPDATE persistence SET status='removed', last_seen=? WHERE key=?", (now, r["key"]))
                    alerts.log_event("info", "persistence", f"Autostart entry removed: {r['name']}", (r["command"] or "")[:300])
            if baseline:
                db.kv_set("persistence_baseline", now)
            with state.lock:
                state.coverage["persistence"] = True
        except Exception:  # noqa: BLE001
            log.exception("persistence scan failed")
        stop_event.wait(PERSIST_INTERVAL)
