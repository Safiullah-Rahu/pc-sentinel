"""User-triggered responses: kill a process, block an IP, allow/block lists, start-at-login.

Every value that reaches a privileged command is validated first (int PIDs, ipaddress-parsed IPs);
commands are passed as argument lists, never through a shell string built from user data.
"""
import ipaddress
import logging
import os
import shutil
import subprocess

import psutil

from . import alerts, autostart, db, rules, state
from .collectors import network
from .osinfo import IS_MAC, IS_WIN

log = logging.getLogger("sentinel.actions")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
PROTECTED = {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
             "svchost.exe", "msmpeng.exe", "dwm.exe", "explorer.exe", "fontdrvhost.exe", "registry",
             # macOS / Linux core processes
             "launchd", "kernel_task", "windowserver", "loginwindow", "systemd", "init", "kthreadd", "sshd",
             "xorg", "gnome-shell", "plasmashell", "dbus-daemon"}


def _run_privileged(argv):
    """Run argv with admin/root rights: directly if we already have them, else ask the OS for approval
    (UAC on Windows, the admin password dialog on macOS, polkit on Linux)."""
    if state.elevated:
        cp = subprocess.run(argv, capture_output=True, text=True, timeout=60, creationflags=NO_WINDOW)
        return cp.returncode == 0, (cp.stderr or cp.stdout or "").strip()[:300]
    if IS_WIN:
        import ctypes
        params = subprocess.list2cmdline(argv[1:])
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", argv[0], params, None, 0)
        return rc > 32, "Approve the Windows admin prompt to finish."
    if IS_MAC:
        script = " ".join(_sh_quote(a) for a in argv)
        osa = f'do shell script "{script}" with administrator privileges'
        cp = subprocess.run(["osascript", "-e", osa], capture_output=True, text=True, timeout=120)
        return cp.returncode == 0, (cp.stderr or "done").strip()[:300]
    if shutil.which("pkexec"):
        cp = subprocess.run(["pkexec", *argv], capture_output=True, text=True, timeout=120)
        return cp.returncode == 0, (cp.stderr or "done").strip()[:300]
    return False, "Needs root: run PC Sentinel with sudo, or install polkit (pkexec)."


def _sh_quote(s):
    # for osascript's "do shell script": single-quote for the shell, then escape for the AppleScript string
    q = "'" + str(s).replace("'", "'\\''") + "'"
    return q.replace("\\", "\\\\").replace('"', '\\"')


def kill(pid):
    try:
        pid = int(pid)
        p = psutil.Process(pid)
    except (psutil.NoSuchProcess, ValueError, TypeError):
        return {"ok": False, "message": f"Process {pid} is not running."}
    name = (p.name() or "").lower()
    if name in PROTECTED or pid in (0, 1, 4) or pid == os.getpid():
        return {"ok": False, "message": f"{name} is a core system process and is protected from being killed here."}
    try:
        p.kill()
        alerts.log_event("info", "process", f"Killed {name} (PID {pid})", "by the user from the dashboard")
        return {"ok": True, "message": f"Killed {name} (PID {pid})."}
    except psutil.AccessDenied:
        argv = ["powershell.exe", "-NoProfile", "-Command", f"Stop-Process -Id {pid} -Force"] if IS_WIN \
            else ["/bin/kill", "-9", str(pid)]
        ok, msg = _run_privileged(argv)
        return {"ok": ok, "message": f"Elevated kill of {name}: {msg}"}


def _block_argv(addr):
    if IS_WIN:
        name = f"PC Sentinel block {addr}"
        ps = (f"New-NetFirewallRule -DisplayName '{name} (out)' -Direction Outbound -RemoteAddress {addr} -Action Block -Profile Any | Out-Null; "
              f"New-NetFirewallRule -DisplayName '{name} (in)' -Direction Inbound -RemoteAddress {addr} -Action Block -Profile Any | Out-Null")
        return ["powershell.exe", "-NoProfile", "-Command", ps]
    if IS_MAC:  # a blackhole route drops all traffic to the address; no firewall config needed
        return (["/sbin/route", "-n", "add", "-inet6", "-host", str(addr), "::1", "-blackhole"] if addr.version == 6
                else ["/sbin/route", "-n", "add", "-host", str(addr), "127.0.0.1", "-blackhole"])
    ip = shutil.which("ip") or "/sbin/ip"
    return [ip, "-6" if addr.version == 6 else "-4", "route", "add", "blackhole", str(addr)]


def block_ip(ip, note=""):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "message": f"'{ip}' is not a valid IP address."}
    if rules.is_private(str(addr)):
        return {"ok": False, "message": f"{addr} is a local/private address; refusing to block it."}
    add_blocklist(str(addr), note or "Blocked from dashboard")
    ok, msg = _run_privileged(_block_argv(addr))
    alerts.log_event("info", "network", f"Block requested for {addr}", msg)
    return {"ok": ok, "message": f"Block for {addr}: {'added' if ok and state.elevated else msg}"}


def set_autostart(enabled):
    ok, msg = autostart.enable() if enabled else autostart.disable()
    return {"ok": ok, "message": msg}


def add_blocklist(ip, note=""):
    db.execute("INSERT OR IGNORE INTO blocklist(ip, note, ts) VALUES(?,?,?)", (ip, note, db.now()))
    network.invalidate_blocklist()
    return {"ok": True, "message": f"{ip} added to the blocklist."}


def remove_blocklist(item_id):
    db.execute("DELETE FROM blocklist WHERE id=?", (int(item_id),))
    network.invalidate_blocklist()
    return {"ok": True, "message": "Removed from the blocklist."}


def allow(kind, value, note=""):
    if kind not in ("process", "destination", "privacy", "persistence") or not value:
        return {"ok": False, "message": "Invalid allowlist entry."}
    db.execute("INSERT OR IGNORE INTO allowlist(kind, value, note, ts) VALUES(?,?,?,?)", (kind, value, note, db.now()))
    rules.invalidate_allow_cache()
    n = alerts.mark_allowed_where(kind, value)
    return {"ok": True, "message": f"Allowed {value} ({kind}); {n} matching alert(s) closed."}


def unallow(item_id):
    db.execute("DELETE FROM allowlist WHERE id=?", (int(item_id),))
    rules.invalidate_allow_cache()
    return {"ok": True, "message": "Removed from the allowlist."}


def set_notify(enabled, min_severity="high"):
    if min_severity not in ("critical", "high", "medium", "low"):
        return {"ok": False, "message": "Invalid level."}
    db.kv_set("notify", {"enabled": bool(enabled), "min_severity": min_severity})
    if enabled:
        return {"ok": True, "message": f"Desktop notifications ON for {min_severity} and above."}
    return {"ok": True, "message": "Desktop notifications OFF — alerts are only shown in the app."}
