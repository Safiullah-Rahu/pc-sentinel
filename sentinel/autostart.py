"""Start PC Sentinel at login (hidden in the tray), per OS, using only per-user locations (no admin needed).

Windows: Startup-folder shortcut · macOS: ~/Library/LaunchAgents plist · Linux: ~/.config/autostart .desktop file.
"""
import os
import plistlib
import shlex
import subprocess
import sys
from pathlib import Path

from . import db, rules
from .config import APP_DIR, FROZEN
from .osinfo import IS_MAC, IS_WIN

LABEL = "io.github.pcsentinel"


def _launch_argv():
    """Command that starts the desktop app hidden in the tray."""
    if FROZEN:
        return [sys.executable, "--tray"]
    py = sys.executable
    if IS_WIN and py.lower().endswith("python.exe"):
        py = py[:-len("python.exe")] + "pythonw.exe"
    return [py, str(APP_DIR / "desktop.py"), "--tray"]


def _path():
    if IS_WIN:
        return Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup/PC Sentinel.lnk"
    if IS_MAC:
        return Path.home() / "Library/LaunchAgents" / f"{LABEL}.plist"
    return Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "autostart" / "pc-sentinel.desktop"


def status():
    kind = "Startup folder shortcut" if IS_WIN else "LaunchAgent" if IS_MAC else "XDG autostart entry"
    return {"supported": True, "enabled": _path().exists(), "detail": f"{kind} · {_path()}"}


def _trust_self(argv):
    """Pre-approve our own autostart entry so the persistence monitor does not alert on it."""
    db.execute("INSERT OR IGNORE INTO allowlist(kind, value, note, ts) VALUES('persistence',?,?,?)",
               (argv[0], "PC Sentinel starts itself at login", db.now()))
    rules.invalidate_allow_cache()


def enable():
    argv = _launch_argv()
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    _trust_self(argv)
    if IS_WIN:
        target, args = argv[0], subprocess.list2cmdline(argv[1:])
        ps = ("$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:PCS_LNK);"
              "$s.TargetPath=$env:PCS_TARGET;$s.Arguments=$env:PCS_ARGS;$s.WorkingDirectory=$env:PCS_WD;"
              "$s.IconLocation=$env:PCS_TARGET+',0';$s.Description='Start PC Sentinel hidden in the tray at login';$s.Save()")
        env = {**os.environ, "PCS_LNK": str(p), "PCS_TARGET": target, "PCS_ARGS": args,
               "PCS_WD": str(Path(target).parent)}  # values go through env vars, never spliced into the script
        cp = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps], env=env,
                            capture_output=True, text=True, timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        ok = cp.returncode == 0 and p.exists()
        return ok, "PC Sentinel will start in the tray when you log in." if ok else f"Could not create shortcut: {cp.stderr[:200]}"
    if IS_MAC:
        with open(p, "wb") as f:
            plistlib.dump({"Label": LABEL, "ProgramArguments": argv, "RunAtLoad": True,
                           "ProcessType": "Interactive"}, f)
        return True, "PC Sentinel will start in the menu bar when you log in."
    exec_line = " ".join(shlex.quote(a) for a in argv)
    p.write_text("[Desktop Entry]\nType=Application\nName=PC Sentinel\nComment=Local security monitor\n"
                 f"Exec={exec_line}\nX-GNOME-Autostart-enabled=true\nTerminal=false\n", encoding="utf-8")
    return True, "PC Sentinel will start in the tray when you log in."


def disable():
    p = _path()
    try:
        p.unlink()
    except FileNotFoundError:
        pass
    except OSError as e:
        return False, f"Could not remove {p}: {e}"
    return True, "PC Sentinel will no longer start at login."
