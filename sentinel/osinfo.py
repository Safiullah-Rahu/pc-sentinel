"""Which operating system we are on, and what each monitor can do here."""
import os
import platform
import sys

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")
PLATFORM = "windows" if IS_WIN else "macos" if IS_MAC else "linux"


def os_label():
    if IS_WIN:
        ver = platform.version()  # 10.0.26200
        build = ver.split(".")[-1]
        name = "Windows 11" if build.isdigit() and int(build) >= 22000 else f"Windows {platform.release()}"
        return f"{name} ({build})"
    if IS_MAC:
        return f"macOS {platform.mac_ver()[0]}"
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            info = dict(line.rstrip().split("=", 1) for line in f if "=" in line)
        return info.get("PRETTY_NAME", "Linux").strip('"')
    except OSError:
        return f"Linux {platform.release()}"


def is_elevated():
    if IS_WIN:
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    return os.geteuid() == 0


# What each monitor can do on this OS (False = not available here; shown as "n/a" in the UI)
COVERAGE_SUPPORTED = {
    "processes": True,
    "network": True,
    "privacy": IS_WIN or IS_LINUX,
    "persistence": True,
    "defender_log": IS_WIN,
    "security_log": IS_WIN,
    "dns_log": IS_WIN,
    "file_audit": IS_WIN,
    "canaries": True,
}
