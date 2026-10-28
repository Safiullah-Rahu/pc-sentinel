"""Paths, intervals and detection constants for PC Sentinel (Windows, macOS, Linux)."""
import json
import os
import re
import sys
from pathlib import Path

from .osinfo import IS_MAC, IS_WIN

VERSION = "1.1.1"
FROZEN = bool(getattr(sys, "frozen", False))  # running as the packaged app
APP_DIR = Path(getattr(sys, "_MEIPASS", "")) if FROZEN else Path(__file__).resolve().parent.parent
DASHBOARD_DIR = APP_DIR / "dashboard"
ICON_PATH = APP_DIR / "assets" / "sentinel.ico"
TRAY_ICON_PATH = APP_DIR / "assets" / "sentinel-64.png"


def _data_dir():
    if IS_WIN:
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "PCSentinel"
    if IS_MAC:
        return Path.home() / "Library" / "Application Support" / "PCSentinel"
    return Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / "pcsentinel"


DATA_DIR = _data_dir()
DATA_DIR.mkdir(parents=True, exist_ok=True)
if not IS_WIN:
    os.chmod(DATA_DIR, 0o700)  # token, database and logs are private to this user
DB_PATH = DATA_DIR / "sentinel.db"
TOKEN_PATH = DATA_DIR / "token.txt"
WATCHLIST_PATH = DATA_DIR / "watched_files.json"
LOG_PATH = DATA_DIR / "sentinel.log"
IOC_PATH = DATA_DIR / "iocs.json"  # optional, user-maintained: {"blocklist": [[ip, note]], "known_bad_sha256": {hash: note}}

HOST = "127.0.0.1"
PORT = int(os.environ.get("PCSENTINEL_PORT", "8777"))

# collector intervals (seconds)
PROC_INTERVAL = 2
NET_INTERVAL = 3
METRIC_INTERVAL = 5
PRIVACY_INTERVAL = 3
PERSIST_INTERVAL = 90
EVENTLOG_INTERVAL = 5
DEFENDER_STATUS_INTERVAL = 300
AUDIT_REAPPLY_INTERVAL = 6 * 3600

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _load_iocs():
    """Threat intel lives in a local file so personal incident data never ships with the code."""
    try:
        with open(IOC_PATH, encoding="utf-8") as f:
            j = json.load(f)
        return ([tuple(x) for x in j.get("blocklist", []) if isinstance(x, list) and len(x) == 2],
                {k.upper(): v for k, v in (j.get("known_bad_sha256") or {}).items()})
    except (OSError, ValueError):
        return [], {}


DEFAULT_BLOCKLIST, KNOWN_BAD_SHA256 = _load_iocs()

# Publishers we treat as "trusted" (anything else with a valid signature is "known")
TRUSTED_SIGNERS = re.compile(
    r"^(Microsoft|Google|Intel|NVIDIA|Mozilla|Opera Norway|Apple|Software Signing|"
    r"Developer ID Application: (Google|Mozilla|Microsoft|Slack|Zoom|Spotify|Discord|Signal|Docker|Dropbox|Brave|Notion|JetBrains)|"
    r"Adobe|Anthropic|OpenAI|Discord|Slack|Signal Messenger|Spotify|Tailscale|Zoom|Telegram|Valve|Epic Games|"
    r"Realtek|Advanced Micro Devices|GIGA-BYTE|Corsair|HP Inc|Hewlett|Python Software|OpenJS|"
    r"Node\.js|JetBrains|GitHub|Git |Johannes Schindelin|Docker|Notion|Obsidian|Dropbox|"
    r"Brave Software|Vivaldi|Oracle|VideoLAN|The Document Foundation|Ollama|"
    r"Anaconda|Logitech|Samsung|Lenovo|Dell|ASUSTeK|Microsoft Windows)", re.I)

# Built-in tools + argument patterns that are rarely benign ("living off the land")
LOLBIN_RULES = [
    # Windows
    ("powershell.exe", re.compile(r"\s-(e|en|enc|enco|encodedcommand)\s|frombase64string|downloadstring|iex\s*\(|"
                                  r"invoke-expression.*http|-w(indowstyle)?\s+hidden.*http", re.I)),
    ("pwsh.exe", re.compile(r"\s-(e|en|enc|encodedcommand)\s|frombase64string|downloadstring|iex\s*\(", re.I)),
    ("mshta.exe", re.compile(r"https?:|javascript:|vbscript:", re.I)),
    ("rundll32.exe", re.compile(r"\\users\\|\\temp\\|\\programdata\\[^\\]+\.dll|javascript:|url\.dll.*http", re.I)),
    ("regsvr32.exe", re.compile(r"/i:\s*https?:|scrobj\.dll|\\users\\public\\|\\temp\\", re.I)),
    ("certutil.exe", re.compile(r"-urlcache|-decode|-encode|verifyctl.*http", re.I)),
    ("bitsadmin.exe", re.compile(r"/transfer|/addfile", re.I)),
    ("wscript.exe", re.compile(r"\\users\\public\\|\\temp\\|\\appdata\\|\\programdata\\|\.(vbs|js|jse|wsf)", re.I)),
    ("cscript.exe", re.compile(r"\\users\\public\\|\\temp\\|\\appdata\\|\\programdata\\", re.I)),
    ("cmd.exe", re.compile(r"(curl|bitsadmin|certutil).*(http|ftp)|powershell.*-e(nc)?\s|\\users\\public\\.*\.(vbs|bat|ps1)", re.I)),
    ("schtasks.exe", re.compile(r"/create.*(\\users\\public\\|\\temp\\|\\appdata\\|\.vbs|\.js|mshta|powershell)", re.I)),
    ("reg.exe", re.compile(r"add.*\\currentversion\\run|add.*image file execution options|add.*winlogon", re.I)),
    ("wmic.exe", re.compile(r"process\s+call\s+create|shadowcopy\s+delete", re.I)),
    ("vssadmin.exe", re.compile(r"delete\s+shadows|resize\s+shadowstorage", re.I)),
    ("msiexec.exe", re.compile(r"/i\s*https?:|/q.*https?:", re.I)),
    # macOS / Linux shells and tools
    ("bash", re.compile(r"/dev/(tcp|udp)/|(curl|wget)[^|]*\|\s*(ba|z)?sh\b|base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh", re.I)),
    ("sh", re.compile(r"/dev/(tcp|udp)/|(curl|wget)[^|]*\|\s*(ba|z)?sh\b|base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh", re.I)),
    ("zsh", re.compile(r"/dev/(tcp|udp)/|(curl|wget)[^|]*\|\s*(ba|z)?sh\b|base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh", re.I)),
    ("nc", re.compile(r"\s-(e|c)\s", re.I)),
    ("ncat", re.compile(r"\s-(e|c)\s|--exec|--sh-exec", re.I)),
    ("socat", re.compile(r"exec:|system:", re.I)),
    ("python3", re.compile(r"-c\s+.*(socket\.socket|pty\.spawn|subprocess.*\/bin\/(ba)?sh)", re.I)),
    ("python", re.compile(r"-c\s+.*(socket\.socket|pty\.spawn|subprocess.*\/bin\/(ba)?sh)", re.I)),
    ("perl", re.compile(r"-e\s+.*socket", re.I)),
    ("osascript", re.compile(r"do shell script.*(curl|wget|base64)|display dialog.*password", re.I)),
    ("launchctl", re.compile(r"load\s+.*(/tmp/|/private/tmp/|/users/shared/)", re.I)),
    ("crontab", re.compile(r"(/tmp/|/dev/shm/|curl|wget)", re.I)),
]

SCRIPT_EXT = re.compile(r"\.(vbs|vbe|js|jse|wsf|wsh|hta|ps1|bat|cmd)\b", re.I)

# Paths where legitimate software rarely runs from
if IS_WIN:
    SUSPICIOUS_PATHS = [
        (re.compile(r"^[a-z]:\\programdata\\[^\\]+\.(exe|scr|com)$", re.I), "exe directly in ProgramData"),
        (re.compile(r"^[a-z]:\\programdata\\\{[0-9a-f-]{36}\}\\", re.I), "random GUID folder in ProgramData"),
        (re.compile(r"\\users\\public\\", re.I), "Public user folder"),
        (re.compile(r"\\appdata\\local\\temp\\[^\\]+\.(exe|scr|com)$", re.I), "Temp folder"),
        (re.compile(r"\\appdata\\roaming\\[^\\]+\.(exe|scr|com)$", re.I), "directly in AppData\\Roaming"),
        (re.compile(r"\\windows\\temp\\", re.I), "Windows Temp folder"),
        (re.compile(r"\\\$recycle\.bin\\", re.I), "Recycle Bin"),
    ]
    SYSTEM_APP_DIRS = re.compile(r"^[a-z]:\\(program files|program files \(x86\)|windows)\\", re.I)
    STORE_APPS = re.compile(r"^[a-z]:\\program files\\windowsapps\\", re.I)
elif IS_MAC:
    SUSPICIOUS_PATHS = [
        (re.compile(r"^/(private/)?tmp/"), "/tmp"),  # nosec B108 (detection pattern, not a temp file)
        (re.compile(r"^/(private/)?var/tmp/"), "/var/tmp"),  # nosec B108 (detection pattern, not a temp file)
        (re.compile(r"^/Users/Shared/"), "/Users/Shared"),
        (re.compile(r"^/Library/Caches/"), "system caches folder"),
    ]
    SYSTEM_APP_DIRS = re.compile(r"^/(System|usr/(bin|sbin|libexec|lib)|bin|sbin|Applications|Library/Apple)/")
    STORE_APPS = re.compile(r"^/Applications/.+\.app/Contents/_MASReceipt")  # never matches an exe; MAS apps are code-signed
else:
    SUSPICIOUS_PATHS = [
        # AppImages legitimately run from /tmp/.mount_*
        (re.compile(r"^/tmp/(?!\.mount_)"), "/tmp"),  # nosec B108 (detection pattern, not a temp file)
        (re.compile(r"^/var/tmp/"), "/var/tmp"),  # nosec B108 (detection pattern, not a temp file)
        (re.compile(r"^/dev/shm/"), "/dev/shm (memory)"),  # nosec B108 (detection pattern, not a temp file)
        (re.compile(r"^/run/user/\d+/[^/]+$"), "runtime dir"),
        (re.compile(r" \(deleted\)$"), "deleted from disk while running"),
        (re.compile(r"^/memfd:"), "fileless (memfd)"),
    ]
    SYSTEM_APP_DIRS = re.compile(r"^/(usr|bin|sbin|lib|lib64|opt|snap)/")
    STORE_APPS = re.compile(r"^/(snap|var/lib/flatpak)/")

# Dot-folders in the home directory where developer tools normally keep binaries (not "hidden" malware)
KNOWN_DOT_DIRS = {".local", ".cache", ".cargo", ".rustup", ".vscode", ".vscode-server", ".npm", ".nvm", ".pyenv",
                  ".rbenv", ".bun", ".deno", ".dotnet", ".gradle", ".m2", ".conda", ".docker", ".config", ".ollama",
                  ".jdks", ".sdkman", ".volta", ".yarn", ".pnpm", ".gem", ".cursor", ".windsurf", ".claude", ".codex"}

COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 3478, 5228, 5223,
                8080, 8443, 19302, 19305}

# Processes allowed to read any watched sensitive file (security / indexing / system)
GLOBAL_FILE_READERS = {"msmpeng.exe", "mpdefendercoreservice.exe", "nissrv.exe", "searchprotocolhost.exe",
                       "searchindexer.exe", "system", "lsass.exe", "svchost.exe", "mpcmdrun.exe"}
