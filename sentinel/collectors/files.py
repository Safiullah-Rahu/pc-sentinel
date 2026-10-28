"""Sensitive-file watchlist (browser credential stores, wallets, SSH keys, messenger keys, canaries)
and, when elevated, the audit rules (SACLs) that make Windows log every read of them (event 4663)."""
import glob
import json
import logging
import os
import subprocess

from .. import state
from ..config import WATCHLIST_PATH
from ..osinfo import IS_MAC, IS_WIN

log = logging.getLogger("sentinel.files")
HOME = os.path.expanduser("~")
if IS_WIN:
    LOCAL = os.environ.get("LOCALAPPDATA", "")
    ROAMING = os.environ.get("APPDATA", "")
    BROWSERS = [  # (label, user-data dir, owning exe names, multi-profile)
        ("Chrome", os.path.join(LOCAL, r"Google\Chrome\User Data"), {"chrome.exe"}, True),
        ("Edge", os.path.join(LOCAL, r"Microsoft\Edge\User Data"), {"msedge.exe", "msedgewebview2.exe"}, True),
        ("Brave", os.path.join(LOCAL, r"BraveSoftware\Brave-Browser\User Data"), {"brave.exe"}, True),
        ("Vivaldi", os.path.join(LOCAL, r"Vivaldi\User Data"), {"vivaldi.exe"}, True),
        ("Opera", os.path.join(ROAMING, r"Opera Software\Opera Stable"), {"opera.exe", "browser_assistant.exe"}, False),
        ("Opera GX", os.path.join(ROAMING, r"Opera Software\Opera GX Stable"), {"opera.exe"}, False),
    ]
    FIREFOX = os.path.join(ROAMING, r"Mozilla\Firefox\Profiles")
    TELEGRAM = os.path.join(ROAMING, r"Telegram Desktop\tdata\key_datas")
    DISCORD = os.path.join(ROAMING, r"discord\Local State")
    SIGNAL = os.path.join(ROAMING, r"Signal\config.json")
    WALLET_ROOT = ROAMING
elif IS_MAC:
    AS = os.path.join(HOME, "Library", "Application Support")
    BROWSERS = [
        ("Chrome", os.path.join(AS, "Google/Chrome"), {"google chrome", "google chrome helper"}, True),
        ("Edge", os.path.join(AS, "Microsoft Edge"), {"microsoft edge"}, True),
        ("Brave", os.path.join(AS, "BraveSoftware/Brave-Browser"), {"brave browser"}, True),
        ("Vivaldi", os.path.join(AS, "Vivaldi"), {"vivaldi"}, True),
        ("Opera", os.path.join(AS, "com.operasoftware.Opera"), {"opera"}, False),
    ]
    FIREFOX = os.path.join(AS, "Firefox/Profiles")
    TELEGRAM = os.path.join(AS, "Telegram Desktop/tdata/key_datas")
    DISCORD = os.path.join(AS, "discord/Local State")
    SIGNAL = os.path.join(AS, "Signal/config.json")
    WALLET_ROOT = AS
else:
    CFG = os.path.join(HOME, ".config")
    BROWSERS = [
        ("Chrome", os.path.join(CFG, "google-chrome"), {"chrome"}, True),
        ("Chromium", os.path.join(CFG, "chromium"), {"chromium", "chromium-browser"}, True),
        ("Edge", os.path.join(CFG, "microsoft-edge"), {"msedge"}, True),
        ("Brave", os.path.join(CFG, "BraveSoftware/Brave-Browser"), {"brave"}, True),
        ("Vivaldi", os.path.join(CFG, "vivaldi"), {"vivaldi-bin"}, True),
        ("Opera", os.path.join(CFG, "opera"), {"opera"}, False),
    ]
    FIREFOX = os.path.join(HOME, ".mozilla/firefox")
    TELEGRAM = os.path.join(HOME, ".local/share/TelegramDesktop/tdata/key_datas")
    DISCORD = os.path.join(CFG, "discord/Local State")
    SIGNAL = os.path.join(CFG, "Signal/config.json")
    WALLET_ROOT = CFG
CANARY_DIR = os.path.join(HOME, "Documents")
CANARIES = ["Bank Passwords (old).txt", "Crypto Wallet Seed Phrase - BACKUP.txt"]


def build_watchlist():
    items = []

    def add(path, label, kind, readers, is_dir=False):
        if os.path.exists(path):
            items.append({"path": path, "label": label, "kind": kind, "readers": sorted(readers), "dir": is_dir})

    for name, root, exes, multi in BROWSERS:
        if not os.path.isdir(root):
            continue
        add(os.path.join(root, "Local State"), f"{name} encryption key (Local State)", "credential", exes)
        profiles = [os.path.join(root, d) for d in os.listdir(root)
                    if d == "Default" or d.startswith("Profile ")] if multi else [root]
        for prof in profiles:
            pname = "" if not multi else f" [{os.path.basename(prof)}]"
            add(os.path.join(prof, "Login Data"), f"{name} saved passwords{pname}", "credential", exes)
            add(os.path.join(prof, "Web Data"), f"{name} cards & autofill{pname}", "credential", exes)
            add(os.path.join(prof, "Network", "Cookies"), f"{name} cookies / sessions{pname}", "credential", exes)
            for wallet_id, wname in (("gojhcdgcpbpfigcaejpfhfegekdgiblk", "Opera Wallet"),
                                     ("nkbihfbglfjjkgkpmhdfhalgbmhedibk", "MetaMask"),
                                     ("bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom")):
                add(os.path.join(prof, "Local Extension Settings", wallet_id), f"{wname} vault ({name})", "wallet", exes, True)
    for prof in glob.glob(os.path.join(FIREFOX, "*")):
        if os.path.isdir(prof):
            ff = {"firefox.exe", "firefox", "firefox-bin"}
            add(os.path.join(prof, "logins.json"), f"Firefox saved passwords [{os.path.basename(prof)}]", "credential", ff)
            add(os.path.join(prof, "key4.db"), f"Firefox password key [{os.path.basename(prof)}]", "credential", ff)
            add(os.path.join(prof, "cookies.sqlite"), f"Firefox cookies [{os.path.basename(prof)}]", "credential", ff)
    add(TELEGRAM, "Telegram session key", "messenger", {"telegram.exe", "telegram", "telegram-desktop"})
    add(DISCORD, "Discord token key", "messenger", {"discord.exe", "discord"})
    add(SIGNAL, "Signal database key", "messenger", {"signal.exe", "signal", "signal-desktop"})
    for k in glob.glob(os.path.join(HOME, ".ssh", "id_*")):
        if not k.endswith(".pub"):
            add(k, f"SSH private key ({os.path.basename(k)})", "ssh",
                {"ssh.exe", "ssh-agent.exe", "git.exe", "code.exe", "ssh-add.exe", "ssh", "ssh-agent", "ssh-add", "git"})
    for wdir, wname in ((os.path.join(WALLET_ROOT, "Exodus", "exodus.wallet"), "Exodus wallet"),
                        (os.path.join(WALLET_ROOT, "Electrum", "wallets"), "Electrum wallets"),
                        (os.path.join(HOME, ".electrum", "wallets"), "Electrum wallets"),
                        (os.path.join(WALLET_ROOT, "atomic", "Local Storage", "leveldb"), "Atomic wallet")):
        add(wdir, wname, "wallet", {"exodus.exe", "electrum.exe", "atomic wallet.exe", "exodus", "electrum"}, True)
    for c in CANARIES:
        add(os.path.join(CANARY_DIR, c), f"Canary: {c}", "canary", set())
    return items


def write_watchlist():
    items = build_watchlist()
    with open(WATCHLIST_PATH, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=1)
    with state.lock:
        state.coverage["canaries"] = sum(1 for i in items if i["kind"] == "canary")
    return items


def create_canaries():
    os.makedirs(CANARY_DIR, exist_ok=True)
    for c in CANARIES:
        p = os.path.join(CANARY_DIR, c)
        if not os.path.exists(p):
            with open(p, "w", encoding="utf-8") as f:
                f.write("PC Sentinel canary file.\r\nThis file is bait: it contains nothing real. If any program other than\r\n"
                        "you opens it, PC Sentinel raises an alert because malware searches for files like this.\r\n")


APPLY_PS = r"""
$ErrorActionPreference = 'Continue'
$items = Get-Content -LiteralPath $args[0] -Raw | ConvertFrom-Json
$ok = 0
foreach ($i in $items) {
  try {
    $inh = if ($i.dir) { 'ContainerInherit,ObjectInherit' } else { 'None' }
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone', 'ReadData', $inh, 'None', 'Success')
    $acl = Get-Acl -LiteralPath $i.path -Audit
    $has = $acl.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $_.FileSystemRights -band 1 }
    if (-not $has) { $acl.AddAuditRule($rule); Set-Acl -LiteralPath $i.path -AclObject $acl }
    $ok++
  } catch { Write-Output "FAIL $($i.path): $($_.Exception.Message)" }
}
Write-Output "APPLIED $ok"
"""


def apply_audit_rules():
    """Windows + admin only. Re-applies ReadData audit rules (files that apps rewrite lose them)."""
    if not (IS_WIN and state.elevated):
        return False
    write_watchlist()
    try:
        script = APPLY_PS.replace("$args[0]", "'" + str(WATCHLIST_PATH).replace("'", "''") + "'")
        cp = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=300, creationflags=subprocess.CREATE_NO_WINDOW)
        log.info("audit rules: %s", (cp.stdout or "").strip()[-300:])
        return "APPLIED" in (cp.stdout or "")
    except Exception as e:  # noqa: BLE001
        log.warning("apply audit rules failed: %s", e)
        return False


def match(object_name, watch):
    """Return the watchlist entry an audited path belongs to."""
    o = (object_name or "").lower()
    for w in watch:
        p = w["path"].lower()
        if o == p or (w.get("dir") and o.startswith(p + "\\")):
            return w
    return None
