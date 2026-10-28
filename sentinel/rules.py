"""Trust classification and suspicious-trait flags for executables and command lines."""
import ipaddress
import os
import re
import stat
from functools import lru_cache

from . import db, signatures
from .config import (KNOWN_DOT_DIRS, LOLBIN_RULES, SCRIPT_EXT, STORE_APPS, SUSPICIOUS_PATHS, SYSTEM_APP_DIRS,
                     TRUSTED_SIGNERS)
from .osinfo import IS_WIN

HOME = os.path.expanduser("~")
SEP = "\\" if IS_WIN else "/"
# kept for backwards compatibility with older imports
PROGRAM_FILES, WINDOWSAPPS = SYSTEM_APP_DIRS, STORE_APPS


@lru_cache(maxsize=4096)
def _dir_hidden(d):
    name = os.path.basename(d)
    if IS_WIN:
        try:
            return bool(os.stat(d).st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)
        except OSError:
            return False
    return name.startswith(".") and name not in KNOWN_DOT_DIRS


def in_hidden_dir(path):
    """True if a folder between the home folder and the file is hidden (Windows Hidden attribute, or an
    unusual dot-folder on macOS/Linux). AppData / well-known developer dot-folders don't count."""
    p = path or ""
    home = HOME.lower() if IS_WIN else HOME
    if not (p.lower() if IS_WIN else p).startswith(home + SEP):
        return False
    parts = os.path.dirname(p).split(SEP)
    base = len(HOME.split(SEP))
    for i in range(base + 1, len(parts) + 1):
        d = SEP.join(parts[:i])
        if IS_WIN and d.lower().endswith("\\appdata"):
            continue
        if _dir_hidden(d):
            return True
    return False


@lru_cache(maxsize=2048)
def _overlay(path, size, mtime):
    """Bytes appended after the PE image (minus a trailing signature). Malware pads this to 100+ MB."""
    import struct
    try:
        with open(path, "rb") as f:
            hdr = f.read(4096)
            if hdr[:2] != b"MZ":
                return 0
            pe = struct.unpack_from("<I", hdr, 0x3C)[0]
            if hdr[pe:pe + 4] != b"PE\0\0":
                f.seek(pe)
                hdr = hdr[:pe] + f.read(4096)
            nsec = struct.unpack_from("<H", hdr, pe + 6)[0]
            opt_size = struct.unpack_from("<H", hdr, pe + 20)[0]
            opt = pe + 24
            magic = struct.unpack_from("<H", hdr, opt)[0]
            dd = opt + (112 if magic == 0x20B else 96)
            cert_off, cert_size = struct.unpack_from("<II", hdr, dd + 4 * 8)
            sec = opt + opt_size
            f.seek(sec)
            table = f.read(40 * nsec)
        end = 0
        for i in range(nsec):
            raw_size, raw_ptr = struct.unpack_from("<II", table, i * 40 + 16)
            end = max(end, raw_ptr + raw_size)
        tail = size - end
        if cert_off and cert_off >= end:
            tail -= cert_size
        return max(0, tail)
    except (OSError, struct.error):
        return 0


def overlay_size(path):
    try:
        st = os.stat(path)
    except OSError:
        return 0
    return _overlay(path, st.st_size, st.st_mtime)


def suspicious_location(path):
    for rx, label in SUSPICIOUS_PATHS:
        if rx.search(path or ""):
            return label
    return None


_allow_cache = {"t": 0, "v": set()}


def allowlisted(kind, value):
    import time
    if time.time() - _allow_cache["t"] > 5:
        _allow_cache["v"] = {(r["kind"], (r["value"] or "").lower()) for r in db.query("SELECT kind, value FROM allowlist")}
        _allow_cache["t"] = time.time()
    return (kind, (value or "").lower()) in _allow_cache["v"]


def invalidate_allow_cache():
    _allow_cache["t"] = 0


def assess(exe, cmdline="", size=None):
    """Return dict(sig_status, signer, trust, flags, sha256, note) for an executable path."""
    flags = []
    if not exe:
        return {"sig_status": "Unknown", "signer": None, "trust": "known", "flags": [], "sha256": None, "note": None}
    status, signer, sha = signatures.get(exe)
    note = None
    bad = signatures.known_bad(sha)
    loc = suspicious_location(exe)
    hidden = in_hidden_dir(exe)
    if size is None:
        try:
            size = os.path.getsize(exe)
        except OSError:
            size = 0

    if status == "HashMismatch":
        flags.append("sig_mismatch")
    elif status in ("NotSigned", "UnknownError", "NotTrusted", "NoAccess") and not WINDOWSAPPS.search(exe):
        flags.append("unsigned")
    if loc:
        flags.append("user_writable_path")
        note = loc
    if hidden:
        flags.append("hidden_dir")
    if size and size > 50 * 1024 * 1024 and status not in ("Valid", "Unknown") and not PROGRAM_FILES.search(exe) \
            and overlay_size(exe) > 40 * 1024 * 1024:
        flags.append("padded_binary")
    name = re.split(r"[\\/]", exe)[-1].lower()  # works for both path styles on every OS
    for lol, rx in LOLBIN_RULES:
        if name == lol and cmdline and rx.search(cmdline):
            flags.append("lolbin")
            break

    if bad:
        trust, note = "malicious", bad
        flags.append("known_bad_hash")
    elif status == "HashMismatch":
        trust = "malicious"
    elif allowlisted("process", exe):
        trust = "known"
    elif status == "Valid":
        trust = "trusted" if (signer and TRUSTED_SIGNERS.search(signer)) else "known"
        if loc or hidden:
            trust = "suspicious" if hidden else trust
    elif WINDOWSAPPS.search(exe):
        trust = "known"
    elif status == "Unknown":
        trust = "known" if PROGRAM_FILES.search(exe) else "unsigned"
    elif loc or hidden or "padded_binary" in flags:
        trust = "suspicious"
    else:
        trust = "unsigned"
    if "lolbin" in flags and trust in ("trusted", "known"):
        trust = "suspicious"
    return {"sig_status": status, "signer": signer, "trust": trust, "flags": flags, "sha256": sha, "note": note}


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):
        return True  # CGNAT / Tailscale tailnet
    return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved


def script_in_cmdline(cmdline):
    return bool(cmdline and SCRIPT_EXT.search(cmdline))
