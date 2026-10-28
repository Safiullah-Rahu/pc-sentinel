"""Code-signature checks, cached by path+size+mtime.

Windows: Authenticode (one batched PowerShell call). macOS: codesign. Linux: no universal code signing, so
"signed" means "owned by an installed package" (dpkg/rpm), or a snap/flatpak install.
Statuses: Valid | NotSigned | HashMismatch | NotTrusted | UnknownError | NoAccess | Unknown (not checked yet).
"""
import hashlib
import json
import logging
import os
import queue
import re
import shutil
import subprocess
import threading
import uuid

from . import db
from .config import DATA_DIR, KNOWN_BAD_SHA256
from .osinfo import IS_MAC, IS_WIN

log = logging.getLogger("sentinel.sig")
_pending: "queue.Queue[str]" = queue.Queue()
_queued = set()
_mem = {}  # key -> (status, signer, sha256)
_lock = threading.Lock()
_listeners = []  # callbacks(path, status, signer, sha256)
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$out = foreach ($p in (Get-Content -LiteralPath __LIST__ -Encoding UTF8)) {
  if (-not $p) { continue }
  try { $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
        $cn = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }
        [pscustomobject]@{ p = [string]$p; s = [string]$s.Status; c = [string]$cn } }
  catch { [pscustomobject]@{ p = [string]$p; s = 'NoAccess'; c = '' } }
}
@($out) | ConvertTo-Json -Compress
"""


def key_of(path):
    return path.lower() if IS_WIN else path


def _cn(subject):
    if not subject:
        return None
    for part in subject.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:].strip('"')
    return subject[:80]


def _stat(path):
    try:
        st = os.stat(path)
        return st.st_size, st.st_mtime
    except OSError:
        return None, None


def sha256_of(path, limit=400 * 1024 * 1024):
    try:
        if os.path.getsize(path) > limit:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest().upper()
    except OSError:
        return None


def on_result(cb):
    _listeners.append(cb)


def get(path):
    """Return (status, signer, sha256) or ('Unknown', None, None) and queue a check."""
    if not path:
        return ("Unknown", None, None)
    key = key_of(path)
    with _lock:
        if key in _mem:
            return _mem[key]
    size, mtime = _stat(path)
    row = db.query_one("SELECT size, mtime, status, signer, sha256 FROM sigcache WHERE path=?", (key,))
    if row and size is not None and row["size"] == size and abs((row["mtime"] or 0) - mtime) < 1:
        res = (row["status"], row["signer"], row["sha256"])
        with _lock:
            _mem[key] = res
        return res
    with _lock:
        if key not in _queued:
            _queued.add(key)
            _pending.put(path)
    return ("Unknown", None, None)


def known_bad(sha):
    return KNOWN_BAD_SHA256.get((sha or "").upper())


# ---------------------------------------------------------------- per-OS checkers
def _check_windows(paths):
    # path list goes through a private file (never the command line) so odd file names can't inject anything
    listfile = DATA_DIR / f"siglist-{uuid.uuid4().hex}.txt"
    listfile.write_text("\n".join(paths), encoding="utf-8")
    try:
        script = PS_SCRIPT.replace("__LIST__", "'" + str(listfile).replace("'", "''") + "'")
        cp = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=600, creationflags=NO_WINDOW)
        data = json.loads(cp.stdout or "[]")
        data = [data] if isinstance(data, dict) else data
    except Exception as e:  # noqa: BLE001
        log.warning("signature batch failed: %s", e)
        data = []
    finally:
        try:
            listfile.unlink()
        except OSError:
            pass
    return {key_of(d["p"]): (d.get("s") or "UnknownError", _cn(d.get("c"))) for d in data}


def _bundle_of(path):
    """/Applications/X.app/Contents/MacOS/X -> /Applications/X.app (codesign verifies the whole bundle)."""
    m = re.match(r"^(.*?\.app)/Contents/", path)
    return m.group(1) if m else path


def _check_macos(paths):
    out = {}
    for p in paths:
        target = _bundle_of(p)
        try:
            v = subprocess.run(["codesign", "--verify", "--strict", target], capture_output=True, text=True, timeout=60)
            err = (v.stderr or "").lower()
            if v.returncode == 0:
                status = "Valid"
            elif "not signed" in err:
                status = "NotSigned"
            elif "invalid signature" in err or "modified" in err or "sealed resource" in err or "does not satisfy" in err:
                status = "HashMismatch"
            else:
                status = "UnknownError"
            signer = None
            if status != "NotSigned":
                d = subprocess.run(["codesign", "-dv", "--verbose=2", target], capture_output=True, text=True, timeout=60)
                for line in (d.stderr or "").splitlines():
                    if line.startswith("Authority="):
                        signer = line.split("=", 1)[1].strip()
                        break
                if signer == "Software Signing":
                    signer = "Apple (Software Signing)"
        except (OSError, subprocess.TimeoutExpired):
            status, signer = "UnknownError", None
        out[key_of(p)] = (status, signer)
    return out


def _check_linux(paths):
    out = {}
    for p in paths:
        if re.match(r"^/snap/([^/]+)/", p):
            out[p] = ("Valid", f"snap: {p.split('/')[2]}")
        elif "/flatpak/" in p:
            out[p] = ("Valid", "flatpak")
    rest = [p for p in paths if p not in out]
    if rest and shutil.which("dpkg-query"):
        real = {p: os.path.realpath(p) for p in rest}
        try:
            cp = subprocess.run(["dpkg-query", "-S", *set(real.values())], capture_output=True, text=True, timeout=120)
            owners = {}
            for line in cp.stdout.splitlines():
                if ": " in line:
                    pkg, f = line.split(": ", 1)
                    owners[f.strip()] = pkg.split(":")[0]
            for p, r in real.items():
                if r in owners:
                    out[p] = ("Valid", f"{owners[r]} (apt package)")
        except (OSError, subprocess.TimeoutExpired):
            pass
    rest = [p for p in paths if p not in out]
    if rest and shutil.which("rpm"):
        for p in rest:
            try:
                cp = subprocess.run(["rpm", "-qf", os.path.realpath(p)], capture_output=True, text=True, timeout=30)
                if cp.returncode == 0 and "not owned" not in cp.stdout:
                    out[p] = ("Valid", f"{cp.stdout.strip().splitlines()[0]} (rpm package)")
            except (OSError, subprocess.TimeoutExpired):
                pass
    for p in paths:
        if p not in out:
            out[p] = ("NotSigned", None) if os.path.exists(p) else ("UnknownError", None)
    return out


def _check_batch(paths):
    if IS_WIN:
        return _check_windows(paths)
    if IS_MAC:
        return _check_macos(paths)
    return _check_linux(paths)


def worker(stop_event):
    while not stop_event.is_set():
        try:
            first = _pending.get(timeout=1)
        except queue.Empty:
            continue
        batch = [first]
        while len(batch) < 200:
            try:
                batch.append(_pending.get_nowait())
            except queue.Empty:
                break
        res = _check_batch(batch)
        for path in batch:
            key = key_of(path)
            status, signer = res.get(key, ("UnknownError", None))
            sha = sha256_of(path) if status != "Valid" else None  # hash unsigned/broken files to match known-bad samples
            size, mtime = _stat(path)
            db.execute("INSERT OR REPLACE INTO sigcache(path,size,mtime,status,signer,sha256,checked) VALUES(?,?,?,?,?,?,?)",
                       (key, size, mtime, status, signer, sha, db.now()))
            with _lock:
                _mem[key] = (status, signer, sha)
                _queued.discard(key)
            for cb in _listeners:
                try:
                    cb(path, status, signer, sha)
                except Exception:  # noqa: BLE001
                    log.exception("signature listener failed")
