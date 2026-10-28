"""One instance per user session: a named mutex on Windows, an exclusive file lock on macOS/Linux."""
from .config import DATA_DIR
from .osinfo import IS_WIN

_held = []


def acquire(name):
    """Return a handle if we are the only instance called `name` for this data folder, else None."""
    import hashlib
    name = f"{name}-{hashlib.sha256(str(DATA_DIR).lower().encode()).hexdigest()[:10]}"
    if IS_WIN:
        import win32api
        import win32event
        import winerror
        h = win32event.CreateMutex(None, False, f"Local\\{name}")
        if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
            return None
        _held.append(h)
        return h
    import fcntl
    f = open(DATA_DIR / f"{name}.lock", "w")  # noqa: SIM115 (must stay open to hold the lock)
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    _held.append(f)
    return f
