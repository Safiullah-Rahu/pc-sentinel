"""PC Sentinel desktop app: a native window (+ tray icon on Windows/Linux) around the monitoring engine.

- Starts the engine in-process (or attaches to one that is already running).
- Closing the window hides it; monitoring keeps running. Windows/Linux: tray menu Open / Quit.
- Linux: the window runs in a child process so a GUI/OpenGL crash can never stop monitoring.
  macOS: launch the app again (Dock, Launchpad, Spotlight) to bring the window back; Quit from the app menu.
- Launching a second time never starts a second copy: it asks the running one to show its window.
- `--tray` starts hidden (used by "Start at login").
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
import webbrowser

try:
    import webview
except Exception:  # noqa: BLE001  (no native web-view backend on this desktop: fall back to the browser)
    webview = None

import main as engine
from sentinel import singleton
from sentinel.config import DATA_DIR, HOST, PORT, TOKEN_PATH, TRAY_ICON_PATH
from sentinel.osinfo import IS_LINUX, IS_MAC, IS_WIN

URL = f"http://{HOST}:{PORT}/"
TITLE = "PC Sentinel"


def server_up():
    try:
        urllib.request.urlopen(URL, timeout=1)  # nosec B310 (constant http://127.0.0.1 URL)
        return True
    except urllib.error.HTTPError:
        return True  # it answered
    except OSError:
        return False


def ask_running_app_to_show():
    """Second launch: tell the running app (via its token-protected local API) to show its window."""
    try:
        token = TOKEN_PATH.read_text().strip()
        req = urllib.request.Request(URL + "api/app/show", data=b"{}", method="POST",
                                     headers={"X-Sentinel-Token": token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as r:  # nosec B310 (constant http://127.0.0.1 URL)
            return json.loads(r.read() or b"{}").get("ok", False)
    except (OSError, ValueError):
        return False


# ---------------------------------------------------------------- Windows niceties
def _win_hwnd():
    import win32gui
    return win32gui.FindWindow(None, TITLE)


def _win_focus():
    import win32con
    import win32gui
    hwnd = _win_hwnd()
    if hwnd:
        win32gui.ShowWindow(hwnd, win32con.SW_SHOW)
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        try:
            win32gui.SetForegroundWindow(hwnd)
        except Exception:  # noqa: BLE001 (Windows may refuse focus stealing; the window is still shown)
            pass


def _win_dark_title_bar():
    """Dark, theme-coloured title bar (Windows 11 DWM attributes; harmless no-op on older Windows)."""
    import ctypes
    hwnd = _win_hwnd()
    if not hwnd:
        return
    for attr, value in ((20, 1),               # DWMWA_USE_IMMERSIVE_DARK_MODE
                        (35, 0x000D0705),      # DWMWA_CAPTION_COLOR (#05070d as 0x00BBGGRR)
                        (36, 0x00EED322),      # DWMWA_TEXT_COLOR    (#22d3ee)
                        (34, 0x00473A10)):     # DWMWA_BORDER_COLOR  (#103a47)
        v = ctypes.c_int(value)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(v), ctypes.sizeof(v))


def browser_mode(start_hidden):
    """No native window available: show the dashboard in the default browser; keep monitoring until Ctrl+C / Quit."""
    from sentinel import server
    server.register_ui(show=lambda: webbrowser.open(URL))
    if not start_hidden:
        webbrowser.open(URL)
    stop = {"quit": False}
    try:
        import pystray
        from PIL import Image
        icon = pystray.Icon("PC Sentinel", Image.open(TRAY_ICON_PATH), "PC Sentinel — monitoring this computer",
                            menu=pystray.Menu(pystray.MenuItem("Open PC Sentinel", lambda *_: webbrowser.open(URL), default=True),
                                              pystray.MenuItem("Quit (stop monitoring)", lambda *_: (stop.update(quit=True), icon.stop()))))
        icon.run()  # blocks until Quit
    except Exception:  # noqa: BLE001
        print(f"PC Sentinel is running: {URL}  (Ctrl+C to stop)")
        try:
            while not stop["quit"]:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    engine.stop_engine()


def run_window_only():
    """Child process on Linux: just the window. If the GUI stack crashes (e.g. no OpenGL), only this dies."""
    if webview is None:
        sys.exit(3)
    webview.create_window(TITLE, URL, width=1480, height=920, min_size=(1100, 700),
                          background_color="#05070d", text_select=True)
    webview.start(private_mode=False, storage_path=str(DATA_DIR / "webview"))


def _window_cmd():
    if getattr(sys, "frozen", False):
        return [sys.executable, "--window-only"]
    return [sys.executable, os.path.abspath(__file__), "--window-only"]


def linux_mode(start_hidden):
    """Linux: the engine and tray live here; the window runs in a child process, so a crash in the
    desktop's GTK/Qt/OpenGL stack can never stop monitoring. A window that crashes on start is retried
    once with software rendering, then PC Sentinel falls back to the default browser."""
    import subprocess
    import threading
    st = {"child": None, "started": 0.0, "software": False, "broken": False, "quit": False}
    lock = threading.Lock()

    def watch(child):
        rc = child.wait()
        if st["quit"] or rc == 0 or time.time() - st["started"] > 15:
            return  # closed by the user (or after running fine): keep monitoring in the background
        if not st["software"]:
            st["software"] = True
            spawn()
        else:
            st["broken"] = True
            webbrowser.open(URL)

    def spawn():
        with lock:
            if st["broken"]:
                webbrowser.open(URL)
                return
            if st["child"] and st["child"].poll() is None:
                return  # already open
            env = dict(os.environ)
            if st["software"]:
                env.update(QT_XCB_GL_INTEGRATION="none", QT_QUICK_BACKEND="software", LIBGL_ALWAYS_SOFTWARE="1",
                           QTWEBENGINE_CHROMIUM_FLAGS="--disable-gpu", WEBKIT_DISABLE_COMPOSITING_MODE="1")
            st["child"] = subprocess.Popen(_window_cmd(), env=env)
            st["started"] = time.time()
            threading.Thread(target=watch, args=(st["child"],), daemon=True).start()

    from sentinel import server
    server.register_ui(show=spawn)
    if not start_hidden:
        spawn()
    try:
        import pystray
        from PIL import Image
        icon = pystray.Icon("PC Sentinel", Image.open(TRAY_ICON_PATH), "PC Sentinel — monitoring this computer",
                            menu=pystray.Menu(pystray.MenuItem("Open PC Sentinel", lambda *_: spawn(), default=True),
                                              pystray.Menu.SEPARATOR,
                                              pystray.MenuItem("Quit (stop monitoring)", lambda *_: icon.stop())))
        icon.run()  # blocks until Quit
    except Exception:  # noqa: BLE001  (no tray on this desktop: keep running until Ctrl+C / logout)
        print(f"PC Sentinel is running: {URL}  (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    st["quit"] = True
    if st["child"] and st["child"].poll() is None:
        st["child"].terminate()
    engine.stop_engine()


def main():
    if "--window-only" in sys.argv:
        return run_window_only()
    if IS_WIN:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("PCSentinel.Desktop")
    if singleton.acquire("PCSentinelApp") is None:
        ask_running_app_to_show()  # second launch just brings the existing window forward
        return
    start_hidden = "--tray" in sys.argv

    engine.start_engine(block=False)  # returns False if a headless engine already runs — we just attach to it
    for _ in range(80):
        if server_up():
            break
        time.sleep(0.25)

    if IS_LINUX:
        return linux_mode(start_hidden)
    if webview is None:
        return browser_mode(start_hidden)

    window = webview.create_window(TITLE, URL, width=1480, height=920, min_size=(1100, 700),
                                   background_color="#05070d", hidden=start_hidden, text_select=True)
    flags = {"quitting": False}
    tray = None

    def show():
        window.show()
        window.restore()
        if IS_WIN:
            _win_focus()

    def quit_app():
        flags["quitting"] = True
        if tray:
            tray.stop()
        engine.stop_engine()
        window.destroy()

    def on_closing():
        if flags["quitting"]:
            return True
        window.hide()  # keep watching in the background
        return False

    window.events.closing += on_closing
    if IS_WIN:
        window.events.shown += _win_dark_title_bar

    from sentinel import server
    server.register_ui(show=show)

    if not IS_MAC:  # macOS: pywebview owns the main thread, so no separate tray loop (see module docstring)
        try:
            import pystray
            from PIL import Image
            tray = pystray.Icon("PC Sentinel", Image.open(TRAY_ICON_PATH), "PC Sentinel — monitoring this computer",
                                menu=pystray.Menu(pystray.MenuItem("Open PC Sentinel", lambda *_: show(), default=True),
                                                  pystray.Menu.SEPARATOR,
                                                  pystray.MenuItem("Quit (stop monitoring)", lambda *_: quit_app())))
            tray.run_detached()
        except Exception:  # noqa: BLE001 (no tray support on this desktop: the window still works)
            tray = None

    try:
        webview.start(gui="edgechromium" if IS_WIN else None, private_mode=False,
                      storage_path=str(DATA_DIR / "webview"))
    except Exception:  # noqa: BLE001  (e.g. Linux without GTK/Qt web-view libraries)
        if tray:
            tray.stop()
        return browser_mode(start_hidden)
    if tray:
        tray.stop()
    engine.stop_engine()


if __name__ == "__main__":
    main()
