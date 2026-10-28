# -*- mode: python ; coding: utf-8 -*-
# Build on each OS (PyInstaller cannot cross-compile):
#   pyinstaller --noconfirm pc_sentinel.spec
#   Windows -> dist/PC Sentinel/PC Sentinel.exe   macOS -> dist/PC Sentinel.app   Linux -> dist/PC Sentinel/PC Sentinel
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

WIN, MAC = sys.platform == "win32", sys.platform == "darwin"

hidden = collect_submodules("uvicorn") + collect_submodules("sentinel") + collect_submodules("webview.platforms") + ["pystray"]
if WIN:
    hidden += ["win32evtlog", "win32timezone", "win32gui", "win32con", "pythoncom", "pywintypes", "win32com.client",
               "pystray._win32", "winotify", "clr"]
elif MAC:
    hidden += ["pystray._darwin"]
else:
    hidden += ["pystray._appindicator", "pystray._xorg", "pystray._gtk"]

datas = ([("dashboard", "dashboard"), ("assets/sentinel.ico", "assets"), ("assets/sentinel-64.png", "assets"),
          ("assets/sentinel-256.png", "assets")] + collect_data_files("webview"))

excludes = ["tkinter", "matplotlib", "numpy", "pandas", "scipy", "IPython", "PyQt5", "PySide2"]
if WIN or MAC:
    excludes += ["PyQt6", "PySide6"]  # Linux may use Qt for the web view

a = Analysis(["desktop.py"], pathex=["."], datas=datas, hiddenimports=hidden, excludes=excludes, noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="PC Sentinel",
          icon="assets/sentinel.ico" if WIN else ("assets/sentinel-256.png" if MAC else None),
          console=False, upx=False)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="PC Sentinel")
if MAC:
    app = BUNDLE(coll, name="PC Sentinel.app", icon="assets/sentinel-256.png", bundle_identifier="io.github.pcsentinel",
                 info_plist={"CFBundleShortVersionString": "1.1.0", "NSHighResolutionCapable": True,
                             "LSApplicationCategoryType": "public.app-category.utilities"})
