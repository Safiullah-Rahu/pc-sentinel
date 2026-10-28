"""Boot the real engine (all collectors) on this OS and check it sees live processes and serves the API."""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_engine_boots_and_collects():
    data = tempfile.mkdtemp(prefix="pcs-smoke-")
    env = {**os.environ, "LOCALAPPDATA": data, "XDG_DATA_HOME": data, "PCSENTINEL_PORT": "8798"}
    if sys.platform == "darwin":
        env["HOME"] = data
    proc = subprocess.Popen([sys.executable, str(ROOT / "main.py")], cwd=ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        token_file = next(Path(data).rglob("token.txt"), None)
        summary = None
        deadline = time.time() + 90
        while time.time() < deadline:
            token_file = token_file or next(Path(data).rglob("token.txt"), None)
            if token_file:
                try:
                    req = urllib.request.Request("http://127.0.0.1:8798/api/summary",
                                                 headers={"X-Sentinel-Token": token_file.read_text().strip()})
                    summary = json.loads(urllib.request.urlopen(req, timeout=3).read())
                    if summary["coverage"]["processes"] and summary["coverage"]["network"] and summary["kpis"]["processes"] > 0:
                        break
                except OSError:
                    pass
            time.sleep(1)
        assert summary, "engine never answered"
        assert summary["kpis"]["processes"] > 0
        assert summary["coverage"]["processes"] and summary["coverage"]["network"]
        log = next(Path(data).rglob("sentinel.log"))
        text = log.read_text(encoding="utf-8", errors="replace")
        assert "Traceback" not in text, text[-3000:]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
