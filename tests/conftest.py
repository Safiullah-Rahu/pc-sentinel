"""Isolate every test run: data folder, token and database live in a throwaway directory."""
import os
import pathlib
import sys
import tempfile

_tmp = tempfile.mkdtemp(prefix="pcs-test-")
os.environ["LOCALAPPDATA"] = _tmp          # Windows data dir
os.environ["XDG_DATA_HOME"] = _tmp         # Linux data dir
if sys.platform == "darwin":
    os.environ["HOME"] = _tmp              # macOS data dir is ~/Library/Application Support
os.environ["PCSENTINEL_PORT"] = "8799"
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
