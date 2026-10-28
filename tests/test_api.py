"""The local API is the attack surface: it must refuse anything without the token, the right Host and sane input."""
import pytest
from fastapi.testclient import TestClient

from sentinel.server import TOKEN, app

BASE = "http://127.0.0.1:8799"
AUTH = {"X-Sentinel-Token": TOKEN}


@pytest.fixture()
def client():
    return TestClient(app, base_url=BASE)


def test_api_requires_token(client):
    assert client.get("/api/summary").status_code == 401
    assert client.get("/api/summary", headers={"X-Sentinel-Token": "wrong"}).status_code == 401


def test_token_in_query_string_only_allowed_for_stream(client):
    assert client.get(f"/api/summary?token={TOKEN}").status_code == 401


def test_foreign_host_rejected(client):
    evil = TestClient(app, base_url="http://evil.example:8799")
    assert evil.get("/api/summary", headers=AUTH).status_code == 403
    assert evil.get("/").status_code == 403


def test_summary_shape(client):
    r = client.get("/api/summary", headers=AUTH)
    assert r.status_code == 200
    s = r.json()
    assert s["engine"]["platform"] in ("windows", "macos", "linux")
    assert set(s["coverage"]) == set(s["coverage_supported"])
    assert 0 <= s["risk"]["score"] <= 100


def test_security_headers(client):
    r = client.get("/api/summary", headers=AUTH)
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp and "script-src 'self'" in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_large_body_rejected(client):
    r = client.post("/api/actions/allow", headers={**AUTH, "Content-Type": "application/json"},
                    content=b'{"kind":"process","value":"' + b"a" * 70000 + b'"}')
    assert r.status_code == 413


def test_index_injects_token_and_is_not_cached(client):
    r = client.get("/")
    if r.status_code == 503:
        pytest.skip("dashboard files not present")
    assert r.status_code == 200
    assert TOKEN in r.text and "__SENTINEL_TOKEN__" not in r.text
    assert r.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("ip", ["not-an-ip", "127.0.0.1", "192.168.1.10", "10.0.0.1", "1.2.3.4; rm -rf /", "::1"])
def test_block_ip_rejects_invalid_and_private(client, ip):
    r = client.post("/api/actions/block_ip", headers=AUTH, json={"ip": ip})
    assert r.status_code == 200 and r.json()["ok"] is False


@pytest.mark.parametrize("pid", ["abc", None, 0, 1, 4, -5, "1; whoami"])
def test_kill_rejects_bad_or_protected_pids(client, pid):
    r = client.post("/api/actions/kill", headers=AUTH, json={"pid": pid})
    assert r.status_code == 200 and r.json()["ok"] is False


def test_allow_validates_kind(client):
    r = client.post("/api/actions/allow", headers=AUTH, json={"kind": "everything", "value": "x"})
    assert r.json()["ok"] is False


def test_unknown_action_404(client):
    assert client.post("/api/actions/format_disk", headers=AUTH, json={}).status_code == 404


def test_notify_toggle_roundtrip(client):
    assert client.post("/api/actions/notify", headers=AUTH, json={"enabled": True, "min_severity": "critical"}).json()["ok"]
    assert client.get("/api/settings", headers=AUTH).json()["notify"] == {"enabled": True, "min_severity": "critical"}
    client.post("/api/actions/notify", headers=AUTH, json={"enabled": False, "min_severity": "high"})
    assert client.get("/api/settings", headers=AUTH).json()["notify"]["enabled"] is False


@pytest.mark.parametrize("path", ["/api/graph", "/api/processes", "/api/network/connections", "/api/network/apps",
                                  "/api/network/destinations", "/api/network/listening", "/api/dns", "/api/privacy",
                                  "/api/persistence", "/api/files", "/api/events", "/api/alerts", "/api/metrics",
                                  "/api/settings"])
def test_read_endpoints_respond(client, path):
    assert client.get(path, headers=AUTH).status_code == 200
