"""
tests/test_security_fixes.py
==============================
Regression tests for findings from a 2026-07-07 red
team review).16 for the full writeup.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import io
import inspect
from fastapi.testclient import TestClient
from app.main import app, bulk_check_file, MAX_URL_LENGTH
from core.auth import get_or_create_dev_key, _request_log

client = TestClient(app)


def test_bulk_check_file_is_not_async():
    """HIGH finding: bulk_check_file was `async def` but did 100%
    synchronous work, blocking the event loop for the whole server
    (confirmed: one 19MB upload froze /health for 35s). A sync `def` runs
    in FastAPI's threadpool automatically instead."""
    assert not inspect.iscoroutinefunction(bulk_check_file)


def test_oversized_upload_rejected():
    key = get_or_create_dev_key()
    big_content = ("https://example.com/\n" * 1).encode() + b"a" * (6 * 1024 * 1024)
    resp = client.post(
        "/api/bulk-check-file", headers={"X-Dev-Key": key},
        files={"file": ("big.txt", io.BytesIO(big_content), "text/plain")},
    )
    assert resp.status_code == 413


def test_oversized_json_url_rejected():
    """Per-URL length cap on the JSON path - this is what made the DoS
    reachable without any file upload at all."""
    key = get_or_create_dev_key()
    huge_url = "http://example.com/" + "a" * (MAX_URL_LENGTH + 1)
    resp = client.post("/api/bulk-check", json={"urls": [huge_url]},
                        headers={"X-Dev-Key": key})
    assert resp.status_code == 422


def test_csv_injection_escaped():
    """OWASP CSV-injection mitigation: formula-trigger characters at the
    start of a field get a leading single quote so spreadsheet apps treat
    them as text, not formulas."""
    key = get_or_create_dev_key()
    csv_content = "url\n=cmd|'/C calc'!A1\n+2+5\n-2+3\n@SUM(1+1)\n"
    resp = client.post(
        "/api/bulk-check-file", headers={"X-Dev-Key": key},
        files={"file": ("test.csv", io.BytesIO(csv_content.encode()), "text/csv")},
    )
    body = resp.text
    assert "'=cmd" in body
    assert "'+2+5" in body
    assert "'-2+3" in body
    assert "'@SUM" in body
    # and none of the RAW (unescaped) forms appear at the start of a line
    for line in body.splitlines():
        assert not line.startswith(("=", "+", "-", "@"))


def test_xff_client_id_uses_last_hop_not_client_supplied_first(monkeypatch):
    """2026-07-09 audit: in production the rate-limit client ID was the
    FIRST X-Forwarded-For entry - which is whatever the client claims.
    An attacker could rotate fake IPs to bypass the limit, or spoof the
    real developer's IP to lock them out. The platform proxy (Render)
    APPENDS the IP it actually saw, so the LAST entry is the trustworthy
    one."""
    import core.auth as auth

    class FakeClient:
        host = "10.0.0.1"

    class FakeRequest:
        headers = {"x-forwarded-for": "6.6.6.6, 203.0.113.9"}
        client = FakeClient()

    monkeypatch.setattr(auth, "_TRUST_PROXY_HEADERS", True)
    assert auth._get_client_id(FakeRequest()) == "203.0.113.9", (
        "Client ID must come from the proxy-appended (last) XFF hop, "
        "never the client-supplied first hop"
    )
    monkeypatch.setattr(auth, "_TRUST_PROXY_HEADERS", False)
    assert auth._get_client_id(FakeRequest()) == "10.0.0.1", (
        "Outside production, XFF must be ignored entirely (spoofable)"
    )


def test_dev_key_rate_limited():
    """LOW finding: no throttling on repeated wrong-key attempts."""
    _request_log.clear()
    statuses = []
    for _ in range(25):
        resp = client.post("/api/bulk-check", json={"urls": ["https://example.com/"]},
                            headers={"X-Dev-Key": "wrong"})
        statuses.append(resp.status_code)
    assert 429 in statuses
    _request_log.clear()  # don't leak rate-limit state into other tests
