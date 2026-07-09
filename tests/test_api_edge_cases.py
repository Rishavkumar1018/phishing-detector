"""
tests/test_api_edge_cases.py
==============================
Phase 4 of the 2026-07-09 upgrade plan: systematic backend edge-case
coverage beyond what the earlier per-fix regression files pin down -
input-boundary behavior (length caps, empty/whitespace, exotic-but-legal
characters), malformed requests, and request-shape abuse. Complements:
  test_malformed_urls.py   (unparseable URLs must not 500)
  test_bulk_check.py       (bulk paths, auth, invalid rows)
  test_security_fixes.py   (DoS caps, CSV injection, rate limiting)
  test_p2_fixes.py         (model-missing -> 503, not 500)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import io
import pytest
from fastapi.testclient import TestClient
from app.main import app, MAX_URL_LENGTH
from core.auth import get_or_create_dev_key

client = TestClient(app)


# ---------------------------------------------------------- input bounds --
def test_empty_url_rejected_by_validation():
    resp = client.post("/api/check", json={"url": ""})
    assert resp.status_code == 422  # pydantic min_length=1


def test_whitespace_only_url_is_invalid_not_a_crash():
    resp = client.post("/api/check", json={"url": "   "})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "invalid"
    assert data["verdict"] is None


def test_url_at_exact_max_length_is_accepted():
    url = "https://example.com/" + "a" * (MAX_URL_LENGTH - len("https://example.com/"))
    assert len(url) == MAX_URL_LENGTH
    resp = client.post("/api/check", json={"url": url})
    assert resp.status_code == 200
    assert resp.json()["verdict"] in ("safe", "unsafe")


def test_url_over_max_length_rejected():
    url = "https://example.com/" + "a" * MAX_URL_LENGTH
    resp = client.post("/api/check", json={"url": url})
    assert resp.status_code == 422


# ------------------------------------------------------ exotic characters --
@pytest.mark.parametrize("url", [
    "https://example.com/path with spaces/file.html",
    "https://example.com/%E2%82%AC/price?x=%20y",       # percent-encoded
    "https://пример.рф/страница",                        # full non-Latin URL
    "https://example.com/a?b=c&d=e#fragment",
    "http://user:pass@example.com/",                     # embedded credentials
    "https://example.com/'\";<script>alert(1)</script>",  # injection-shaped path
])
def test_special_character_urls_get_a_verdict_not_a_500(url):
    resp = client.post("/api/check", json={"url": url})
    assert resp.status_code == 200, f"{url} -> {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["status"] == "ok"
    assert data["verdict"] in ("safe", "unsafe")
    assert data["checked_url"] == url  # echo must be exact


# ------------------------------------------------- scheme / pseudo-URLs --
def test_bare_domain_without_scheme_is_checked():
    resp = client.post("/api/check", json={"url": "google.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "safe"
    assert data["stage"] == "allowlist"


@pytest.mark.parametrize("text", [
    "erfgvrthtyjnn",              # keyboard mash, no domain structure
    "javascript:alert(1)",        # pseudo-scheme, no authority
    "not a url at all",
    "12345",
])
def test_non_urls_are_invalid_not_scored(text):
    resp = client.post("/api/check", json={"url": text})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "invalid", f"{text!r} -> {data}"
    assert data["verdict"] is None


# ------------------------------------------------- government / education --
@pytest.mark.parametrize("url", [
    "https://www.usa.gov/",
    "https://www.india.gov.in/",
    "https://www.irs.gov/",
])
def test_allowlisted_government_domains_are_safe(url):
    """The original v1 failure class (india.gov.in flagged unsafe)."""
    resp = client.post("/api/check", json={"url": url})
    data = resp.json()
    assert data["verdict"] == "safe", f"{url} -> {data}"


@pytest.mark.parametrize("url", [
    "https://www.michigan.gov/sos/vehicle/registration",
    "https://ocw.mit.edu/courses/",
    "https://www.ox.ac.uk/admissions/undergraduate",
])
def test_unallowlisted_gov_edu_domains_do_not_crash(url):
    """Not allowlisted, so the verdict comes from the model - we don't
    pin WHICH verdict (that's the model-quality suite's job, and pinning
    it here would make every retrain a test failure), only that the
    pipeline handles compound public-suffix domains without erroring."""
    resp = client.post("/api/check", json={"url": url})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# --------------------------------------------------- malformed requests --
def test_wrong_json_shape_rejected():
    resp = client.post("/api/check", json={"foo": "bar"})
    assert resp.status_code == 422


def test_non_json_body_rejected():
    resp = client.post("/api/check", content=b"just some bytes",
                        headers={"Content-Type": "text/plain"})
    assert resp.status_code == 422


def test_wrong_method_rejected():
    resp = client.get("/api/check")
    assert resp.status_code == 405


def test_url_must_be_a_string_not_a_number():
    resp = client.post("/api/check", json={"url": 12345})
    assert resp.status_code == 422


def test_bulk_check_empty_url_list_rejected():
    key = get_or_create_dev_key()
    resp = client.post("/api/bulk-check", json={"urls": []},
                        headers={"X-Dev-Key": key})
    assert resp.status_code == 422  # pydantic min_length=1


def test_bulk_check_file_empty_upload_rejected():
    key = get_or_create_dev_key()
    resp = client.post(
        "/api/bulk-check-file", headers={"X-Dev-Key": key},
        files={"file": ("empty.txt", io.BytesIO(b""), "text/plain")},
    )
    assert resp.status_code == 400


def test_bulk_check_file_whitespace_only_upload_rejected():
    key = get_or_create_dev_key()
    resp = client.post(
        "/api/bulk-check-file", headers={"X-Dev-Key": key},
        files={"file": ("blank.txt", io.BytesIO(b"\n\n   \n"), "text/plain")},
    )
    assert resp.status_code == 400


# -------------------------------------------------------------- health --
def test_health_reports_model_version():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["model_version"]
