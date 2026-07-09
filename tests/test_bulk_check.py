"""
tests/test_bulk_check.py
=========================
Covers: auth gating (no key / wrong key rejected), JSON bulk check,
CSV/TXT file upload, and that results match what /api/check would give
for the same URLs individually (no drift between single and bulk paths).
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import io
from fastapi.testclient import TestClient
from app.main import app
from core.auth import get_or_create_dev_key

client = TestClient(app)

TEST_URLS = [
    "https://www.google.com/",
    "https://www.sbl.co.in/",
    "http://192.168.10.5/wp-admin/login.php?redirect=confirm",
]


def test_bulk_check_rejects_missing_key():
    resp = client.post("/api/bulk-check", json={"urls": TEST_URLS})
    assert resp.status_code == 401


def test_bulk_check_rejects_wrong_key():
    resp = client.post("/api/bulk-check", json={"urls": TEST_URLS},
                        headers={"X-Dev-Key": "definitely-wrong"})
    assert resp.status_code == 401


def test_bulk_check_json_with_correct_key():
    key = get_or_create_dev_key()
    resp = client.post("/api/bulk-check", json={"urls": TEST_URLS},
                        headers={"X-Dev-Key": key})
    assert resp.status_code == 200
    data = resp.json()
    assert data["summary"]["total"] == len(TEST_URLS)
    verdicts = {r["checked_url"]: r["verdict"] for r in data["results"]}
    assert verdicts["https://www.google.com/"] == "safe"
    assert verdicts["https://www.sbl.co.in/"] == "unsafe"
    assert verdicts["http://192.168.10.5/wp-admin/login.php?redirect=confirm"] == "unsafe"


def test_bulk_matches_single_check_no_drift():
    """The single and bulk paths share _decide_stage1 and the same model
    call pattern - this pins that they can't silently diverge."""
    key = get_or_create_dev_key()
    bulk_resp = client.post("/api/bulk-check", json={"urls": TEST_URLS},
                             headers={"X-Dev-Key": key})
    bulk_by_url = {r["checked_url"]: r for r in bulk_resp.json()["results"]}
    for url in TEST_URLS:
        single = client.post("/api/check", json={"url": url}).json()
        assert single["verdict"] == bulk_by_url[url]["verdict"]
        assert single["stage"] == bulk_by_url[url]["stage"]


def test_bulk_check_file_txt_upload():
    key = get_or_create_dev_key()
    content = "\n".join(TEST_URLS).encode()
    resp = client.post(
        "/api/bulk-check-file",
        headers={"X-Dev-Key": key},
        files={"file": ("urls.txt", io.BytesIO(content), "text/plain")},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    body = resp.text
    assert "checked_url,verdict,stage" in body
    assert "www.google.com" in body


def test_bulk_check_file_csv_upload_with_url_column():
    key = get_or_create_dev_key()
    csv_content = "name,url\nGoogle,https://www.google.com/\nTyposquat,https://www.sbl.co.in/\n"
    resp = client.post(
        "/api/bulk-check-file",
        headers={"X-Dev-Key": key},
        files={"file": ("urls.csv", io.BytesIO(csv_content.encode()), "text/csv")},
    )
    assert resp.status_code == 200
    body = resp.text
    assert "www.google.com" in body
    assert "sbl.co.in" in body


def test_bulk_check_file_requires_key():
    content = b"https://www.google.com/"
    resp = client.post(
        "/api/bulk-check-file",
        files={"file": ("urls.txt", io.BytesIO(content), "text/plain")},
    )
    assert resp.status_code == 401


def test_bulk_check_marks_non_urls_invalid_instead_of_scoring_them():
    """2026-07-09 audit: the bulk path never called is_valid_url (the
    single-check path has since commit 08ecdec), so a stray non-URL line
    in an uploaded file got fed to the model and came back with a
    confident safe/unsafe verdict - the exact single-vs-bulk drift
    _decide_stage1's docstring promises can't happen."""
    key = get_or_create_dev_key()
    resp = client.post(
        "/api/bulk-check",
        json={"urls": ["https://www.google.com/", "definitely not a url"]},
        headers={"X-Dev-Key": key},
    )
    assert resp.status_code == 200
    data = resp.json()
    by_url = {r["checked_url"]: r for r in data["results"]}
    bad = by_url["definitely not a url"]
    assert bad["status"] == "invalid"
    assert bad["verdict"] is None
    assert data["summary"]["invalid"] == 1
    assert by_url["https://www.google.com/"]["verdict"] == "safe"
    # and the single path agrees - no drift in the other direction either
    single = client.post("/api/check", json={"url": "definitely not a url"}).json()
    assert single["status"] == "invalid"
    assert single["verdict"] is None


def test_bulk_check_file_reports_invalid_rows_in_csv():
    """File-upload path: invalid rows appear in the exported CSV with an
    empty verdict and status=invalid, instead of a made-up verdict."""
    key = get_or_create_dev_key()
    content = "https://www.google.com/\nnot-a-real-url-line\n".encode()
    resp = client.post(
        "/api/bulk-check-file",
        headers={"X-Dev-Key": key},
        files={"file": ("urls.txt", io.BytesIO(content), "text/plain")},
    )
    assert resp.status_code == 200
    body = resp.text
    assert "status" in body.splitlines()[0]
    invalid_line = next(l for l in body.splitlines() if "not-a-real-url-line" in l)
    assert "invalid" in invalid_line


def test_bulk_check_rejects_over_limit():
    key = get_or_create_dev_key()
    from app.main import MAX_BULK_URLS
    too_many = ["https://example.com/"] * (MAX_BULK_URLS + 1)
    resp = client.post("/api/bulk-check", json={"urls": too_many},
                        headers={"X-Dev-Key": key})
    assert resp.status_code == 422  # pydantic max_length validation
