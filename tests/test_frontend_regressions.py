"""
tests/test_frontend_regressions.py
====================================
Source-inspection regression tests for the frontend bugs fixed in the
2026-07-09 audit pass (same approach as test_p1_fixes.py: real XSS/DOM
behavior needs a browser, but each of these bugs has an unambiguous
source-level signature that a plain text check can pin down).
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]


def _read(relpath: str) -> str:
    return (ROOT / relpath).read_text(encoding="utf-8")


def test_bulk_paste_splits_on_real_newlines():
    """bulk.html split pasted input on the two-character literal
    backslash-n ( .split('\\n') in the JS source), which never occurs in
    textarea input - so ALL pasted URLs were concatenated and checked as
    one giant 'URL'. The paste feature was completely broken. Must split
    on a real newline regex (handling Windows CRLF too)."""
    bulk = _read("app/static/bulk.html")
    assert r"split('\n')" not in bulk, (
        "bulk.html splits pasted URLs on a literal backslash-n again - "
        "this breaks the paste feature entirely"
    )
    assert r"split(/\r?\n/)" in bulk, "expected newline-regex split not found"


def test_bulk_page_renders_invalid_rows():
    """Once /api/bulk-check can return status='invalid' rows (verdict
    null), the results table must not call .toUpperCase() on null."""
    bulk = _read("app/static/bulk.html")
    assert "invalid" in bulk, "bulk.html has no handling for invalid rows"
    assert "r.status === 'invalid'" in bulk


def test_popup_handles_invalid_status_without_crashing():
    """popup.js renderStatus() crashed (TypeError on
    result.verdict.toUpperCase()) when the backend answered
    status='invalid' with verdict=null - e.g. a manual check on an
    intranet host or localhost."""
    popup = _read("extension/popup.js")
    assert 'result.status === "invalid"' in popup, (
        "popup.js does not handle the backend's status='invalid' response"
    )


def test_index_submits_on_enter_key():
    """The URL input isn't inside a <form>, so Enter did nothing -
    clicking the button was the only way to submit."""
    index = _read("app/static/index.html")
    assert "keydown" in index and "'Enter'" in index, (
        "index.html has no Enter-key submit handler"
    )


def test_index_handles_http_error_responses_deliberately():
    """Non-2xx responses (422 URL-too-long, 429, 503) previously 'worked'
    only because data.verdict.toUpperCase() threw a TypeError that
    happened to land in the catch block."""
    index = _read("app/static/index.html")
    assert "!res.ok" in index, "index.html never checks res.ok"


def test_options_page_validates_backend_url_before_saving():
    """options.js saved any string as the backend URL; a typo silently
    broke every subsequent check (fail-open '?' badge on every site)."""
    options = _read("extension/options.js")
    assert "new URL(" in options, "options.js does not validate the URL"
    for proto_check in ['u.protocol === "http:"', 'u.protocol === "https:"']:
        assert proto_check in options, "options.js does not restrict to http(s)"
