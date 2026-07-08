"""
app/main.py
===========
Serving layer. Implements the blueprint's defense-in-depth pipeline:

    [Incoming URL]
          |
          v
    +----------+   hit
    | Blocklist|-------> UNSAFE (stage="blocklist")
    +----+-----+
         | miss
         v
    +----------+   hit
    | Allowlist|-------> SAFE (stage="allowlist")
    +----+-----+
         | miss
         v
    +-------------------------+
    | ML model (core.features |
    | -> models/train.py's    |
    | pipeline)                |
    +-------------------------+

Fixes the "Checked URL doesn't match what I typed" bug (screenshot 4):
that bug is a symptom of shared mutable state somewhere (a global variable
holding "the last result," or a frontend not tying a response to the
request that produced it). This app has NO global mutable request state -
every request is handled independently, and the response always echoes
back exactly the URL IT checked. The frontend below uses AbortController
so an in-flight stale request can never overwrite a newer one.

Also exposes developer-only bulk checking (/dev/bulk page, /api/bulk-check
and /api/bulk-check-file endpoints), gated by a secret key auto-generated
in config/dev_key.txt (see core/auth.py) - not open to the public checker.
"""
from __future__ import annotations
import os
import sys
import io
import csv
import logging
from typing import Annotated
from pathlib import Path
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
from core.features import extract_features, extract_features_batch, _safe_urlparse
from core.registry import load_current_model, ModelNotFoundError
from core.lists import is_allowlisted, is_blocklisted, reload_lists
from core.typosquat import find_typosquat_match
from core.auth import require_dev_key, get_or_create_dev_key

# Structured logging of verdicts/stages - domain + outcome only, NEVER the
# full URL (path/query can carry search terms, tokens, session data - the
# same privacy reasoning as the extension's query-string stripping).
# Enough to debug "which domains are generating false-positive reports"
# without logging anything a user typed or visited beyond its domain.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("phishing_detector")


def _domain_only(url: str) -> str:
    """Hostname only, for logging - never the full URL. See module note above."""
    try:
        return _safe_urlparse(url).hostname or "(unparseable)"
    except Exception:
        return "(unparseable)"


def _log_verdict(url: str, verdict: str, stage: str, confidence: float | None = None) -> None:
    conf_str = f" confidence={confidence:.3f}" if confidence is not None else ""
    logger.info(f"domain={_domain_only(url)} verdict={verdict} stage={stage}{conf_str}")

# In production, FastAPI's auto-generated /docs, /redoc, /openapi.json
# disclose the full shape of the dev-only bulk endpoints (header name,
# request/response models) to any unauthenticated scanner - the auth gate
# itself isn't affected, but it aids reconnaissance for no benefit once
# this isn't being actively developed against. Set APP_ENV=production in
# your host's environment variables to close this; defaults open (docs
# visible) for local development, where they're genuinely useful.
_is_production = os.environ.get("APP_ENV", "development").lower() == "production"
app = FastAPI(
    title="Phishing URL Checker",
    docs_url=None if _is_production else "/docs",
    redoc_url=None if _is_production else "/redoc",
    openapi_url=None if _is_production else "/openapi.json",
)

# Browser extensions call this API from a chrome-extension:// origin, which
# is a real, distinct origin as far as CORS is concerned. Wide open here
# (extension calls carry no cookies, and /api/check is meant to be public;
# /api/bulk-check* is separately gated by X-Dev-Key regardless of origin).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

MAX_BULK_URLS = 5000  # guard against an accidental multi-hour request
MAX_URL_LENGTH = 2048  # matches CheckRequest's existing cap
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB - well past any real URL-list file

# the safe/unsafe cutoff used to be a magic 0.5
# written TWICE (single-check + bulk-check paths) - the exact "two paths
# silently diverge" failure mode this codebase otherwise guards against
# everywhere else (core/features.py's whole reason to exist). One
# constant, one place to change it.
#
# TODO (deferred - review's own suggestion): 0.5 is almost never the
# right operating point for a security product with asymmetric
# false-positive/false-negative costs, and there's no "uncertain" band -
# a 50.1% score renders identically to 99.9%. Tuning this from the
# validation PR curve at a target precision, and adding a three-way
# verdict (safe/suspicious/unsafe), is real follow-up work - not done
# here, this fix only removes the duplication.
DECISION_THRESHOLD = 0.5


class CheckRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)


class CheckResponse(BaseModel):
    checked_url: str
    verdict: str          # "safe" | "unsafe"
    stage: str            # "blocklist" | "allowlist" | "typosquat" | "model"
    confidence: float | None = None
    model_version: str | None = None
    note: str | None = None


class BulkCheckRequest(BaseModel):
    # Per-item max_length closes a real gap found in security testing: the
    # list-level max_length above only capped URL COUNT, not per-URL byte
    # size - a single 500,000-character "URL" was accepted and processed,
    # which is what made the event-loop-blocking DoS reachable through
    # plain JSON, no file upload required.
    urls: list[Annotated[str, Field(max_length=MAX_URL_LENGTH)]] = Field(
        ..., min_length=1, max_length=MAX_BULK_URLS
    )


class BulkCheckResponse(BaseModel):
    results: list[CheckResponse]
    summary: dict


def _decide_stage1(url: str) -> CheckResponse | None:
    """Blocklist -> allowlist -> typosquat. Returns None if the URL falls
    through to the ML model (stage1 alone can't decide it). Shared by
    both /api/check and /api/bulk-check so the two paths can never
    silently diverge - the same lesson as core/features.py."""
    result: CheckResponse | None = None
    if is_blocklisted(url):
        result = CheckResponse(checked_url=url, verdict="unsafe", stage="blocklist")
    elif is_allowlisted(url):
        result = CheckResponse(checked_url=url, verdict="safe", stage="allowlist")
    else:
        typosquat_match = find_typosquat_match(url)
        if typosquat_match:
            result = CheckResponse(
                checked_url=url, verdict="unsafe", stage="typosquat",
                note=f"Domain closely resembles known site '{typosquat_match}' but does not match it exactly.",
            )
    if result is not None:
        _log_verdict(url, result.verdict, result.stage)
    return result


@app.get("/health")
def health():
    try:
        _, meta = load_current_model()
        return {"status": "ok", "model_version": meta["version"]}
    except ModelNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.post("/api/admin/reload", dependencies=[Depends(require_dev_key)])
def admin_reload():
    """both core/registry.py and core/lists.py
    advertise 'call cache_clear() after retraining/refresh' in their own
    docstrings, but nothing ever called them and no endpoint existed to
    trigger it - after retraining or editing config/*.json, the running
    server kept serving the OLD model/lists until a manual restart. This
    is the missing wiring, gated behind the same dev key as bulk-check."""
    load_current_model.cache_clear()
    reload_lists()
    try:
        _, meta = load_current_model()
        model_version = meta["version"]
    except ModelNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return {"status": "reloaded", "model_version": model_version}


@app.post("/api/check", response_model=CheckResponse)
def check_url(payload: CheckRequest):
    url = payload.url.strip()

    early = _decide_stage1(url)
    if early is not None:
        return early

    try:
        pipeline, metadata = load_current_model()
    except ModelNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))

    feats = extract_features(url)
    row = pd.DataFrame([feats])
    proba_phishing = float(pipeline.predict_proba(row)[0, 1])
    verdict = "unsafe" if proba_phishing >= DECISION_THRESHOLD else "safe"
    _log_verdict(url, verdict, "model", proba_phishing)

    return CheckResponse(
        checked_url=url,
        verdict=verdict,
        stage="model",
        confidence=proba_phishing,
        model_version=metadata["version"],
    )


def _bulk_check(urls: list[str]) -> BulkCheckResponse:
    """Batch-efficient: stage1 (blocklist/allowlist/typosquat) runs per URL
    since those are cheap dict/edit-distance lookups, but anything that
    falls through gets ONE batched feature-extraction + ONE batched
    pipeline.predict_proba call, instead of reloading/predicting per row -
    the difference between checking 5000 URLs in seconds vs minutes."""
    urls = [u.strip() for u in urls if u.strip()][:MAX_BULK_URLS]

    results: list[CheckResponse | None] = []
    fallthrough_indices = []
    fallthrough_urls = []
    for i, url in enumerate(urls):
        early = _decide_stage1(url)
        results.append(early)
        if early is None:
            fallthrough_indices.append(i)
            fallthrough_urls.append(url)

    if fallthrough_urls:
        try:
            pipeline, metadata = load_current_model()
        except ModelNotFoundError as e:
            raise HTTPException(status_code=503, detail=str(e))
        feats_df = extract_features_batch(fallthrough_urls)
        probs = pipeline.predict_proba(feats_df)[:, 1]
        for idx, url, p in zip(fallthrough_indices, fallthrough_urls, probs):
            p = float(p)
            verdict = "unsafe" if p >= DECISION_THRESHOLD else "safe"
            _log_verdict(url, verdict, "model", p)
            results[idx] = CheckResponse(
                checked_url=url,
                verdict=verdict,
                stage="model",
                confidence=p,
                model_version=metadata["version"],
            )

    final_results = [r for r in results if r is not None]
    summary = {
        "total": len(final_results),
        "safe": sum(1 for r in final_results if r.verdict == "safe"),
        "unsafe": sum(1 for r in final_results if r.verdict == "unsafe"),
        "by_stage": {
            stage: sum(1 for r in final_results if r.stage == stage)
            for stage in ("blocklist", "allowlist", "typosquat", "model")
        },
    }
    return BulkCheckResponse(results=final_results, summary=summary)


@app.post("/api/bulk-check", response_model=BulkCheckResponse, dependencies=[Depends(require_dev_key)])
def bulk_check_json(payload: BulkCheckRequest):
    """Developer-only (X-Dev-Key header required, see core/auth.py). Takes
    a JSON list of URLs directly - useful for scripting."""
    return _bulk_check(payload.urls)


def _csv_safe(value) -> str:
    """OWASP CSV-injection mitigation: prefix any field starting with a
    formula-trigger character with a single quote, forcing spreadsheet
    apps to treat it as text rather than evaluate it. Closes a confirmed
    finding: an uploaded url column value like '=cmd|\' /C calc\'!A1'
    was written verbatim into the exported CSV and would execute as a
    formula if opened in Excel/Sheets."""
    s = "" if value is None else str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


@app.post("/api/bulk-check-file", dependencies=[Depends(require_dev_key)])
def bulk_check_file(file: UploadFile = File(...)):
    """Developer-only. Accepts a .txt (one URL per line) or .csv (a 'url'
    column, or falls back to the first column) and returns a downloadable
    CSV of results - the actual "upload your file of URLs" feature.

    Deliberately a plain `def`, not `async def`: this function does 100%
    synchronous CPU/IO work (parsing, feature extraction, prediction), and
    a synchronous function in FastAPI runs in a threadpool automatically,
    the same as bulk_check_json above already benefits from. The previous
    `async def` version ran all of that directly on the single event-loop
    thread - confirmed in security testing: one 19MB upload froze the
    entire server, including the public /api/check endpoint, for 35
    seconds."""
    content_length = file.size
    if content_length is not None and content_length > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({content_length} bytes); max is {MAX_UPLOAD_BYTES} bytes.",
        )

    raw_bytes = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large; max is {MAX_UPLOAD_BYTES} bytes.",
        )
    raw = raw_bytes.decode("utf-8", errors="ignore")
    urls: list[str] = []

    if file.filename and file.filename.lower().endswith(".csv"):
        reader = csv.reader(io.StringIO(raw))
        rows = list(reader)
        if not rows:
            raise HTTPException(status_code=400, detail="Empty CSV file.")
        header = [h.strip().lower() for h in rows[0]]
        url_col = header.index("url") if "url" in header else 0
        data_rows = rows[1:] if "url" in header else rows
        urls = [r[url_col] for r in data_rows if len(r) > url_col and r[url_col].strip()]
    else:
        urls = [line for line in raw.splitlines() if line.strip()]

    # Per-URL length cap, same reasoning as BulkCheckRequest above - this
    # is what makes the file-upload path exploitable at the same severity
    # as the JSON path was before that fix.
    oversized = sum(1 for u in urls if len(u) > MAX_URL_LENGTH)
    urls = [u[:MAX_URL_LENGTH] for u in urls]

    if not urls:
        raise HTTPException(status_code=400, detail="No URLs found in the uploaded file.")
    if len(urls) > MAX_BULK_URLS:
        raise HTTPException(status_code=400, detail=f"Too many URLs ({len(urls)}); max is {MAX_BULK_URLS} per file.")

    bulk_result = _bulk_check(urls)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["checked_url", "verdict", "stage", "confidence", "model_version", "note"])
    for r in bulk_result.results:
        writer.writerow([_csv_safe(r.checked_url), _csv_safe(r.verdict), _csv_safe(r.stage),
                          r.confidence, _csv_safe(r.model_version), _csv_safe(r.note)])
    output.seek(0)

    headers = {"Content-Disposition": "attachment; filename=bulk_check_results.csv"}
    if oversized:
        headers["X-Truncated-URLs"] = str(oversized)
    return StreamingResponse(output, media_type="text/csv", headers=headers)


STATIC_DIR = Path(__file__).resolve().parent / "static"


@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/dev/bulk", response_class=HTMLResponse)
def dev_bulk_page():
    """No @Depends(require_dev_key) here - the PAGE itself is just HTML/JS;
    the key is entered in the browser and sent as a header on the actual
    /api/bulk-check-file request, which IS protected. Serving the page
    without a key is harmless; it does nothing without a valid key."""
    return (STATIC_DIR / "bulk.html").read_text(encoding="utf-8")


