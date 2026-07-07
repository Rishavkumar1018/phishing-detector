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
from pathlib import Path
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field
import sys
import io
import csv

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
from core.features import extract_features, extract_features_batch
from core.registry import load_current_model, ModelNotFoundError
from core.lists import is_allowlisted, is_blocklisted
from core.typosquat import find_typosquat_match
from core.auth import require_dev_key, get_or_create_dev_key

import os

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

from typing import Annotated

MAX_BULK_URLS = 5000  # guard against an accidental multi-hour request
MAX_URL_LENGTH = 2048  # matches CheckRequest's existing cap
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB - well past any real URL-list file


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
    # plain JSON, no file upload required. See AUDIT_NOTES.md 3.16.
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
    if is_blocklisted(url):
        return CheckResponse(checked_url=url, verdict="unsafe", stage="blocklist")
    if is_allowlisted(url):
        return CheckResponse(checked_url=url, verdict="safe", stage="allowlist")
    typosquat_match = find_typosquat_match(url)
    if typosquat_match:
        return CheckResponse(
            checked_url=url, verdict="unsafe", stage="typosquat",
            note=f"Domain closely resembles known site '{typosquat_match}' but does not match it exactly.",
        )
    return None


@app.get("/health")
def health():
    try:
        _, meta = load_current_model()
        return {"status": "ok", "model_version": meta["version"]}
    except ModelNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))


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
    verdict = "unsafe" if proba_phishing >= 0.5 else "safe"

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
            results[idx] = CheckResponse(
                checked_url=url,
                verdict="unsafe" if p >= 0.5 else "safe",
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
    formula if opened in Excel/Sheets. See AUDIT_NOTES.md 3.16."""
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
    seconds. See AUDIT_NOTES.md 3.16."""
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


@app.get("/", response_class=HTMLResponse)
def index():
    return _INDEX_HTML


@app.get("/dev/bulk", response_class=HTMLResponse)
def dev_bulk_page():
    """No @Depends(require_dev_key) here - the PAGE itself is just HTML/JS;
    the key is entered in the browser and sent as a header on the actual
    /api/bulk-check-file request, which IS protected. Serving the page
    without a key is harmless; it does nothing without a valid key."""
    return _BULK_HTML


_INDEX_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Phishing Website Checker</title>
<style>
  body { background:#0b0f19; color:#e5e7eb; font-family:-apple-system,sans-serif;
         display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
  .card { background:#111827; border-radius:12px; padding:28px 32px; width:420px;
          box-shadow:0 4px 24px rgba(0,0,0,.4); }
  h1 { font-size:20px; margin:0 0 4px; }
  p.sub { color:#9ca3af; font-size:13px; margin:0 0 16px; }
  .row { display:flex; gap:8px; }
  input { flex:1; background:#0b0f19; border:1px solid #374151; color:#e5e7eb;
          border-radius:8px; padding:10px 12px; font-size:14px; }
  button { background:#2563eb; color:white; border:none; border-radius:8px;
           padding:10px 18px; font-size:14px; cursor:pointer; }
  button:disabled { opacity:.6; cursor:default; }
  .result { margin-top:18px; font-size:14px; }
  .badge { display:inline-block; padding:3px 10px; border-radius:12px; font-weight:600; font-size:12px; }
  .safe { background:#064e3b; color:#6ee7b7; }
  .unsafe { background:#4c0519; color:#fca5a5; }
  .meta { color:#6b7280; font-size:12px; margin-top:10px; border-top:1px solid #1f2937; padding-top:10px; }
</style>
</head>
<body>
  <div class="card">
    <h1>Phishing Website Checker</h1>
    <p class="sub">Enter a URL to see if this website is safe or unsafe.</p>
    <div class="row">
      <input id="urlInput" value="https://www.example.com/" />
      <button id="checkBtn" onclick="checkUrl()">Check</button>
    </div>
    <div id="result" class="result"></div>
  </div>

<script>
// AbortController ties each response to the request that produced it, so a
// slow older request can NEVER overwrite the display after a newer one has
// already returned. This is the direct fix for the "input says X, result
// says Y" bug: without this, a slow first request finishing after a fast
// second request would silently clobber the correct, newer result.
let currentController = null;

async function checkUrl() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) return;

  if (currentController) currentController.abort();
  currentController = new AbortController();
  const thisController = currentController;

  const btn = document.getElementById('checkBtn');
  btn.disabled = true;

  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url}),
      signal: thisController.signal,
    });
    const data = await res.json();

    // Guard: only render if this is still the most recent request.
    if (thisController !== currentController) return;

    const badgeClass = data.verdict === 'safe' ? 'safe' : 'unsafe';
    const confidenceStr = data.confidence != null
      ? ` (model confidence: ${(data.confidence*100).toFixed(1)}%)` : '';
    const noteStr = data.note ? `<br/><span style="color:#fca5a5">${data.note}</span>` : '';
    document.getElementById('result').innerHTML = `
      <span class="badge ${badgeClass}">${data.verdict.toUpperCase()}</span>
      This website is ${data.verdict}.${confidenceStr}${noteStr}
      <div class="meta">
        Checked URL: ${data.checked_url}<br/>
        Decision stage: ${data.stage}${data.model_version ? ' &middot; model ' + data.model_version : ''}
      </div>`;
  } catch (err) {
    if (err.name !== 'AbortError') {
      document.getElementById('result').innerHTML =
        `<span style="color:#f87171">Error checking URL.</span>`;
    }
  } finally {
    if (thisController === currentController) btn.disabled = false;
  }
}
</script>
</body>
</html>
"""


_BULK_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Bulk URL Checker (Dev)</title>
<style>
  body { background:#0b0f19; color:#e5e7eb; font-family:-apple-system,sans-serif;
         margin:0; padding:32px; }
  .card { background:#111827; border-radius:12px; padding:28px 32px; max-width:900px;
          margin:0 auto; box-shadow:0 4px 24px rgba(0,0,0,.4); }
  h1 { font-size:20px; margin:0 0 4px; }
  p.sub { color:#9ca3af; font-size:13px; margin:0 0 20px; }
  label { display:block; font-size:13px; color:#9ca3af; margin:14px 0 6px; }
  input[type=password], input[type=file], textarea {
    width:100%; box-sizing:border-box; background:#0b0f19; border:1px solid #374151;
    color:#e5e7eb; border-radius:8px; padding:10px 12px; font-size:14px; font-family:inherit;
  }
  textarea { resize:vertical; }
  button { background:#2563eb; color:white; border:none; border-radius:8px;
           padding:10px 18px; font-size:14px; cursor:pointer; margin-top:14px; }
  button:disabled { opacity:.6; cursor:default; }
  .error { color:#fca5a5; font-size:13px; margin-top:10px; }
  table { width:100%; border-collapse:collapse; margin-top:20px; font-size:13px; }
  th, td { text-align:left; padding:6px 10px; border-bottom:1px solid #1f2937; }
  th { color:#9ca3af; font-weight:600; }
  .safe { color:#6ee7b7; }
  .unsafe { color:#fca5a5; }
  .summary { margin-top:16px; font-size:13px; color:#9ca3af; }
  .divider { border-top:1px solid #1f2937; margin:20px 0; }
</style>
</head>
<body>
  <div class="card">
    <h1>Bulk URL Checker</h1>
    <p class="sub">Developer-only. Upload a .txt (one URL per line) or .csv (a "url" column) file, or paste URLs directly.</p>

    <label for="devKey">Dev key</label>
    <input type="password" id="devKey" placeholder="X-Dev-Key" />

    <div class="divider"></div>

    <label for="fileInput">Upload file</label>
    <input type="file" id="fileInput" accept=".txt,.csv" />
    <button id="uploadBtn" onclick="uploadFile()">Check file</button>

    <div class="divider"></div>

    <label for="pasteInput">...or paste URLs (one per line)</label>
    <textarea id="pasteInput" rows="6" placeholder="https://example.com&#10;https://another-example.com"></textarea>
    <button id="pasteBtn" onclick="checkPasted()">Check pasted URLs</button>

    <div id="error" class="error"></div>
    <div id="summary" class="summary"></div>
    <div id="resultsContainer"></div>
  </div>

<script>
function getKey() {
  const key = document.getElementById('devKey').value.trim();
  sessionStorage.setItem('devKey', key);
  return key;
}
window.onload = () => {
  const saved = sessionStorage.getItem('devKey');
  if (saved) document.getElementById('devKey').value = saved;
};

function renderResults(data) {
  document.getElementById('error').textContent = '';
  const s = data.summary;
  document.getElementById('summary').innerHTML =
    `Total: ${s.total} &middot; Safe: ${s.safe} &middot; Unsafe: ${s.unsafe} ` +
    `&middot; By stage: ${Object.entries(s.by_stage).map(([k,v]) => k+'='+v).join(', ')}`;

  let rows = data.results.map(r => `
    <tr>
      <td>${r.checked_url}</td>
      <td class="${r.verdict}">${r.verdict.toUpperCase()}</td>
      <td>${r.stage}</td>
      <td>${r.confidence != null ? (r.confidence*100).toFixed(1)+'%' : ''}</td>
      <td>${r.note || ''}</td>
    </tr>`).join('');

  document.getElementById('resultsContainer').innerHTML = `
    <table>
      <thead><tr><th>URL</th><th>Verdict</th><th>Stage</th><th>Confidence</th><th>Note</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

async function checkPasted() {
  const key = getKey();
  const urls = document.getElementById('pasteInput').value
    .split('\\n').map(u => u.trim()).filter(Boolean);
  if (!urls.length) return;
  document.getElementById('pasteBtn').disabled = true;
  try {
    const res = await fetch('/api/bulk-check', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Dev-Key': key},
      body: JSON.stringify({urls}),
    });
    if (!res.ok) {
      const err = await res.json();
      document.getElementById('error').textContent = err.detail || 'Request failed.';
      return;
    }
    renderResults(await res.json());
  } catch (e) {
    document.getElementById('error').textContent = 'Error checking URLs.';
  } finally {
    document.getElementById('pasteBtn').disabled = false;
  }
}

async function uploadFile() {
  const key = getKey();
  const fileInput = document.getElementById('fileInput');
  if (!fileInput.files.length) return;
  document.getElementById('uploadBtn').disabled = true;
  try {
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    const res = await fetch('/api/bulk-check-file', {
      method: 'POST',
      headers: {'X-Dev-Key': key},
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({detail: 'Request failed.'}));
      document.getElementById('error').textContent = err.detail || 'Request failed.';
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'bulk_check_results.csv';
    a.click();
    document.getElementById('error').textContent = '';
    document.getElementById('summary').textContent = 'Downloaded bulk_check_results.csv';
  } catch (e) {
    document.getElementById('error').textContent = 'Error checking file.';
  } finally {
    document.getElementById('uploadBtn').disabled = false;
  }
}
</script>
</body>
</html>
"""
