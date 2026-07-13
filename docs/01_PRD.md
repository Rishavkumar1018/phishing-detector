# Product Requirements Document — Phishing URL Detector

## Problem Statement

Phishing sites trick people into typing passwords, OTPs, and card details into
fake pages that look like a bank, a government portal, or a well-known brand.
Most people can't reliably tell a real domain from a lookalike one at a
glance (`sbl.co.in` vs `sbi.co.in`), and by the time a browser's built-in
warnings or a security team notices, the damage is often done. This app
gives anyone — a single person pasting a suspicious link from a text
message, or someone checking a whole spreadsheet of URLs — an instant,
plain-language verdict on whether a URL is safe to visit, with a reason they
can actually understand.

## Target Users

- **Everyday users** who receive a suspicious link (SMS, email, WhatsApp)
  and want a fast yes/no answer without technical knowledge. Low to medium
  tech comfort — the product must explain verdicts in plain English, not
  model scores or jargon.
- **People auditing a batch of links** — e.g. checking a list of URLs
  collected from spam reports or a phishing awareness exercise. Comfortable
  pasting text or uploading a `.txt`/`.csv`, but not writing code.
- **Developers/scripters** who want to call the detector programmatically
  (`curl`/`POST /api/check`) to integrate it into their own tooling.
- **The always-on user** who wants protection without having to remember to
  check anything — covered by the browser extension, which checks every
  site automatically before it loads.

## Product Vision

Become the fastest, most trustworthy first check anyone reaches for before
clicking an unfamiliar link — whether that's one URL typed by hand, a batch
of hundreds pasted from a report, or every site visited automatically in the
background.

## Core Features

| Feature | Description | Priority |
|---|---|---|
| Single URL check | Paste one URL, get a safe/unsafe verdict with plain-language reason | Must-have |
| Bulk paste check | Paste up to 50 URLs (newline or comma separated), get a results table | Must-have |
| Bulk file upload check | Upload a `.txt`/`.csv` (up to 2MB, up to 75 URLs), URLs extracted automatically regardless of column/position | Must-have |
| Bulk results export | Download bulk results as CSV or Excel, with CSV-injection-safe formatting | Must-have |
| Blocklist/allowlist stage | Known-bad and known-good domains resolve instantly without invoking the ML model | Must-have |
| Typosquat detection | Flags domains that closely resemble a known brand (e.g. `arnazon.com` vs `amazon.com`) and names the real domain being impersonated | Must-have |
| ML verdict | For anything not caught by the above, an XGBoost/sklearn pipeline scores the URL's structural features | Must-have |
| Browser extension (Manifest V3) | Automatically checks every site visited, before it loads, using the same backend | Must-have |
| Health check endpoint | `/health` reports service + model version status, used by uptime checks and the extension | Must-have |
| Admin model/list reload | Dev-key-gated hot-swap of the model/lists after retraining, no restart needed | Nice-to-have (operator-only) |
| Public API access | `/api/check`, `/api/bulk-check-*` are usable directly via `curl`/scripts, no auth | Nice-to-have |

**Deliberately NOT in this version:** user accounts/login, per-user history
or saved-checks, real-time threat-feed ingestion (blocklist/allowlist are
static JSON files, meant to be swapped for live feeds later), multi-language
UI, mobile app, and browser support beyond Chromium (Manifest V3).

## App Flow

**Single check (web):**
1. User lands on the homepage and sees a single search-bar-style input.
2. User pastes/types a URL and submits.
3. Backend runs the URL through: blocklist → allowlist → typosquat → ML
   model, stopping at the first stage that reaches a verdict.
4. Response renders as Safe/Unsafe with a plain-language reason (and, for
   unsafe verdicts, the real domain being impersonated if known).
5. An in-flight request is never overwritten by a stale one — every
   response is bound to the exact request that produced it (`AbortController`
   client-side), so what's shown always matches what was typed.

**Bulk check (paste or upload):**
1. User clicks the **+** next to the search bar.
2. Chooses **paste** (textarea, up to 50 URLs) or **upload** (`.txt`/`.csv`,
   up to 75 URLs, 2MB max).
3. Submits; backend extracts/splits URLs, runs each through the same
   detection pipeline as the single check (batched feature extraction +
   one model call for anything reaching the ML stage).
4. Results render as a table: URL, Safe/Unsafe/Invalid, percent chance, and
   reason (for unsafe rows).
5. User optionally downloads the table as CSV or XLSX, built in memory —
   nothing about the upload or results is stored server-side.

**Browser extension:**
1. User loads the unpacked extension, opens Settings, and points it at a
   deployed backend URL (localhost won't work once the browser closes).
2. On every navigation, the extension calls the backend before the page
   finishes loading.
3. Unsafe verdicts show a warning page; if a typosquat/impersonation match
   exists, the warning offers a link to the real (allowlisted) site.

## Success Metrics

- **Regression correctness**: zero failures on `test_regression_known_sites.py`
  (the known-benign sites — `perplexity.ai`, `discord.com`, `india.gov.in`,
  `icici.bank.in` — that a prior version got wrong) before any deploy.
- **False positive rate** on well-known benign sites, tracked via the
  regression suite and the 100k-URL evaluation in `models/evaluate.py`.
- **Bulk-check completion rate**: percentage of bulk submissions that return
  results without hitting the 50/75-URL or 2MB caps (signals whether limits
  are too tight for real usage).
- **Extension adoption**: number of installs / active backend health-check
  pings from extension instances.
- **API uptime**: `/health` endpoint success rate on the deployed Render
  instance, including cold-start recovery time after free-tier spin-down.
