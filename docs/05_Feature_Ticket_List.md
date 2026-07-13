# Feature Ticket List — Phishing URL Detector

Status reflects the current repo state (2026-07-12). Shipped tickets are
kept here as the reference spec for their acceptance criteria — useful when
touching that code again — plus a set of not-yet-built tickets for the
PRD's remaining nice-to-haves.

---

### TICKET-01 — Single URL Check API
**Status:** Shipped (`POST /api/check`, `app/main.py`)
**Description:** Accept a single URL and return a safe/unsafe/invalid
verdict by running it through blocklist → allowlist → typosquat → ML model,
in that order, stopping at the first stage that decides.
**Acceptance Criteria:**
- A blocklisted domain returns `verdict: "unsafe", stage: "blocklist"` without invoking the model.
- An allowlisted domain returns `verdict: "safe", stage: "allowlist"` without invoking the model.
- A typosquat match (e.g. `sbl.co.in`) returns `verdict: "unsafe", stage: "typosquat"` with `legit_domain` set to the real allowlisted domain.
- Anything else returns a `stage: "model"` verdict with a `confidence` score and `model_version`.
- Non-URL input returns `status: "invalid"` with a user-facing `message`, never a verdict.
- The response's `checked_url` always exactly matches the URL that was checked (no shared mutable state, no stale-response bugs).
**Dependencies:** `core/features.py`, `core/registry.py`, `core/lists.py`, `core/typosquat.py`.
**Priority:** Must-have.

---

### TICKET-02 — Bulk Paste Check
**Status:** Shipped (`POST /api/bulk-check-paste`)
**Description:** Accept freeform pasted text (newline- and/or comma-
separated), split it into individual tokens, and run every token through
the same detection pipeline as TICKET-01.
**Acceptance Criteria:**
- Every pasted token is preserved and checked, including ones that aren't valid URLs (returned as `"Invalid"` rows, never silently dropped).
- Requests with more than 50 URLs are rejected outright (`400`) — never silently truncated.
- Empty/whitespace-only submissions are rejected with a clear message.
- Results and single-check results never diverge for the same URL (shared `_decide_stage1`/`_bulk_check` code path).
**Dependencies:** TICKET-01's detection pipeline.
**Priority:** Must-have.

---

### TICKET-03 — Bulk File Upload Check
**Status:** Shipped (`POST /api/bulk-check-upload`)
**Description:** Accept a `.txt` or `.csv` upload (≤2MB), extract URL-like
substrings from anywhere in its content (not assumed to be in a specific
column), dedupe, cap at 75, and check each through the same pipeline.
**Acceptance Criteria:**
- Only `.txt`/`.csv` extensions accepted; anything else returns `400`.
- Files over 2MB are rejected (`413`), verified against both declared and actual size.
- The file is never written to disk and nothing about its content persists past the response.
- URL extraction is safe against adversarial input (no catastrophic-backtracking regex) — verified against a 2,000,000-character adversarial payload completing in under 1 second.
- More than 75 extracted URLs → `400`, not silent truncation.
**Dependencies:** TICKET-01's detection pipeline.
**Priority:** Must-have.

---

### TICKET-04 — Bulk Results Export (CSV/XLSX)
**Status:** Shipped (`POST /api/bulk-check-export`)
**Description:** Turn a set of results the browser already has (from
TICKET-02/03) into a downloadable CSV or Excel file, built in memory.
**Acceptance Criteria:**
- Output columns: URL, Status, Percent Chance, Reason (unsafe rows only).
- Any field starting with `=`, `+`, `-`, `@`, tab, or CR is prefixed with a single quote to prevent spreadsheet formula execution (CSV-injection fix) — applies to both CSV and XLSX.
- Nothing is written to disk; the buffer is streamed and discarded.
- Does not re-run detection — purely a formatting/export step over existing results.
**Dependencies:** TICKET-02 or TICKET-03 having produced results.
**Priority:** Must-have.

---

### TICKET-05 — Typosquat / Brand-Impersonation Detection
**Status:** Shipped (`core/typosquat.py`)
**Description:** Detect domains that closely resemble a known allowlisted
brand domain and surface the real domain being impersonated.
**Acceptance Criteria:**
- The verdict-deciding match requires corroborating evidence (not just short-string similarity) to avoid false positives on coincidental collisions (e.g. `redfin.com` vs `reddit.com`).
- A looser, advisory-only match (`require_corroboration=False`) is available for suggesting a "real site" link on verdicts that were already unsafe for other reasons, and never drives the verdict itself.
- `legit_domain` in the response is always a literal `config/allowlist.json` entry — never text derived from the flagged URL — so a fooled match can only redirect to the wrong *real* site, never an attacker-controlled one.
**Dependencies:** `config/allowlist.json`.
**Priority:** Must-have.

---

### TICKET-06 — ML Verdict Pipeline (Train + Serve)
**Status:** Shipped (`models/train.py`, `core/features.py`, `core/registry.py`)
**Description:** Train a versioned sklearn/XGBoost pipeline on the PhiUSIIL
dataset (plus benign-with-path augmentation) and serve it via a single
canonical feature-extraction path shared by training and serving.
**Acceptance Criteria:**
- `core/features.py` is the only place URL → feature-row logic exists — `test_feature_parity.py` fails the build if train and serve code ever compute features differently.
- Every trained model version writes a versioned artifact to `models/artifacts/` plus updates `current.json`.
- `DECISION_THRESHOLD` is defined once (`core/registry.py`) and imported everywhere it's used (serving and `models/evaluate.py`) — never redefined with a second hardcoded value.
- `test_regression_known_sites.py` (the known-benign regression set, e.g. `perplexity.ai`, `discord.com`, `india.gov.in`, `icici.bank.in`) passes before any deploy.
**Dependencies:** `dataset/PhiUSIIL_Phishing_URL_Dataset.csv`, `core/augmentation_data.py`.
**Priority:** Must-have.

---

### TICKET-07 — Browser Extension (Manifest V3)
**Status:** Shipped (`extension/`)
**Description:** A Chrome MV3 extension that checks every site visited,
before it loads, against a deployed backend.
**Acceptance Criteria:**
- Uses a background service worker (no persistent background page, MV3-compliant).
- Settings page lets the user set a backend URL (required — `localhost` only works while the developer's own machine is running).
- Unsafe verdicts show a warning page before the destination site loads.
- Warning page offers a "go to the real site" link when `legit_domain` is present in the response.
**Dependencies:** A publicly reachable backend deployment (TICKET-08).
**Priority:** Must-have.

---

### TICKET-08 — Production Deployment (Render)
**Status:** Shipped (`render.yaml`, README deploy instructions)
**Description:** One-command-ish deploy path to Render's free tier so the
extension has a real, always-reachable backend.
**Acceptance Criteria:**
- `render.yaml` auto-detected by Render, pre-filling build (`pip install -r requirements.txt`) and start (`uvicorn app.main:app --host 0.0.0.0 --port $PORT`) commands.
- `/health` returns `{"status":"ok","model_version": "..."}` once deployed.
- `PHISHING_DETECTOR_DEV_KEY` settable as an env var so the operator controls the admin key instead of hunting through platform logs for an auto-generated one.
- `APP_ENV=production` closes `/docs`/`/redoc`/`/openapi.json` and switches rate-limiting to trust Render's proxy header correctly.
**Dependencies:** GitHub repo connected to Render.
**Priority:** Must-have.

---

### TICKET-09 — Admin Model/List Hot Reload
**Status:** Shipped (`POST /api/admin/reload`, `core/auth.py`)
**Description:** Let an operator hot-swap the model and allow/blocklists
after a retrain or config edit, without restarting the server.
**Acceptance Criteria:**
- Gated by `X-Dev-Key` header, compared with `secrets.compare_digest` (constant-time).
- Failed attempts are rate-limited (20/min/client); successful requests never count against the limit.
- Rate-limit client identification trusts `X-Forwarded-For`'s last hop only when `APP_ENV=production`, never by default.
- Calls both `load_current_model.cache_clear()` and `reload_lists()` — previously neither was wired to any endpoint, so a retrain required a full manual restart.
**Dependencies:** TICKET-06 (model registry), TICKET-08 (deployment, for proxy-aware rate limiting).
**Priority:** Should-have (operator-only, not needed for public functionality).

---

### TICKET-10 — Structured, Privacy-Safe Verdict Logging
**Status:** Shipped (`app/main.py`'s `_log_verdict`)
**Description:** Log enough to debug false-positive patterns per-domain
without ever logging what a user actually typed or visited beyond its
hostname.
**Acceptance Criteria:**
- Logged fields: domain, verdict, stage, confidence — never the full URL (path/query may carry search terms, tokens, or session data).
- Applies uniformly across single-check and every bulk-check path.
**Dependencies:** None.
**Priority:** Must-have.

---

### TICKET-11 — Live Threat-Feed Integration for Block/Allowlists
**Status:** Not built (nice-to-have, PRD "deliberately not in v1")
**Description:** Replace the static `config/blocklist.json` /
`allowlist.json` seed files with a periodically-refreshed feed from a live
threat-intelligence source, without changing the `/api/admin/reload`
hot-swap contract.
**Acceptance Criteria:**
- Existing `core/lists.py` interface (`is_allowlisted`, `is_blocklisted`, `reload_lists`) unchanged for callers.
- A scheduled job or manual trigger refreshes the underlying JSON files, then calls the existing reload path.
- Falls back gracefully to the last-known-good list if a feed fetch fails (never serves an empty/corrupt list).
**Dependencies:** TICKET-09 (reload plumbing already exists).
**Priority:** Nice-to-have.

---

### TICKET-12 — Per-User Accounts & Check History
**Status:** Not built (explicitly out of scope for v1)
**Description:** Allow a signed-in user to see their own past checks.
**Acceptance Criteria:** Not yet specified — would require introducing
authentication, a real database, and row-level access rules (none of which
exist today; see Security & Access Document). Treat as a v2 candidate, not
a v1 extension.
**Dependencies:** A decision to introduce user accounts at all — currently a deliberate non-goal.
**Priority:** Nice-to-have / future consideration.
