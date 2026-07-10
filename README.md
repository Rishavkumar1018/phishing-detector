# Phishing URL Detector v2

Rebuilt from a technical audit of a prior version, then hardened against
an independent red-team security assessment and a 100,000-URL model
evaluation (both non-destructive, both run via Claude Code). The full
findings writeups live in private audit notes kept outside this repo;
`PROJECT_UPGRADE_REPORT.md` (in this repo) documents the most recent
audit-and-upgrade pass. This README is just "how do I run it."

## Bulk checking (public, no auth)

From the homepage, click the **+** next to the search bar for two ways to
check multiple URLs at once — no login or key required:

- **Bulk paste**: paste URLs (one per line, or comma-separated) into the
  textarea and click Check. Capped at 50 URLs per request; results show
  directly on the page as a table.
- **Upload file**: upload a `.txt` or `.csv` file (under 2MB). URLs are
  extracted from anywhere in the file's content — not assumed to be in
  any particular column — deduplicated, and capped at 75 per file. The
  file is read straight from the upload stream into memory and never
  written to disk; nothing about it persists after the response is sent.
  Once results are ready, download them as CSV or Excel (`.xlsx`),
  generated in memory on demand.

Both flows reuse the exact same detection pipeline as the single-URL
checker (`POST /api/check`) — see `app/main.py`'s `_bulk_check()` — so
results never drift between single and bulk checks. The underlying
endpoints (`POST /api/bulk-check-paste`, `POST /api/bulk-check-upload`,
`POST /api/bulk-check-export`) are scriptable directly too:

```bash
curl -X POST http://localhost:8000/api/bulk-check-paste \
  -H "Content-Type: application/json" \
  -d '{"text": "https://example.com/\nhttps://sbl.co.in/"}'
```

`POST /api/admin/reload` remains developer-only, gated by the same
auto-generated `X-Dev-Key` (see `config/dev_key.txt`, gitignored) as
before — it hot-swaps the model/lists after a retrain without a restart.

## Browser extension (auto-checks every site you visit)

The `extension/` folder is a Manifest V3 Chrome extension that checks every
site you navigate to, automatically, before it loads — see
`extension/README.md` for what each file does and how to load it.

**It needs a backend it can reach over the internet** (not `localhost` —
that only works while your PC is on and the server running). Deploy to
Render's free tier:

1. **Push this project to GitHub** (if you haven't already):
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   ```
   Create a new repo on github.com, then follow its "push an existing
   repository" instructions to connect and push.

2. **Sign up at [render.com](https://render.com)** (free, no credit card needed for the free tier) — sign in with GitHub for the easiest setup.

3. **New → Web Service** → connect your GitHub repo. Render should
   auto-detect the `render.yaml` in this project and pre-fill the build/start
   commands. If not, set them manually:
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

4. **(Optional) Set an environment variable** `PHISHING_DETECTOR_DEV_KEY` to
   a password of your choice, so `/api/admin/reload` works on the deployed
   version with a key you control (otherwise one gets auto-generated per
   deploy and printed in Render's logs, which is less convenient to find
   repeatedly). Bulk checking itself is public and needs no key.

5. **Deploy.** Render gives you a URL like `https://phishing-detector-xyz.onrender.com`.
   Free tier spins down after ~15 min idle — the first request after that
   can take 20-60 seconds while it wakes back up; after that it's normal speed.

6. **Test it**: visit `https://your-url.onrender.com/health` in a browser —
   should show `{"status":"ok","model_version":"..."}`.

7. **Point the extension at it**: load the extension (see
   `extension/README.md`), open its Settings, paste your Render URL into
   "Backend URL", save.

## Setup

```bash
pip install -r requirements.txt
```

`requirements.txt` is runtime-only (what the deployed app needs to serve
traffic). For local development, also install the test tooling:

```bash
pip install -r requirements-dev.txt
```

(this pulls in `requirements.txt` too, so one command covers both.)

## Train

```bash
python models/train.py
```

Reads PhiUSIIL's raw URLs from `dataset/PhiUSIIL_Phishing_URL_Dataset.csv`
(override the location with the `PHISHING_DETECTOR_DATASET` env var),
extracts features via `core/features.py` (the single canonical
implementation), augments the training split with real benign-with-path
URLs (see `core/augmentation_data.py`'s module docstring), fits one
bundled sklearn Pipeline, and writes a versioned artifact to
`models/artifacts/` plus a `current.json` pointer.

## Serve

```bash
uvicorn app.main:app --reload --port 8000
```

Visit `http://localhost:8000/`. `POST /api/check {"url": "..."}` returns
`{checked_url, status, verdict, stage, confidence, model_version}` —
`status` is `"ok"` or `"invalid"` (non-URL input; `verdict` is null and a
user-facing `message` explains why).

## Test

```bash
pytest tests/ -v
```

`test_regression_known_sites.py` is the CI gate — it includes the exact
URLs that were wrong in the legacy system (`perplexity.ai`, `discord.com`,
`india.gov.in`, `icici.bank.in`) plus more known-benign sites and synthetic
suspicious-structure cases. A failure here should block deploy.
`test_feature_parity.py` guards against training and serving code ever
forking apart again.

## Project layout

```
core/features.py       single source of truth for URL -> features
core/registry.py        versioned model loading, absolute paths only
core/lists.py            allowlist/blocklist, config-driven
core/typosquat.py        brand-similarity detection (e.g. sbl.co.in vs sbi.co.in)
core/wordplay.py          general character-substitution/homoglyph detection
core/wordplay_training_data.py   synthetic training data for the above
core/auth.py             dev-key auth for /api/admin/reload (bulk checking is public)
config/*.json            seed lists (replace with live feeds in prod)
models/train.py          training script
models/evaluate.py        realistic held-out evaluation (see its docstring)
models/artifacts/        versioned model + metadata - committed to git
                          (Render needs these to serve without retraining;
                          check this folder before each commit and remove
                          stale generations)
app/main.py               FastAPI serving layer + API
app/static/                the actual HTML/CSS/JS the app serves
extension/                 the browser extension (Manifest V3)
tests/                    regression + parity tests
.github/workflows/         CI - runs pytest on every push/PR
requirements.txt           runtime dependencies only
requirements-dev.txt       adds test tooling for local development
runtime.txt                pins the Python version
render.yaml                Render deploy blueprint (build/start commands, env vars)
PROJECT_UPGRADE_REPORT.md  changelog of the 2026-07 audit-and-upgrade pass
```
