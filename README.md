# Phishing URL Detector

A machine-learning-based system that checks whether a URL is likely
phishing or legitimate, with a simple web checker and a browser
extension that checks sites automatically.

## What's in this repo

- **`core/`** — the detection logic: feature extraction, the allowlist/
  typosquat/wordplay checks that run before the ML model, and model
  loading.
- **`app/`** — the FastAPI web app: a simple checker page, an API, and a
  developer-only bulk-checking tool.
- **`models/`** — training script and the trained model files.
- **`config/`** — allowlist/blocklist seed data.
- **`tests/`** — automated tests covering the detection logic end to end.

## How it works

Every URL passes through a few stages, in order, stopping at the first
one that makes a decision:

1. **Blocklist** — known-bad domains, instant reject
2. **Allowlist** — known-good domains, instant pass
3. **Typosquat check** — catches domains that closely resemble a known
   brand (e.g. a one-character typo of a real bank's domain)
4. **ML model** — everything else gets scored by a trained classifier

## Setup

```bash
pip install -r requirements.txt
```

## Train (optional — a trained model is already included)

```bash
python models/train.py
```

By default this expects a copy of the PhiUSIIL Phishing URL dataset (a
public dataset available on Kaggle) at a path you set inside
`models/train.py` — update `DATA_PATH` near the top of that file to
wherever you save it locally. You only need this if you want to retrain;
the repo already ships a working trained model in `models/artifacts/`.

## Serve

```bash
uvicorn app.main:app --reload --port 8000
```

Visit `http://localhost:8000/` for the checker page. Or call the API
directly:

```bash
curl -X POST http://localhost:8000/api/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/"}'
```

Returns `{checked_url, verdict, stage, confidence, model_version}`.

## Bulk checking (developer-only)

Visit `http://localhost:8000/dev/bulk`. On first use, check your terminal
output for a line like:[phishing_detector] Dev key: aB3xY...
This is auto-generated on first run and saved locally — never committed
to this repo. Paste that key into the page's "Dev key" field, then upload
a `.txt` (one URL per line) or `.csv` (with a `url` column), or paste
URLs directly. Results download as a CSV.

## Test

```bash
pytest tests/ -v
```

## Deploying (for the browser extension / public access)

The extension needs a backend reachable over the internet, not just
`localhost`. To deploy for free on [Render](https://render.com):

1. Push this repo to GitHub (already done if you're reading this on GitHub)
2. Sign up at render.com, sign in with GitHub
3. **New → Web Service** → connect this repo
4. Build command: `pip install -r requirements.txt`
5. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
6. Deploy — Render gives you a URL like `https://your-app.onrender.com`

Free tier spins down after ~15 minutes idle; the first request after
that takes 20-60 seconds to wake up, then runs normally.

## Project layout
core/features.py      URL -> feature extraction (single source of truth,
used identically by training and serving)
core/registry.py       loads the current trained model
core/lists.py           allowlist/blocklist checks
core/typosquat.py       brand-similarity / typosquat detection
core/wordplay.py        character-substitution and homoglyph detection
core/auth.py            developer-key auth for bulk checking
config/*.json           allowlist/blocklist data
models/train.py         training script
models/artifacts/       trained model files (included in this repo)
app/main.py             web app + API
tests/                  automated tests
