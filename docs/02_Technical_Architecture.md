# Technical Architecture Document — Phishing URL Detector

## Tech Stack

| Layer | Choice | Version | Reasoning |
|---|---|---|---|
| Backend framework | FastAPI | 0.139.0 | Async-capable Python framework with automatic request validation (Pydantic) and OpenAPI docs; matches the project's need for a small, fast, typed API surface. |
| ASGI server | Uvicorn (`[standard]`) | 0.50.2 | Standard production ASGI server for FastAPI; `[standard]` extras add performance (uvloop/httptools) where the host platform supports them. |
| Data validation | Pydantic | 2.13.4 | Request/response models (`CheckRequest`, `CheckResponse`, etc.) get free validation, serialization, and OpenAPI schema generation. |
| File upload parsing | python-multipart | 0.0.32 | Required by FastAPI for `UploadFile`/`File(...)` handling (bulk-check-upload). |
| ML model | XGBoost | 3.3.0 | Gradient-boosted trees, good accuracy/speed tradeoff on tabular URL-structure features, wrapped inside a scikit-learn `Pipeline`. |
| ML pipeline/preprocessing | scikit-learn | 1.8.0 | Provides the `Pipeline` abstraction that bundles preprocessing + the XGBoost estimator into one artifact loaded at serve time. |
| Data handling | pandas | 3.0.2 | Batches feature rows for both training and serving (`extract_features_batch`); also builds bulk-check CSV/XLSX exports. |
| Numerics | numpy, scipy | 2.4.4 / 1.17.1 | Underlying array/math support for scikit-learn and feature computation. |
| Model persistence | joblib | 1.5.3 | Serializes/deserializes the versioned pipeline artifact in `models/artifacts/`. |
| Excel export | openpyxl | 3.1.5 | Writes `.xlsx` bulk-check exports in memory. |
| Frontend | Static HTML/CSS/JS (`app/static/index.html`) | — | No frontend framework/build step; FastAPI serves the file directly. Keeps the deploy surface to a single Python service. |
| Browser extension | Chrome Manifest V3 | manifest v3, extension v1.0.0 | Required format for current Chrome Web Store submissions; uses a background service worker (`background.js`) plus a popup/options page, matching Google's MV3 requirements (no persistent background pages). |
| Hosting | Render (free tier), `render.yaml` blueprint | — | Zero-cost hosting with GitHub-integrated auto-deploy; documented tradeoff is free-tier spin-down after ~15 min idle. |
| Dataset | PhiUSIIL Phishing URL Dataset | `dataset/PhiUSIIL_Phishing_URL_Dataset.csv` | Public labeled phishing/legitimate URL dataset used as the training source, overridable via `PHISHING_DETECTOR_DATASET`. |
| Python version pin | see `runtime.txt` | — | Pins the interpreter version Render provisions, so training/serving behavior doesn't drift across deploys. |
| CI | GitHub Actions (`.github/workflows/`) | — | Runs `pytest` on every push/PR; `test_regression_known_sites.py` is the deploy-blocking gate. |

## File & Folder Structure

```
app/
  main.py            FastAPI serving layer + all API endpoints
  static/
    index.html        the entire frontend (HTML/CSS/JS, no build step)
core/
  features.py         single source of truth for URL -> ML features
                       (imported by BOTH training and serving — see
                       test_feature_parity.py, which guards against
                       train/serve logic ever forking apart)
  registry.py          versioned model loading, absolute paths only,
                        exposes DECISION_THRESHOLD
  lists.py              allowlist/blocklist lookups, config-driven,
                         reload_lists() + cache_clear() for hot-swap
  typosquat.py           brand-similarity detection (edit-distance style
                          matching against config/allowlist.json entries)
  wordplay.py             general character-substitution/homoglyph
                           detection (e.g. rn -> m, 0 -> o)
  wordplay_training_data.py   synthetic training data generation for
                               the wordplay/typosquat detectors
  augmentation_data.py    benign-with-path URL augmentation for the
                           training split (see its module docstring)
  auth.py                  dev-key auth + rate limiting for
                            /api/admin/reload only
config/
  allowlist.json          seed list of known-good domains
  blocklist.json          seed list of known-bad domains
  dev_key.txt              auto-generated, gitignored dev key
                            (never committed)
dataset/
  PhiUSIIL_Phishing_URL_Dataset.csv   raw training data (or path set via
                                        PHISHING_DETECTOR_DATASET)
models/
  train.py               training script: features -> augmentation ->
                          Pipeline.fit -> versioned artifact
  evaluate.py              realistic held-out evaluation harness
  artifacts/                versioned model + metadata, COMMITTED to
                             git (Render serves from here without
                             retraining; prune stale generations before
                             each commit)
extension/
  manifest.json            Manifest V3 config
  background.js             service worker: intercepts navigation,
                             calls the backend
  popup.html / options.html   UI for manual check + backend URL setting
  icons/                    extension icons (16/32/48/128)
  README.md                 what each file does, how to load unpacked
tests/
  test_regression_known_sites.py   CI deploy gate — known-benign sites
                                    that a prior version misclassified
  test_feature_parity.py           train/serve feature-extraction parity
  test_api_edge_cases.py, test_bulk_check.py,
  test_malformed_urls.py, test_security_fixes.py,
  test_p1..p4_fixes.py, test_wordplay.py,
  test_frontend_regressions.py, test_extension_popup_bugs.py
scripts/                  one-off/maintenance scripts
.github/workflows/        CI: pytest on every push/PR
requirements.txt          runtime-only dependencies (what's deployed)
requirements-dev.txt      adds test tooling (pulls in requirements.txt)
runtime.txt                pins the Python version
render.yaml                Render deploy blueprint
PROJECT_UPGRADE_REPORT.md  changelog of the 2026-07 audit-and-upgrade pass
README.md                  run/train/serve/test instructions
```

## Database Schema

This project has **no traditional database**. State is file-based by design
(single-operator tool, not a multi-tenant SaaS):

| "Table" (file) | Fields | Notes |
|---|---|---|
| `config/allowlist.json` | list of known-good domain strings | Loaded into memory via `core/lists.py`; hot-reloadable via `/api/admin/reload` without a restart. |
| `config/blocklist.json` | list of known-bad domain strings | Same loading/reload behavior as allowlist. |
| `config/dev_key.txt` | single secret string | Auto-generated on first run if absent; gitignored. Not a table — one shared secret, not per-user credentials. |
| `models/artifacts/<version>/` | serialized sklearn `Pipeline` (joblib) + metadata JSON (`version`, training info) | `current.json` at the artifacts root points to the active version. Versioned so a bad retrain can be rolled back by repointing `current.json`. |
| In-memory rate-limit table (`core/auth.py`'s `_request_log`) | `client_id -> deque[timestamps]` | Not persisted — sliding-window rate limiting for failed `/api/admin/reload` auth attempts only. Reset on process restart. Explicitly single-instance; a multi-instance deployment would need a shared store (e.g. Redis) instead. |

No user accounts, sessions, or PII are stored anywhere. Logging
(`app/main.py`'s `_log_verdict`) intentionally records only `domain +
verdict + stage + confidence` — never the full URL — so path/query
components that could carry search terms, tokens, or session data are never
persisted, even in logs.

## Environment & Config Notes

| Variable | Purpose | Required? | Notes |
|---|---|---|---|
| `PHISHING_DETECTOR_DEV_KEY` | Sets a known dev key for `/api/admin/reload`, instead of an auto-generated one | Optional | Recommended for deployed environments (Render) so you don't have to dig through platform logs for an auto-generated key each deploy. Checked before falling back to `config/dev_key.txt`. |
| `APP_ENV` | Set to `production` to (a) disable `/docs`, `/redoc`, `/openapi.json`, and (b) trust `X-Forwarded-For` for rate-limit client identification | Recommended for prod | Defaults to `development` (docs open, proxy headers NOT trusted — trusting them by default off-Render would let a client spoof its own rate-limit bucket). |
| `PHISHING_DETECTOR_DATASET` | Overrides the path to the training CSV | Optional | Defaults to `dataset/PhiUSIIL_Phishing_URL_Dataset.csv`. |

**Never hardcode:** the dev key (always via env var or auto-generated file,
never in source), and never log full URLs (domain-only, per `_log_verdict`).
`config/dev_key.txt` is gitignored — verify it's never accidentally
committed before pushing.

**Deploy-specific:** `models/artifacts/` is committed to git (unusual for a
model artifact, but deliberate — Render's free tier has no persistent volume
across deploys and this project doesn't want to require a retrain step on
every deploy). Prune stale artifact generations before committing to avoid
repo bloat.
