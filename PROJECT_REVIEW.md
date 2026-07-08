# Project Review — Phishing URL Detector

**Date:** 2026-07-08
**Scope:** Every project file reviewed — `app/`, `core/`, `models/`, `extension/`, `config/`, `tests/`, `scripts/`, root files. Findings below are ordered by severity. Items marked **[VERIFIED]** were reproduced by actually running the code, not just read.

---

## 1. Critical / High — fix these first

### 1.1 `/api/check` crashes (HTTP 500) on malformed URLs **[VERIFIED]**
- **Where:** [core/features.py:198](core/features.py#L198) (`parsed.port`), and `urllib.parse.urlparse` itself.
- **What:** These inputs raise unhandled `ValueError`, verified live:
  - `http://example.com:99999/` → `Port out of range 0-65535`
  - `http://example.com:abc/` → `Port could not be cast to integer`
  - `https://[::1/` → `Invalid IPv6 URL` (this one crashes even the blocklist stage in `core/lists.py`, before the model is reached)
- **Impact:** Any user (or the browser extension, automatically, on any weird URL it navigates to) gets a 500. Worse: in `/api/bulk-check`, **one** malformed URL in a 5,000-row batch throws inside `extract_features_batch` and fails the entire batch.
- **How to fix:** Wrap URL parsing in a guard. In `extract_features`, catch `ValueError` around `urlparse`/`parsed.port` and fall back to safe defaults (e.g. treat unparseable URLs as `has_port=0` or return a "suspicious by construction" feature row — a URL that can't parse is itself a signal). In `app/main.py`, catch parse failures per-URL and return a per-item `verdict` with a `note` like "unparseable URL" instead of 500. Add regression tests with exactly the four inputs above.
- **Effort:** ~1 hour. **Priority: highest.**

### 1.2 Extension warning page buttons do nothing **[VERIFIED by inspection]**
- **Where:** [extension/warning.html:32-33](extension/warning.html#L32-L33)
- **What:** `onclick="goBack()"` / `onclick="proceedAnyway()"` are inline event handlers. Manifest V3 extension pages run under a CSP (`script-src 'self'`) that **blocks all inline handlers**. Clicking "Go back (recommended)" or "Proceed anyway" silently does nothing — the user is trapped on the warning page.
- **How to fix:** Remove the `onclick` attributes; in `warning.js` add:
  ```js
  document.getElementById("backBtn").addEventListener("click", goBack);
  document.getElementById("proceedBtn").addEventListener("click", proceedAnyway);
  ```
  and give the buttons `id`s. (`popup.js` and `options.js` already do this correctly — only `warning.html` has the bug.)
- **Effort:** 10 minutes. **Priority: highest** (it's the user-facing safety flow).

### 1.3 `models/train.py` cannot run — dataset path is a leftover from the AI session **[VERIFIED by inspection]**
- **Where:** [models/train.py:36](models/train.py#L36) — `DATA_PATH = Path("/mnt/user-data/uploads/PhiUSIIL_Phishing_URL_Dataset.csv")`
- **What:** That's a Linux path from the Claude environment that generated this file. The dataset actually lives in this repo at `dataset/PhiUSIIL_Phishing_URL_Dataset.csv`. Training is currently broken on this machine, and the README papers over it ("update DATA_PATH … inside the file").
- **How to fix:** `DATA_PATH = ROOT / "dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"`, overridable via env var or `argparse`. Same pattern the rest of the codebase already preaches (paths derived from file location, never hardcoded absolute).
- **Effort:** 5 minutes.

### 1.4 The extension sends your entire browsing history to a third-party server
- **Where:** [extension/background.js:90-121](extension/background.js#L90-L121)
- **What:** Every top-level navigation — **full URL, including query strings** (which routinely contain search terms, session tokens, password-reset links, document IDs) — is POSTed to the Render backend. This is a significant privacy exposure and would fail Chrome Web Store review without a prominent disclosure and privacy policy.
- **How to fix (in order of increasing effort):**
  1. Strip query string and fragment before sending (`url.origin + url.pathname`) — the model's path features still work, query features are lost for the extension path only.
  2. Better: ship the allowlist + a Bloom filter of popular domains inside the extension and only call the backend for domains that miss it (most browsing is top-1000 sites — this eliminates ~95% of calls).
  3. Document the data flow in the extension description and add a privacy policy.
- **Effort:** option 1 is ~15 minutes; option 2 is a half-day. **Do at least option 1 before distributing the extension.**

---

## 2. Medium — real bugs and mechanism problems

### 2.1 Allowlist/blocklist JSON re-read from disk on every request **[VERIFIED]**
- **Where:** [core/lists.py:43](core/lists.py#L43) — `@lru_cache(maxsize=1)` on `_load(name)`.
- **What:** `maxsize=1` with two distinct keys (`"allowlist"`, `"blocklist"`) means each call evicts the other. Measured: after two full check cycles, `CacheInfo(hits=0, misses=4)` — zero cache hits, ever. Every URL check does 2+ file reads and JSON parses (typosquat adds a third).
- **How to fix:** `@lru_cache(maxsize=None)`. `reload_lists()` still works unchanged.
- **Effort:** 1 minute. Meaningful latency win on bulk checks.

### 2.2 List matching is O(n) linear scan per URL
- **Where:** [core/lists.py:58-65](core/lists.py#L58-L65) — `any(_host_matches_entry(host, e) for e in domain_set)`.
- **What:** The `_domain_set` set is built and then… iterated linearly anyway. Fine at 80 entries, but the file's own comment says production should sync the **Tranco Top 1M** — at which point every check is a million-iteration scan, and typosquat (which loops all protected domains with an O(len²) edit-distance DP each) becomes seconds per URL.
- **How to fix:** For exact + subdomain matching, walk the host's own suffixes instead: split `host` on dots and check each suffix (`en.wikipedia.org` → check `en.wikipedia.org`, `wikipedia.org`, `org`) against the set — O(#labels) regardless of list size. For typosquat at scale, keep a *separate, small* protected-brands list (top ~500) instead of reusing a 1M-entry allowlist.
- **Effort:** ~1 hour now; saves a rewrite later.

### 2.3 Rate limiter: unbounded memory + broken behind a proxy
- **Where:** [core/auth.py:36-50](core/auth.py#L36-L50)
- **What:** Two issues. (a) `_request_log` is a `defaultdict` keyed by client IP that **never deletes keys** — a scanner cycling spoofed/rotating IPs grows it forever (slow memory leak on a long-lived deployment). (b) On Render (the documented deployment target!) the app sits behind a proxy, so `request.client.host` is the proxy's IP — every client shares one bucket, meaning 20 req/min *total* for all users of the dev endpoints, and an attacker can lock the real developer out (denial of service on the dev tooling). Also note the limit counts *successful* requests too, so a legitimate bulk-scripting session hits 429 after 20 calls/min.
- **How to fix:** (a) periodically drop empty deques (e.g. when `len(_request_log) > 10_000`, purge stale entries). (b) Read `X-Forwarded-For` (first hop) when a trusted-proxy env flag is set, or run uvicorn with `--proxy-headers` and trust `request.client` after that. (c) Consider rate-limiting only *failed* auth attempts.
- **Effort:** 1–2 hours.

### 2.4 XSS via `innerHTML` on the dev bulk page (and self-XSS on the index page)
- **Where:** [app/main.py:492-505](app/main.py#L492-L505) (`_BULK_HTML`'s `renderResults` builds table rows with raw `${r.checked_url}` / `${r.note}` into `innerHTML`); [app/main.py:396-402](app/main.py#L396-L402) (index page, same pattern).
- **What:** A URL is attacker-controlled text. A developer who uploads a URL list from an untrusted source (which is *exactly* the use case — checking suspicious URLs!) with an entry like `https://example.com/<img src=x onerror=alert(document.cookie)>` gets script execution on the dev page — where the dev key sits in `sessionStorage`. The public index page has the same pattern (self-XSS, lower risk). The extension's `popup.js:11-15` also injects `result.note` via `innerHTML` (backend-controlled; low today, but one compromised backend away from XSS in the extension).
- **How to fix:** Build rows with `document.createElement` + `textContent`, or escape HTML before interpolation. Same one-liner escape helper everywhere.
- **Effort:** ~1 hour across the three spots.

### 2.5 Extension URL cache grows without bound
- **Where:** [extension/background.js:41-52](extension/background.js#L41-L52)
- **What:** `urlCache` in `chrome.storage.session` accumulates one entry per distinct URL visited, TTL-checked on read but **never evicted**. `storage.session` has a ~10 MB quota; heavy browsing eventually makes `chrome.storage.session.set` start throwing, which then breaks caching (and every navigation silently re-fetches). Same for `tempAllow`. There's also a read-modify-write race: two simultaneous navigations can drop each other's cache writes (harmless but worth knowing).
- **How to fix:** On each `setCacheEntry`, prune expired entries; cap the map (e.g. 500 entries, drop oldest). 10 lines.
- **Effort:** 30 minutes.

### 2.6 Model hot-swap doesn't exist despite the docstrings saying so
- **Where:** [core/registry.py:31-35](core/registry.py#L31-L35), [core/lists.py:51-56](core/lists.py#L51-L56)
- **What:** Both caches advertise "call `cache_clear()` after retraining/refresh" — but nothing ever calls them, and there's no admin endpoint to do so. After retraining or editing `config/*.json`, the running server keeps serving the old model/lists until restarted. The mechanism is documented but not wired up.
- **How to fix:** Add a dev-key-gated `POST /api/admin/reload` that calls `load_current_model.cache_clear()` and `reload_lists()`. Also: `load_current_model` doesn't check `metadata_file` existence before reading it (only preprocessor/xgb) → a half-written `current.json` yields `FileNotFoundError` → 500 instead of the intended 503.
- **Effort:** ~1 hour.

### 2.7 Hard-coded 0.5 decision threshold, duplicated in two places
- **Where:** [app/main.py:163](app/main.py#L163) and [app/main.py:203](app/main.py#L203)
- **What:** The safe/unsafe cutoff is a magic `0.5` written twice (single + bulk path — exactly the "two paths silently diverge" failure mode the codebase lectures about elsewhere). For a security product, false negatives and false positives have asymmetric costs; 0.5 is almost never the right operating point, and there's no "uncertain" band — a 50.1% score renders the same red UNSAFE as 99.9%.
- **How to fix:** One module-level constant (or in model metadata, chosen from the validation PR curve at a target precision). Consider a three-way verdict (`safe` / `suspicious` / `unsafe`) surfaced in the UI and extension.
- **Effort:** constant extraction: 15 min. Threshold tuning + uncertain band: half a day.

---

## 3. Model / ML issues

### 3.1 Reported metrics are inflated — test set is PhiUSIIL-only
- **Where:** [models/train.py:100-149](models/train.py#L100-L149)
- **What:** The code itself documents that PhiUSIIL's legitimate class is 100% bare homepages with `www.` artifacts — i.e. the test split has the *same* distribution artifacts the training worked around. The ROC-AUC in the metadata measures performance on an artifact-laden distribution, not real traffic. Meanwhile the augmentation sets (the URLs shaped like real-world traffic) go **only** into training — so the model is never *scored* on the distribution it was patched to handle. The 100K-URL evaluation mentioned in comments lives outside the repo entirely.
- **How to fix:** Build a held-out evaluation set that never touches training: a slice of the augmentation-style benign URLs (path-bearing real pages) + fresh phishing URLs (e.g. a PhishTank snapshot from a *later date* than training data). Report metrics on both PhiUSIIL-test and this "realistic" set in the metadata. Add the evaluation harness as a script (`models/evaluate.py`) so it's reproducible instead of anecdotal.
- **Effort:** half a day; this is the single highest-value ML improvement.

### 3.2 Synthetic wordplay data risks teaching the model template artifacts
- **Where:** [core/wordplay_training_data.py:61-77](core/wordplay_training_data.py#L61-L77)
- **What:** All synthetic phishing URLs come from ~4 fixed f-string templates (`{variant}-portal.{tld}/`, `user-{variant}.{tld}/index.php`, …), each replicated 8×. A tree ensemble can memorize the template shape (e.g. `-portal.` + `.tk`) instead of the substitution technique — the same memorization failure mode `augmentation_data.py`'s docstring describes for v1. There's also a subtle bug: `random.seed(42)` at *module import* means generated data depends on import order/how many times generators are called before training — call the seed inside each generator for true reproducibility.
- **How to fix:** Diversify templates (10–20 structural shapes), vary path depth/parameters, and — more robustly — verify the *features* carry the signal by checking feature importances: if `num_confusable_chars`/`has_mixed_script` have near-zero gain, the synthetic data isn't teaching what you think.
- **Effort:** 2–3 hours.

### 3.3 Case-sensitivity inconsistency in feature extraction
- **Where:** [core/features.py:123](core/features.py#L123) — `url.replace(host, norm_host, 1)`
- **What:** `urlparse().hostname` is lowercased, but the raw `url` isn't — for `HTTP://WWW.GOOGLE.COM`, `replace` finds nothing, so the `www.` stripping silently doesn't happen and count-based features differ from the lowercase form of the same URL. Two byte-different but semantically identical URLs get different feature vectors — precisely what the `count_basis_url` machinery exists to prevent.
- **How to fix:** Lowercase scheme+host before all count logic (path/query case can legitimately stay), or do the replace on a case-normalized copy.
- **Effort:** 30 min + a parity test (`extract_features(u) == extract_features(u_uppercased_host)`).

### 3.4 Typosquat check 3 (homoglyph exact-match) is unreachable for short brands
- **Where:** [core/typosquat.py:193-216](core/typosquat.py#L193-L216)
- **What:** For protected cores of length ≤ 4 (`jio`, `x`… well, ≥3 required, so `jio`, `sbi`, `nih`, `irs`, `ajio`), the `continue` statements inside Check 2 skip straight to the next protected domain, so Check 3 (leetspeak/homoglyph normalized exact match) never runs for them. `s81.co.in` (leet for `sbi`) with distance 2 would be missed even though `normalize_confusables` would catch it. Same for the `abs(len diff) > 1` branch.
- **How to fix:** Move Check 3 *before* Check 2, or restructure so `continue` only skips the fuzzy branch.
- **Effort:** 30 min + tests.

### 3.5 Threshold/feature-list drift risks
- `COMMON_TLDS` and `SUSPICIOUS_PATH_KEYWORDS` are code constants ([core/features.py:44-56](core/features.py#L44-L56)); the model metadata itself lists "expand via config, not by editing code" as a known limitation — but changing them silently invalidates a trained model (feature semantics shift under a frozen model). If moved to config, version them and record the hash in model metadata so serve-time can refuse a mismatched combination.

---

## 4. Security (beyond the XSS above)

| # | Issue | Where | Severity |
|---|---|---|---|
| 4.1 | CORS `allow_origins=["*"]` + `allow_headers=["*"]` also covers dev endpoints — any website the developer visits can call `/api/bulk-check` from their browser (needs the key, but combined with 2.4's XSS the key is stealable). Restrict CORS on dev routes, or move the wildcard CORS to `/api/check` only. | [app/main.py:77-82](app/main.py#L77-L82) | Medium |
| 4.2 | Dev key printed to stdout — on Render, stdout goes to platform logs, retained and visible to anyone with dashboard access. Print the path only, not the key value. | [core/auth.py:67](core/auth.py#L67) | Low-Med |
| 4.3 | `/health` publicly leaks model version string. Harmless-ish; consider gating detail. | [app/main.py:138-144](app/main.py#L138-L144) | Low |
| 4.4 | `bulk_check_file` trusts the filename extension to pick CSV vs TXT parsing — a `.csv` with weird quoting can smuggle rows; harmless here but validate/normalize. | [app/main.py:272](app/main.py#L272) | Low |
| 4.5 | Warning page is `web_accessible_resources` for `<all_urls>` — any website can detect the extension is installed (fingerprinting) and can navigate users to a *fake-looking* warning with attacker-chosen `url`/`note` params. Tighten: remove it from web-accessible (the extension navigates to it itself via `chrome.tabs.update`, which doesn't require web-accessibility) | [extension/manifest.json:27-32](extension/manifest.json#L27-L32) | Medium |
| 4.6 | Fail-open design in the extension (backend down → no protection) is a documented tradeoff, but combined with a free-tier backend that sleeps after 15 min idle, the extension is effectively *off* most of the time for a casual user. At minimum, keep-alive ping or bundle the blocklist locally. | [extension/background.js:114-120](extension/background.js#L114-L120) | Design |

---

## 5. Flow / repo hygiene

1. **Untracked work at risk:** `git status` shows `dataset/` and `extension/` entirely untracked. The whole browser extension — a major component — is not committed. One bad `git clean` and it's gone. Commit `extension/`; add `dataset/` to `.gitignore` (the PhiUSIIL CSV is large and redistributable from Kaggle; keep `dataset_small.csv` if tests need it).
2. **Dangling references:** Code comments cite `AUDIT_NOTES.md`, `SECURITY_ASSESSMENT.md`, `MODEL_EVALUATION.md` in ~15 places, but those files were removed from the repo (commit "Remove internal docs") and are gitignored. Every reference is now a dead link for any collaborator. Either restore sanitized versions or trim the references to be self-contained.
3. **Artifact accumulation:** `models/artifacts/` has 4 model generations committed (incl. one orphaned `.joblib` from the old single-blob format). Keep only the current generation in git, or use Git LFS / releases.
4. **`requirements.txt`** mixes runtime and dev deps (`pytest` ships to production). Split `requirements.txt` / `requirements-dev.txt`. Also nothing pins the Python version (`.pcy` files say 3.14) — add `runtime.txt`/README note; Render defaults may differ.
5. **No CI:** the tests are good (real regression tests with history behind them) but nothing runs them automatically. A 20-line GitHub Actions workflow (`pytest` on push) makes the "run it in CI on every PR" comments in `tests/test_regression_known_sites.py` true.
6. **`scripts/package_release.sh` excludes less than `.gitignore` does** — it doesn't exclude `venv/`, `config/dev_key.txt`, `dataset/`, or `.env`, so a release tarball built from a working directory **ships the secret dev key, the venv, and the 100MB dataset**. Build releases from `git archive` instead, which respects tracked files only.
7. **HTML embedded in Python strings** (`_INDEX_HTML`, `_BULK_HTML`, ~250 lines): move to `templates/`/`static/` files served by FastAPI — editable, lintable, and syntax-highlighted.
8. **No logging**: the app has zero logging (only `print` in auth). Add structured logging of verdicts/stages (not full URLs, for privacy) so you can debug false-positive reports.

---

## 6. Prioritized action plan

| Priority | Items | Effort | Impact |
|---|---|---|---|
| **P0 — broken now** | 1.1 malformed-URL 500s · 1.2 dead warning buttons · 1.3 train.py path · 5.1 commit extension/ | ~½ day | Restores correctness of core flows |
| **P1 — before anyone else uses it** | 1.4 privacy (strip queries) · 2.4 XSS escaping · 4.5 web_accessible · 5.6 release script leaks key · 2.1 cache thrash | ~1 day | Security & privacy baseline |
| **P2 — robustness** | 2.3 rate limiter · 2.5 extension cache · 2.6 reload endpoint · 2.7 threshold constant · 3.3 case bug · 3.4 check-3 order | ~1–2 days | Fewer production surprises |
| **P3 — model quality** | 3.1 realistic eval set · 3.2 synthetic-data diversity · 3.5 config versioning · 2.2 scalable matching | ~2–3 days | Trustworthy metrics, scales to real lists |
| **P4 — hygiene** | 5.2–5.5, 5.7, 5.8, CI, logging | ~1 day | Maintainability |

---

## 7. Copy-paste prompt for the next AI session

Use this as the opening prompt when you ask Claude (or any AI) to do the improvement work. It encodes the context an AI otherwise has to rediscover, and forces the working style that avoids regressions:

```
You are working on my phishing-URL-detector project (FastAPI backend +
XGBoost model + Chrome MV3 extension). Before changing anything, read
PROJECT_REVIEW.md in the repo root — it is a verified findings document;
treat its file:line references as ground truth and its priority table
(section 6) as the work order.

Project invariants you must never break:
1. core/features.py is the single source of truth for feature extraction —
   training and serving must call the same function. Never duplicate
   feature logic.
2. Changing any feature semantics (COMMON_TLDS, keyword lists, count
   normalization) invalidates the trained model in models/artifacts/ —
   if you change them, say so explicitly and note that retraining is
   required; do not silently ship a mismatched model.
3. The API surface (/api/check request/response shape) is consumed by the
   browser extension in extension/ — keep it backward compatible.
4. The extension is Manifest V3: no inline scripts/handlers, no blocking
   webRequest, service-worker background only.
5. tests/ contains regression tests tied to real past bugs — they must
   all pass after every change. Run: venv/Scripts/python.exe -m pytest tests/ -v
   (Windows machine; use the project venv, not system Python.)

Working style:
- Work through PROJECT_REVIEW.md section 6 in priority order, P0 first.
  One priority tier per session/PR-sized change set; don't mix tiers.
- For every bug fix, FIRST write a failing test that reproduces it
  (e.g. POST /api/check with "http://example.com:99999/" must not 500),
  THEN fix, then show the test passing.
- After each change, run the full test suite and report actual output.
  If something fails, say so — do not summarize failures as successes.
- Do not refactor code unrelated to the finding you are fixing.
- Do not add new dependencies without stating why and asking first.
- When a fix has options (e.g. privacy: strip query strings vs local
  bloom filter), implement the option marked as recommended in the
  review, and note the deferred alternative in a TODO.
- If you discover a NEW bug while working, add it to PROJECT_REVIEW.md
  under the right section instead of silently fixing it.

Start with P0: (1) make extract_features and both API endpoints immune to
malformed URLs (ValueError from urlparse/port — see review 1.1, with the
four exact reproduction inputs), (2) fix the dead inline onclick handlers
in extension/warning.html (review 1.2), (3) point models/train.py
DATA_PATH at dataset/PhiUSIIL_Phishing_URL_Dataset.csv relative to the
repo root (review 1.3). Show me the diff and test results before moving on.
```

**Why this prompt works:** it front-loads the invariants an AI can't infer quickly (feature parity, model-invalidating changes, MV3 constraints, Windows venv), forces test-first fixes so regressions are caught, forbids the two classic AI failure modes (drive-by refactoring, mixing unrelated changes), and scopes each session to one priority tier so context stays coherent.
