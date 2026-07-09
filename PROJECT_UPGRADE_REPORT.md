# Project Upgrade Report — 2026-07-09

Full audit-and-upgrade pass over the LexSentinel phishing detector
(backend + frontend + extension + ML model), executed phase by phase per
`UPGRADE_PLAN.md`. Rollback points: every phase is its own commit;
the pre-audit state is commit `b7a14de`.

**Context established up front:** this repo is *v2* — already rebuilt
once from a prior audit (the plan's references to Flask and to "the
model comparison logic" predate that rebuild; the backend is FastAPI and
the previously reported `india.gov.in` false positive was already fixed
and regression-tested). This pass audited the *current* code fresh
rather than re-running stale instructions, and found that the newest,
least-reviewed code (the recent frontend redesign) held most of the new
bugs.

Test suite: **91 passed at baseline → 131 passed at finish** (40 new
tests). Every phase ended with a full green run.

---

## Phase 1 — Bugs found and fixed (commit `e5f520c`)

Every issue was verified live before fixing, and has a dedicated
regression test after.

| # | File/component | Before | After | Why it mattered |
|---|---|---|---|---|
| 1 | `core/typosquat.py` | Subdomain-prefix check ran before the short-core guard and trusted any exact prefix-label match | Short cores (`id`, `x`) never match; generic cores (`usa`, `outlook`, `office`, `zoom`) require corroboration (lure word in path *or another host label*, or unusual TLD) | **Confirmed false positives on major real sites**: `outlook.live.com` (Microsoft's webmail), `id.atlassian.com` (Atlassian login), `usa.philips.com`, `zoom.cisco.com` — the extension redirected all of them to the phishing warning. Attacks still caught: `irs.mynewsblog.net`, `outlook.secure-signin.com`, `usa.tax-refund.top` |
| 2 | `app/static/bulk.html` | `split('\\n')` — splits on a literal backslash-n | `split(/\r?\n/)` | Pasted URLs were never split; the whole textarea went to the backend as one giant "URL". The paste feature was completely broken |
| 3 | `extension/popup.js` | `result.verdict.toUpperCase()` on a null verdict | Dedicated "Can't check" state for `status:"invalid"` | Popup crashed mid-render (red border, stale badge) when checking localhost/intranet pages |
| 4 | `app/main.py` `/api/bulk-check` | No URL validation (single-check path had it) | Same `is_valid_url` pre-filter; invalid rows get `status:"invalid"`, a summary count, and a CSV `status` column | Garbage lines in uploaded files received confident safe/unsafe verdicts — exactly the single-vs-bulk drift `_decide_stage1`'s docstring promises can't happen |
| 5 | `core/auth.py` | Rate-limit client ID = **first** X-Forwarded-For entry (client-supplied) | **Last** entry (appended by the platform proxy) | An attacker could rotate fake IPs to bypass the rate limit, or spoof the developer's IP to lock them out — the exact attack the code's own comment claimed to prevent |
| 6 | `app/static/index.html` | Enter key did nothing (no form, no handler) | keydown handler submits | Basic UX expectation for a single-field checker |
| 7 | `app/static/index.html` | `res.ok` never checked; 422/429/503 "worked" via an accidental TypeError landing in `catch` | Explicit non-2xx branch showing the server's `detail` message | Deliberate error handling instead of a coincidence |
| 8 | `models/train.py` | `open(..., "w")` without encoding for metadata/current.json | `encoding="utf-8"` | The exact bug class commit `e5df692` ("explicit UTF-8 on all file reads/writes") fixed everywhere else — these two writes were missed |
| 9 | `extension/options.js` | Any string saved as backend URL | Validates http(s) URL before saving, shows error | A typo silently broke every future check (fail-open "?" badge with no hint why) |
| 10 | `app/static/bulk.html` | Renderer assumed verdict is never null | INVALID row state, null-safe stage/note cells | Required by fix #4; previously crashed the results table |
| 11 | `README.md` / `render.yaml` | README promised a `render.yaml` that didn't exist; stale `/mnt/user-data/uploads/` training path; told readers to read a file not in the repo; outdated API response shape | `render.yaml` created (build/start commands, `PYTHON_VERSION`, `APP_ENV=production`); all references corrected | Deploy instructions were unfollowable as written |

## Phase 2 — Cleanup (commit `da831c7`)

| File/component | Before | After | Reason |
|---|---|---|---|
| `DECISION_THRESHOLD` | Defined in `app/main.py`, **and** hardcoded as `0.5` twice in `models/evaluate.py` | One definition in `core/registry.py`, imported by both | The constant existed specifically to prevent "same value written twice"; evaluation had recreated the problem — a future threshold tuning would have silently diverged from the reported metrics |
| `app/main.py` | Unused `get_or_create_dev_key` import | Removed | Dead import (only tests use it, from `core.auth` directly) |
| `models/train.py` | Unused `subprocess`, `numpy`, `scipy.sparse` imports | Removed | Dead imports |
| `bulk.html` comment | "Same helper as the index page (app/main.py)" | "(index.html)" | HTML moved out of Python strings long ago |

**Dead-file sweep:** every tracked file is referenced (imports, manifest,
routes, config loads, or tests). **Nothing was deleted.**
`core/lists.py:_host_matches_entry` looks orphaned but is used by
`test_p3_fixes.py` (and its docstring says so) — kept.

**Comment coverage:** the codebase already carries unusually thorough
explanatory comments from prior audit rounds (feature extraction, every
route, the frontend race-condition logic). New comments were added only
where this pass introduced or changed logic, rather than re-narrating
working code.

## Phase 3 — Model review & retrain (commit `655168f`)

**Baseline weakness (model `20260708T152549Z`):** PhiUSIIL's own test
split looked excellent (98.3% accuracy) but is artifact-laden (its
benign class is 100% bare homepages). On the realistic held-out set,
**every error was a false positive on a legitimate content URL with a
hyphenated multi-word path** — 9 of 19 benign URLs flagged (47.4% FP
rate), disproportionately on .org/.org.uk/unseen domains.

**Change:** expanded `core/augmentation_data.py` (v3) with ~105 real,
search-sourced benign URLs across 12 new topic categories — car
maintenance, gardening, museums, university admissions (.edu), guitar
lessons, UK-gov visas (.gov.uk), DIY plumbing, chess, toddler sleep
(.nhs.uk), astronomy, cycling, coffee — deliberately covering
non-.com TLDs. Now 254 URLs / 215 distinct hostnames. Categories were
chosen **disjoint from the held-out evaluation categories** so the
measurement stays honest. Replication kept at 8× (raising it is the
documented memorization mechanism). Same seed, same hyperparameters —
the only variable is data.

**Metrics (threshold 0.5 in both):**

| Metric | Old model | New model (`20260709T131117Z`) |
|---|---|---|
| PhiUSIIL test accuracy | 98.32% | 98.33% |
| PhiUSIIL precision / recall | 99.09% / 96.97% | 99.09% / 97.00% |
| PhiUSIIL FP rate / FN rate | 0.66% / 3.03% | 0.67% / 3.00% |
| PhiUSIIL ROC-AUC | 0.9925 | 0.9926 |
| Held-out accuracy | 73.5% | **94.1%** |
| Held-out precision | 62.5% | **88.2%** |
| Held-out recall (FN rate) | 100% (0%) | 100% (0%) |
| Held-out FP rate | **47.4%** (9 of 19) | **10.5%** (2 of 19) |

Decision rule from the plan — "keep only if it demonstrably improves
FP/FN rates without hurting overall accuracy" — clearly met: held-out FP
rate fell 4.5×, recall stayed perfect, PhiUSIIL unchanged within noise.
All 131 tests (including every known-site regression gate and the
memorization canary `numpy.org` test) pass against the new model.

`models/evaluate.py` now also reports `false_positive_rate`,
`false_negative_rate`, and raw FP/FN counts in every metrics block, and
`models/train.py` computes the distinct-hostname count for metadata
instead of a stale hardcoded number.

**Remaining held-out misses (2):** `quickbooks.intuit.com/r/taxes/...`
(deliberately unseen category) and `doggoneproblems.com/miles/`.
Documented, not chased — fixing them by adding their categories to
training would contaminate the held-out set.

## Phase 4 — Backend testing (commit `2291ea5`)

New `tests/test_api_edge_cases.py` (29 tests): empty/whitespace input,
exact 2048/2049 length boundary, spaces/percent-encoding/non-Latin
URLs/embedded credentials/injection-shaped paths, bare domains,
pseudo-schemes (`javascript:`), allowlisted government domains, compound
public-suffix gov/edu domains, wrong JSON shape/type/method, empty and
whitespace-only bulk uploads, `/health`. Model-failure behavior (503,
not 500) was already pinned by `test_p2_fixes.py`. Nothing failed —
Phase 1's fixes covered the gaps these tests exercise.

## Phase 5 — End-to-end system test

Live server boot (uvicorn, new model), driving the real HTTP surface:

- **Green (safe)**: allowlist stage and model stage (unaugmented
  `numpy.org` docs URL → 0.089 probability, correctly safe)
- **Red (unsafe)**: blocklist, typosquat (with user-facing note), and
  model (synthetic phishing → 1.000) stages
- **Yellow (invalid)**: non-URL input → `status:"invalid"` + message
- **Blue (error)**: 422 over-long URL and 401 unauthenticated bulk
- Bulk JSON summary (`safe/unsafe/invalid/by_stage`) and CSV export
  (status column, empty verdict on invalid rows) verified byte-level
- `/api/admin/reload` hot-swap works with the dev key
- Both HTML pages serve with all four glow states, the Enter handler,
  the fixed newline split, and escaping helpers present

The browser extension exercises the same `/api/check` contract verified
above; its invalid-status handling and scheme filtering are covered by
source-level tests (a real-browser run is outside this environment).

## Phase 6 — Final double-check

Full suite re-run (131 passed), clean working tree, and a stale-
reference sweep (old model version, removed paths, dangling doc links,
the old split bug) — the only matches are the tests that guard against
those patterns.

---

## Files removed

| File | Why safe |
|---|---|
| `models/artifacts/model_20260708T152549Z.ubj` + `.metadata.json` + `preprocessor_20260708T152549Z.joblib` | Superseded model generation; `current.json` points to `20260709T131117Z`. README's artifact policy says stale generations must not ship. Recoverable from git history (`655168f^`) |

No source files were deleted — the dead-file sweep found none.

## Deliberately NOT changed (and why)

- **`dataset/PhiUSIIL_Phishing_URL_Dataset.csv` is tracked in git even
  though `.gitignore` lists `dataset/`** (the ignore only affects
  untracked files). The README says to fetch it from Kaggle. Untracking
  it (`git rm --cached`) would shrink the repo ~50 MB but changes what
  collaborators/CI can do without a Kaggle step — **your call, left
  alone.** (CI currently doesn't need it: `evaluate.py` degrades
  gracefully and tests don't read it.)
- **`nerdwallet.com` appears in both training augmentation and one
  held-out URL** (pre-existing). Left as-is so the before/after model
  comparison used an identical yardstick; worth cleaning next time the
  held-out set is regenerated.
- **0.5 decision threshold** — centralized but not tuned; threshold
  tuning + a three-way safe/suspicious/unsafe verdict remains the
  documented TODO in `core/registry.py`.
- **`apple.slashdot.org`-class false positives** — `apple`/`gmail`
  remain strict subdomain-prefix cores because their impersonation value
  outweighs rare legitimate uses; only cores with *confirmed mainstream*
  legitimate use (`usa`, `outlook`, `office`, `zoom`) got the
  corroboration gate, and `id`/`x` the length guard.
- **`core/lists.py` doesn't NFKC-fold hostnames** (typosquat's
  normalizer does) — an exotic-Unicode allowlist/blocklist miss just
  falls through to the model stage; defense in depth is intact.
- **Extension cache keyed by full URL** while checks send the
  query-stripped URL — correct behavior, marginally conservative; left.
- **Stale `.gitignore` entries (`x/`, `APPLY_INSTRUCTIONS.txt`)** —
  protective if old tooling reappears, zero cost.
- **Committed model metadata contains build-machine absolute paths** —
  informational fields only (the loader uses `current.json` file names);
  regenerated on every retrain.

## Known limitations

- The realistic held-out set is small (n=34); its rates are coarse
  (each URL ≈ 3 points of accuracy). It exists to catch gross
  distribution failure, which it did; a larger independent benchmark
  remains the highest-value evaluation improvement.
- No live WHOIS/DNS/TLS or page-content signal, by design (URL-string
  features only — WAF-safe, no network calls in the request path).
- Blocklist/allowlist are seed lists; production should sync
  Tranco/PhishTank feeds as their `_comment` fields describe.
