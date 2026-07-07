# Phishing Detector v2 — Audit Findings & New Architecture

## 1. Scope of this document

This covers three inputs:
1. `Technical_Audit_Report_Preliminary.docx` — the uploaded audit.
2. The legacy project's file tree (screenshot).
3. Four live screenshots of the legacy checker misclassifying `perplexity.ai`, `discord.com`, `india.gov.in`, and `icici.bank.in` as unsafe, plus one showing a "Checked URL" that didn't match the typed input.

**Important caveat up front:** the uploaded audit is explicitly preliminary — it never executed the app, and its findings are about packaging/repo hygiene (`.git` included in the release archive, IDE metadata, logs, a relative model path, stale hardcoded allowlists). It does **not** explain the false-positive behavior in the screenshots. The rest of this document is independent investigation done this session to find the actual root causes, using the file tree and the real trained data as evidence rather than assumption.

## 2. What the file tree suggested, and what we confirmed

| Observation | Risk it implies |
|---|---|
| `legacy/extract_url_features.py`, `legacy/URLFeatureExtraction.py`, **and** a separate root `phishing_features.py` | Two+ independent feature-extraction implementations. If training used one and serving used another, every prediction is built on mismatched features. |
| `models/phishing_pipeline.pkl` **and** `models/XGBoostClassifier.pickle.dat` | Two model artifacts, no version metadata — unclear which one `app.py` actually loads. |
| `train_phishing.log`, `_v2.log`, `_v3.log` | Three retraining attempts already — reactive debugging, not caught by tests. |
| Screenshot 4: input `india.gov.in`, result `Checked URL: icici.bank.in` | A request/response state bug, unrelated to model quality. |

We tested the train/serve-skew risk directly rather than assuming it: we tried to recompute PhiUSIIL's own published `URLLength` column from its own raw `URL` column. **92% of rows were off by exactly 1 character; 8% matched exactly.** Even a "trivial" length feature can't be reliably reverse-engineered from a public dataset's stored text column, because undocumented preprocessing happened before the CSV was finalized. This is the mechanism class that produces "the model flags everything as phishing": training-time and serving-time feature code silently diverging.

## 3. Findings from this session's model work

### 3.1 Label direction was inverted
In PhiUSIIL, `label=1` means **legitimate**, not phishing. Verified against real URLs (`uni-mainz.de` → 1, `teramill.com` / `.gq` domains → 0). Flipped consistently everywhere downstream.

### 3.2 `URLSimilarityIndex` is leaked ground truth
Exactly `100.0`, zero variance, for every legitimate row — computed via a lookup against a reference legitimacy list at dataset-construction time. Dropped entirely.

### 3.3 `IsHTTPS` is a dataset artifact, not a real-world rule
Every single legitimate URL in PhiUSIIL uses HTTPS (0 exceptions). This is almost certainly a collection artifact (benign set likely sourced from an HTTPS-only popularity list), not a real invariant. We kept `is_https` as one signal among ~28, not a gate.

### 3.4 The big one: PhiUSIIL's benign class has zero real-path examples
```
has_real_path   benign(0)   phishing(1)
False            100.0%        72.8%
True               0.0%        27.2%
```
**Not one legitimate URL in the entire training set has a path beyond `/`.** The model had literally never seen a benign example with real content at a real path, so it learned "any real path = phishing" by default — which would misclassify most normal web traffic (articles, docs, product pages). We confirmed this concretely: `https://en.wikipedia.org/wiki/Main_Page` scored **99.9995% phishing** in the first honestly-trained model, purely because of the path — `example.com/wiki/Main_Page` scored similarly high, ruling out anything Wikipedia-specific.

**Mitigation applied:** we pulled 47 real, live-search-sourced legitimate URLs with genuine paths (Wikipedia articles, Indian government service pages, cooking blogs, developer docs, product reviews, GitHub) across deliberately varied categories, and added them to the **training split only** (test split stayed untouched, so metrics are still comparable), upweighted 40x to give the tree ensemble enough signal to stop treating "has a path" as deterministic.

**Honest result of that mitigation:** it fixed the exact screenshot cases and generalizes to domains similar to the augmented set, but **does not fully generalize**. We tested a domain with no allowlist entry and no augmentation coverage — `some-other-wiki-fansite.net/wiki/Random_Article` — and the model still scored it **93.9% phishing**, just for the path shape. This is a partial, directional fix, not a complete one. See §6 for why the architecture limits the damage anyway, and §7 for the real fix.

### 3.5 Allowlist matching bug (found and fixed during testing)
Our first regression-test run caught `en.wikipedia.org` failing because the allowlist only matched hosts *exactly equal to* an entry, not subdomains of it. Fixed to match `host == entry OR host.endswith("." + entry)`.

### 3.6 The "Checked URL" mismatch (screenshot 4)
Not a model problem. It's a symptom of shared mutable state — a global "last result" variable, or a frontend that doesn't tie a response to the request that produced it. The new frontend uses `AbortController` so a slow, stale request can never overwrite a newer one's result, and the API always echoes back the exact URL it evaluated.

### 3.7 Cross-platform serialization: pickling XGBoost inside a joblib Pipeline breaks Linux→Windows deployment
Discovered when a user tried to run this on Windows after the model was trained on Linux: loading raised `XGBoostError: input stream corrupted`, even with byte-identical files (verified by SHA256) and identical library versions on both sides. XGBoost's raw internal booster buffer, when embedded in a pickle/joblib blob, is not guaranteed portable across operating systems even at an identical version number. **Fix:** the XGBoost model is now saved via its own native `save_model()`/`load_model()` (UBJSON format, explicitly designed to be cross-platform), as a separate file from the sklearn preprocessing (which stays in joblib — plain Python/numpy objects don't have this problem). `core/registry.py` reconstructs a `Pipeline`-like object from the two files at load time. Never go back to one joblib blob containing the whole thing.

### 3.8 A second, sharper version of §3.4's dataset bias: trailing slashes
While debugging §3.7, we found the raw model (bypassing the allowlist entirely) scored `https://discord.com/` and `https://www.perplexity.ai/` at ~99.99% phishing. Root cause: **100% of PhiUSIIL's legitimate URLs have exactly 2 slashes — none has a trailing slash, ever.** `num_slashes` alone accounted for 55% of the trained model's total feature importance. **First attempt (insufficient):** added ~20 real bare-root URLs with trailing slashes to the augmentation set. This fixed the exact screenshot cases but, per §3.9, didn't generalize broadly. **Actual fix:** normalized the artifact away at the source in `core/features.py` — a bare-root URL with or without a trailing slash now produces byte-identical features, since they're the same URL to a browser. This is structural, not a data patch, and is what actually made the fix generalize (see §3.9).

### 3.9 A broad regression the earlier spot-check missed: www-prefix bias
After shipping §3.7/3.8's *first* fix (augmentation only, no normalization yet), a much broader test sweep (20 real domains across `.gov`/`.org`/`.ai`/`.ngo`/`.com`) revealed most were *still* failing — my earlier validation (a handful of spot-checked URLs) was too small to catch this, and I should have swept broadly before calling it fixed. Root cause, found by comparing feature vectors of failing vs. passing domains: **100% of PhiUSIIL's legitimate URLs have a `www.` prefix; ~59% of its phishing URLs don't.** `openai.com`, `elevenlabs.io` (no `www.`) failed at 99%+ while structurally-identical `whitehouse.gov`, `icicibank.com` (with `www.`) passed. Same defect class as §3.8, same fix pattern: normalize the `www.` prefix out of every feature computation in `core/features.py` (applied alongside the trailing-slash normalization), rather than keep adding individual augmented URLs. After both structural fixes, the same 20-URL sweep went from ~1/20 to 17/20 correct — and, importantly, `notion.so` and `whitehouse.gov` (never in the augmentation set) now pass, confirming genuine generalization rather than memorization of specific examples.

### 3.10 Remaining gap: real paths on domains outside the augmentation set
The 3 remaining failures in the 20-URL sweep (`spotify.com/us/premium/`, `nasa.gov/mission/...`, `state.gov/countries-area/`) are all the same category flagged honestly in §3.4: TF-IDF path/query text is now the single largest driver of the model's decisions (39% of feature importance) precisely because the benign training vocabulary for paths is still almost entirely empty outside the ~67 augmented URLs. This isn't fixable by another normalization trick — real path content is genuinely different from a bare root — so the only real fix is substantially more real, diverse path examples in training (see §7).

### 3.11 A different problem entirely: typosquat/brand-similarity detection
User-reported: typing `sbl.co.in` (one character off from the allowlisted `sbi.co.in`) returned SAFE at 0.06% phishing probability. This is not a bug in the features above — `sbl.co.in` is structurally clean (no suspicious keywords, ordinary TLD, no obfuscation), so nothing in the lexical/TF-IDF feature set could ever catch it. This needed a fundamentally different mechanism: `core/typosquat.py` computes Levenshtein distance between a candidate domain and every domain in the allowlist, flagging near-misses (edit distance 1, length-matched for short 3-4 character brand cores like `sbi`/`rbi`/`pnb`) as a new `typosquat` stage in the pipeline — deterministic, not left to the ML model, since high-precision brand-impersonation detection shouldn't depend on the model having seen enough typosquat examples. Verified it doesn't cause real short bank codes to falsely flag each other (`sbi.co.in` and `rbi.org.in` are both real, both allowlisted, and are edit-distance-1 from each other's brand core — neither is flagged for existing).

## 4. New architecture

```
[Incoming URL]
      │
      ▼
┌──────────────┐   hit
│  Blocklist   ├──────────────► UNSAFE  (stage="blocklist")
└──────┬───────┘
       │ miss
       ▼
┌──────────────┐   hit
│  Allowlist   ├──────────────► SAFE    (stage="allowlist")
└──────┬───────┘
       │ miss
       ▼
┌──────────────┐   hit
│  Typosquat   ├──────────────► UNSAFE  (stage="typosquat")
│  (edit-dist  │
│  vs allowlist)│
└──────┬───────┘
       │ miss
       ▼
┌───────────────────────────────┐
│ core/features.py              │  <- SAME function, train AND serve
│  -> ColumnTransformer          │
│     (numeric + path/query      │
│      TF-IDF char 3-5gram)      │
│  -> XGBoost (native UBJSON,    │
│     cross-platform safe)       │
└───────────────────────────────┘
```

## 5. Legacy problem → root cause → fix

| Legacy symptom | Root cause | Fix in v2 |
|---|---|---|
| Model flags almost everything unsafe | Train/serve feature skew (likely — two extractor implementations) | `core/features.py` is the *only* feature code; imported identically by `models/train.py` and `app/main.py`. `tests/test_feature_parity.py` guards this permanently. |
| Unclear which model file is live | Two `.pkl` files, no versioning | `models/train.py` writes a timestamped artifact + `metadata.json` + a `current.json` pointer; `core/registry.py` is the only reader, resolves paths via `Path(__file__)`, never `cwd`. |
| "Relative model path" (audit finding) | Same as above | Same fix — absolute, `__file__`-relative resolution. |
| Whitelist maintenance risk (audit finding) | Hardcoded in source | Lists live in `config/*.json`, hot-reloadable via `reload_lists()`, documented as due for a Tranco/PhishTank sync job. |
| Checked URL ≠ typed URL | Shared mutable state / no request-response correlation | Stateless FastAPI handler; frontend `AbortController`; response always echoes its own request's URL. `tests/test_regression_known_sites.py::test_response_always_echoes_the_request_url` pins this. |
| `.git`, IDE metadata, logs in release archive (audit finding) | No packaging discipline | `scripts/package_release.sh` (see below) — not yet written; flagging as the one audit item this document doesn't yet close. |
| Model flags most real domains outside a small known set (found 2026-07-07 via broad sweep) | `www.`-prefix and trailing-slash artifacts in PhiUSIIL's benign class (§3.8, §3.9) | Both normalized at the source in `core/features.py` — structural fixes, not data patches. Verified against a 20-domain sweep never used in training. |
| `sbl.co.in` (typosquat of `sbi.co.in`) scored safe | No brand-similarity mechanism existed | `core/typosquat.py` — deterministic Levenshtein-distance check against the allowlist, new `typosquat` pipeline stage. |

## 6. Why defense-in-depth limits the damage from remaining residual limitations

The model's residual path-content bias (§3.4, §3.10) matters less in production than it would as a standalone classifier, because the allowlist is meant to be populated from the Tranco Top 1M (per the original blueprint) — the overwhelming majority of real-world legitimate traffic hits well-known domains and never reaches the ML stage at all. The model only judges the long tail of unrecognized domains, where a path-content bias is a real but secondary concern versus a first-line classifier with no gate in front of it. The typosquat layer (§3.11) adds a second line of defense specifically for attacks that target that gate directly (impersonating an allowlisted brand).

## 7. What's NOT done — next steps, honestly

- **The path-topic diversity gap (§3.17) is real and precisely diagnosed, not just "needs more data."** Domain generalization is now genuinely solid (verified: `numpy.org`, `stripe.com`, `notion.so`, `openai.com`, `whitehouse.gov` all correctly safe, none were augmented). What's still thin is *topic* diversity within the path text itself — a broad 10-URL sweep of unaugmented paths on augmented domains scored 7/10, and the 3 failures all share the pattern of a topic area (TV reviews, sports scores, GitHub feature pages) not represented anywhere in the augmentation set's path text, even though the domain itself is. The fix is straightforward but was out of scope for this pass: audit the augmentation set for topic concentration (10 of 124 URLs are all "pandas groupby" tutorials) and deliberately spread path *topics* within each domain category, not just add more domains.
- **Typosquat detection (§3.14, §3.17) only covers the allowlist's ~69 seed domains.** It will scale automatically as the allowlist grows toward a real Tranco-based list, but until then it only protects brands already in the seed list.
- **No live Tier 2 (WHOIS/DNS/TLS) or Tier 3 (content) integration** in this serving path — `dataset_small`'s model remains separate, as a complementary signal, not yet wired into `/api/check`.
- **Allowlist/blocklist are seed lists**, not live syncs. Blocklist specifically caught 0 of 100,000 URLs in the independent evaluation (still 3 RFC-2606 placeholder entries) — production needs a scheduled job pulling Tranco/Cisco Umbrella (allowlist) and PhishTank/OpenPhish/URLHaus (blocklist).
- **No release packaging script yet** — the original audit's `.git`/IDE-metadata/log-exclusion finding isn't closed by this deliverable.
- **Subdomain counting in `core/features.py`** is still a naive heuristic (label-count based), not the size-matched-against-known-domains approach now used in `core/typosquat.py` — consistent with the multi-part-TLD caveat in §3.17 (a general public-suffix-list fix was tried and rejected for the same `bank.in` reason), this remains a documented approximation, not a live-confirmed bug.
- **Validation lesson learned twice now, the hard way:** a small spot-check passed and was reported "fixed" before a broader sweep (first at 20 URLs, now at 100,000) revealed the real picture. `tests/test_regression_known_sites.py::test_broader_real_world_sweep_mostly_safe` and `test_augmentation_generalizes_to_unaugmented_domains` are permanent CI gates specifically so regressions of this shape can't happen silently again — but they are not a substitute for another independent large-scale evaluation before claiming this is fully solved.

### 3.13 Made production-deployable for the browser extension
Two changes were needed to move from "runs on localhost only" to "deployable to a real host": (1) CORS middleware added so a `chrome-extension://` origin can call the API — previously untested since only same-origin browser requests had been used; (2) `core/auth.py`'s dev key now checks an environment variable (`PHISHING_DETECTOR_DEV_KEY`) before falling back to the local auto-generated file, because Render's (and most PaaS) filesystems are ephemeral and reset on every deploy — without this, the bulk-check key would silently rotate on every redeploy.

### 3.14 Typosquat detection missed transpositions and had too-narrow brand coverage
User-reported: `filpkart.com` and `filpcart.com` (both typosquats of `flipkart.com`, a major Indian e-commerce site) scored SAFE. Two independent causes, both fixed:
1. **Coverage gap:** `flipkart.com` and `instagram.com` weren't in the protected-brands list at all (it only had ~19 seed domains), so typosquat detection never got a chance to compare against them. Expanded to ~69 domains, adding major global and Indian consumer/social/finance platforms (Instagram, Facebook, WhatsApp, Flipkart, Paytm, PhonePe, Swiggy, Zomato, several more Indian banks, etc.) — since this list serves both the allowlist fast-path and the typosquat reference set, expanding it improves both at once.
2. **Algorithm gap:** even with `flipkart.com` in the list, plain Levenshtein distance between `flipkart` and `filpkart` is 2 (two substitutions) — past the old distance-1 threshold — because standard edit distance doesn't recognize an adjacent-character swap ("li"→"il") as a single logical move the way a human reads it. Replaced with Damerau-Levenshtein, which counts a transposition as one edit. This also catches the compound case `filpcart.com` (transposition + a k→c substitution = distance 2 under Damerau).

**Found and fixed a new false positive while testing the fix:** loosening the distance threshold to 2 (needed to catch the compound typo) initially caused `slacker.com` — a real, unrelated company — to be flagged as a typosquat of `slack.com`, because a 2-character length difference let a short brand core match a longer, coincidentally-similar real word. Fixed by decoupling the two tolerances: edit distance can be up to 2, but length difference is capped at 1 regardless — every actual reported attack was same-length, so this loses no real coverage while closing the false-positive gap.

### 3.15 General character-substitution/homoglyph defense (not brand-list-bound)
User feedback after 3.14: the request wasn't "protect these specific brands better," it was "detect the *technique* of character-level wordplay generally" — leetspeak digit substitution (`s3cure`, `acc0unt`), Unicode homoglyphs (Cyrillic `а` standing in for Latin `a`), and punycode-encoded lookalikes. Brand-list matching alone can never generalize past whatever's in the list.

**Design decision — rejected a big fuzzy-match dictionary:** considered bundling a large English word list (104K words available via `apt install wamerican`) to fuzzy-match domain cores against "any common word," but rejected it: (a) brand names like "google" or "instagram" aren't in a standard dictionary anyway, so it wouldn't even help the domain-impersonation case, and (b) fuzzy-matching against 100K+ words raises real false-positive risk on short/coincidental legitimate domains. Instead, normalization is applied to a small, well-scoped set of ~13 generic security-relevant terms (secure, verify, login, account, bank, password, etc.) — the *technique* (character-substitution normalization) generalizes without needing a huge reference set that would itself become a noise source.

**What was built** (`core/wordplay.py`):
- `normalize_confusables()` — maps leetspeak digits/symbols (0→o, 1→l, 3→e, 4→a, 5→s, etc.) and common Cyrillic/Greek homoglyphs to their canonical Latin letter.
- `has_mixed_script()` — flags a hostname mixing Latin with Cyrillic/Greek characters (a brand-agnostic IDN-homograph signal — legitimate domains essentially never do this).
- `is_punycode()` — flags `xn--`-prefixed hostname labels.
- `contains_obfuscated_suspicious_term()` — flags text that, after normalization, contains a generic suspicious term, but ONLY if the raw text already contained an actual substitution character. That second condition is load-bearing: it's what stops this from flagging a legitimate company whose name plainly contains "secure" or "bank" in ordinary spelling.

**Wired into three places:**
1. `core/features.py`'s existing `suspicious_keyword_count` now checks both raw AND normalized path/query text, so `v3rify-acc0unt.php` matches "verify"/"account" even though neither literal substring appears.
2. Five new ML features (`has_mixed_script`, `is_punycode`, `num_confusable_chars`, `confusable_char_ratio`, `domain_has_obfuscated_suspicious_term`) feed the general homoglyph/leetspeak signal into the model itself, not just a hardcoded rule.
3. `core/typosquat.py` now also compares the leetspeak/homoglyph-*normalized* domain core against every protected brand, generalizing typosquat detection to catch leetspeak variants (`g00gle.com`, `paypаl.com` with Cyrillic а) of ALL ~69 protected brands at once, not just ones with a hand-written variant.

**Training data — the user's "retrain on a new dataset" ask, done directly:** PhiUSIIL almost certainly has few or no examples of this attack class, so the new features would have had no real training signal. `core/wordplay_training_data.py` generates ~240 synthetic phishing examples (systematic leetspeak substitution applied to generic suspicious terms and to a sample of allowlist brand names, plus a handful of real Cyrillic-homoglyph and punycode-style examples) and 16 legitimate numeric-brand counter-examples, added to the training split only (test split stays untouched).

**Found a real false positive while building the counter-examples:** `1Password` — a genuine, well-known password manager — legitimately normalizes to contain "password" after leetspeak normalization (`1password` → `lpassword`). Without an explicit counter-example, the naive heuristic would flag a real company for the crime of being named what it's named. Added to both the allowlist directly and the training counter-examples, alongside `9gag.com`, `auth0.com`, `id.me`, `23andme.com`, `office365.com`, and others chosen specifically because they legitimately mix digits into otherwise-alphabetic branding.

**Verified generalization, not memorization:** tested the raw ML model (bypassing the allowlist/typosquat layers entirely) against wordplay patterns that do NOT appear in the synthetic generator's output — `p4ypal-security.info/verify/acc0unt.php`, `microsft-support.online/sign1n`, `netfl1x-billing.xyz/update-p4yment`, a Cyrillic-homoglyph Dropbox lookalike — all scored ~100% phishing. Also verified zero false positives on 8 real numeric-branded companies (all scored <2% phishing probability).

---

## 3B. Independent red-team security assessment and 100,000-URL model evaluation (2026-07-07)

The user commissioned two independent, non-destructive reviews via Claude Code: a red-team security assessment of the live running application, and a 100,000-URL functional evaluation of the detection pipeline across 12 phishing technique families and a broad legitimate-traffic sample. Both were thorough, rigorous, and cross-verified internally before being handed off. Findings below, and what was actually fixed vs. what remains open.

### 3.16 Security assessment findings — fixed

**HIGH — event-loop-blocking DoS via oversized bulk upload (confirmed live: a single 19MB upload froze the entire server, including the public `/api/check` endpoint, for 35 seconds).** Root cause: `bulk_check_file` was declared `async def` but did 100% synchronous CPU/IO work, running directly on Uvicorn's single event-loop thread instead of FastAPI's threadpool (which sync `def` functions get automatically — `bulk_check_json` was never vulnerable to this for exactly that reason). Fixed: changed to a plain `def`, added a request size check via `Content-Length` before reading, and a defense-in-depth check on the actual bytes read (rejects >5MB either way).

**MEDIUM — CSV/formula injection in exported results (confirmed: `=cmd|'/C calc'!A1` and similar payloads survived unescaped into `bulk_check_results.csv`, would execute as a formula if opened in Excel/Sheets).** Fixed with the standard OWASP mitigation: any exported field starting with `=`, `+`, `-`, `@`, tab, or CR gets a leading single quote, forcing spreadsheet apps to treat it as text.

**MEDIUM — no per-URL length cap on bulk endpoints (confirmed: a 500,000-character single "URL" was accepted and processed via plain JSON, no file upload needed — this is what made the DoS above reachable two ways).** Fixed: `BulkCheckRequest.urls` items now carry the same 2048-char cap `CheckRequest` already had; `bulk_check_file` truncates oversized lines/cells before they reach feature extraction.

**LOW — no rate limiting on dev-key auth failures.** Added a simple in-memory sliding-window limiter (20 requests/60s per client IP) on the dev-key-gated endpoints. Brute force isn't realistically feasible against a 192-bit token regardless — this is defense-in-depth/log-hygiene, not a response to a real bypass risk.

**LOW — `/docs`, `/redoc`, `/openapi.json` publicly reachable, disclosing the dev-only bulk endpoints' shape to unauthenticated scanners.** Gated behind `APP_ENV=production` (defaults open for local development, where they're genuinely useful).

**LOW / INFORMATIONAL — unpinned dependencies, broadening Unicode homoglyph coverage.** All remaining dependencies (`fastapi`, `uvicorn`, `pydantic`, `python-multipart`, `joblib`, `pytest`, `httpx`) now pinned to exact versions, matching the ML stack's existing discipline. `core/typosquat.py`'s host normalization now runs Unicode NFKC normalization first, closing the fullwidth-Unicode gap (`ａ`-`ｚ`) essentially for free without hand-maintaining a bigger confusables table.

### 3.17 Model evaluation findings — fixed

**A newly discovered bug, found independently by the evaluation: `mail.*` subdomains flagged as Gmail typosquats.** `core/typosquat.py::_brand_core()` used to take `hostname.split(".")[0]` — the first DNS label of the *entire* hostname — with no registrable-domain awareness. Any company's `mail.` subdomain (`mail.chase.com`, `mail.skrill.com`, and by the evaluation's account, thousands of others) extracted core `"mail"`, one Damerau-Levenshtein edit from the allowlisted `gmail.com`'s core `"gmail"`. This alone caused 94% (2,613 of 2,777) of the typosquat layer's false positives in the 100K-URL run.

**The fix was NOT to adopt a general public-suffix-list library.** `tldextract` was tried and rejected during this session: its bundled PSL doesn't recognize `bank.in` as a compound suffix, so it would have mis-parsed our OWN allowlist entry `icici.bank.in` as `domain="bank"`, `subdomain="icici"` — backwards, and a worse bug than the one being fixed. Instead: since the exact structure of every protected domain is always known (they're literal strings in `config/allowlist.json`), the host is size-matched against each specific protected domain's own label count. `mail.chase.com` compared against 2-label `gmail.com` correctly extracts `chase`, not `mail`.

**This also closed a second, related gap the security assessment found independently: brand names used as a subdomain *prefix* to impersonate (`irs.mynewsblog.net`), previously excluded by the old "distance must be exactly 1" rule (this is an exact match, distance 0).** Now checked as a dedicated, high-precision exact-match rule against any label before the size-matched suffix.

**Verified the fix doesn't reopen old gaps or create new ones:** `mail.chase.com`/`mail.skrill.com` no longer flagged; `irs.mynewsblog.net` now correctly flagged; `filpkart.com`/`filpcart.com`/`sbl.co.in`/`lnstagram.com` (the earlier user-reported attacks) still correctly caught.

**A separate finding from the evaluation — coincidental brand-name collisions (`redfin.com`/`reddit.com`, `shopify.com`/`spotify.com`, `slate.com`/`slack.com`, `usbank.com`/`yesbank.in`) flagged with no other evidence.** Added a corroboration requirement to the 5+-character, distance-2 fuzzy-match branch: a suspicious keyword or unusual TLD must accompany the near-miss. **Important correction to the evaluation's own recommendation, found while implementing it:** the recommendation assumed "real reported attacks in this class also carried a suspicious path or TLD" — testing showed this is false for `filpcart.com` specifically (the user's own original report, bare domain, ordinary `.com`, no path). A blanket corroboration gate would have silently broken detection of a real, already-reported attack. Fixed properly by distinguishing *why* a distance-2 match occurred: a transposition-involving distance-2 match (plain Levenshtein distance ≠ Damerau distance) is unambiguous enough on its own and bypasses the gate; a pure-substitution distance-2 match (the coincidental collisions) requires corroboration. Verified against both the coincidental collisions (no longer flagged bare) and the real attack (still flagged, no corroboration needed).

**The memorization problem (§5.2 of the evaluation — the single most damning finding).** Matched-pair proof: a verbatim-augmented path on `pandas.pydata.org` scored 0.22% phishing; the same-shape, unseen `numpy.org` scored 99.94%. Worse: two different paths on the *same* domain (`realpython.com`) — one augmented, one not — scored 0.40% and 99.86% respectively. Root cause per the evaluation: 40x replication of a ~69-URL set teaches memorization of literal strings, not the general shape of a legitimate content URL.

**Fix:** expanded `core/augmentation_data.py` from ~69 to ~144 real URLs across ~94 distinct domains spanning 13 genuinely different topic categories (outdoor recreation, government services, health, personal finance, consumer tech reviews, sports, online education, insurance, real estate, plus the original set), and cut replication from 40x to 8x — high replication of a small set is the mechanism that caused memorization, not a neutral efficiency choice.

**Verified with the evaluation's own matched-pair test:** `numpy.org` (never augmented) went from 99.94% → 8.84% phishing probability — genuine cross-domain generalization, confirmed by a broader 10-URL sweep of unaugmented domains and paths (7/10 correct, up from what was effectively 0/2 on this specific test before).

**Honest residual gap, more precisely diagnosed than the original evaluation:** `realpython.com/python-json/` (same domain as an augmented URL, different *topic*) still scores 99.47% — barely changed. Investigated why: 10 of the 124 augmented URLs are all specifically about "pandas groupby" tutorials — good *domain* diversity was undermined by poor *path-topic* diversity within one category. The TF-IDF text component operates on path content, not domain, so it learned "groupby"-related vocabulary as safe without learning anything general about "documentation site content" as a shape. **This is a more actionable diagnosis than "memorized, not generalized"** — the fix isn't just "more URLs," it's "more distinct path *topics* per domain category," and is the clearest next step (see §7).

### 3.18 Findings from the evaluation not yet addressed (honest, per its own recommendations)

- **Blocklist still catches 0 of any URL tested** — `config/blocklist.json` remains 3 RFC-2606 placeholder entries. This was already flagged as unfinished infrastructure work in §7, not a modeling problem; wiring up a real PhishTank/OpenPhish/URLHaus feed is a genuinely separate undertaking (needs scheduled network fetches) out of scope for this session.
- **Threshold tuning will not fix the remaining path-topic gap.** The evaluation found true-positive and false-positive confidences both cluster above 0.99 with almost no separation to act on — confirmed consistent with the `realpython.com/python-json/` result above (99.47%, not a borderline call). Any further fix has to be in training data/features, not the decision boundary.
