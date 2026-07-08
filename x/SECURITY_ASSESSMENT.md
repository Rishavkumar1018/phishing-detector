# Phishing URL Detector — Red Team / Blue Team Security Assessment

Adversarial testing against the running application (auth, bulk-upload, and URL/model-evasion
surfaces), followed by prioritized remediation guidance. No code was modified during this review.

- **Target:** `app/main.py` served at `http://127.0.0.1:8000`
- **Scope:** auth & access control · bulk upload/input handling · URL parsing & model evasion
- **Method:** live HTTP testing + source review, non-destructive
- **Result:** 1 High, 3 Medium, 3 Low, 7 checks passed clean

**Provenance note:** three red-team passes were run in parallel. The auth/infra pass finished
cleanly; the bulk-upload and model-evasion passes hit an account-level API session limit
partway through and were completed directly by the orchestrating session using the same test
plans. The local server used for testing was stopped at the end of the review.

---

## Table of contents

1. [Auth & access control](#1-auth--access-control)
2. [Bulk upload & input handling](#2-bulk-upload--input-handling)
3. [URL parsing & model evasion](#3-url-parsing--model-evasion)
4. [Remediation plan](#4-remediation-plan)
5. [What's already solid](#5-whats-already-solid)

---

## 1. Auth & access control

*Red team · `core/auth.py`* — tried bypassing the dev-key gate on `/api/bulk-check*`, probed
CORS, error-message disclosure, doc-endpoint exposure, and dependency hygiene. **No
authentication bypass was found.**

### Finding — No rate limiting or lockout on dev-key auth failures — `LOW`

30 rapid wrong-key requests all returned plain `401`s with no throttling or backoff. Brute force
is impractical given the key is a 192-bit `secrets.token_urlsafe(24)` token, so this is a
defense-in-depth/log-hygiene gap rather than a real bypass risk.

```
Repro: 30x POST /api/bulk-check-file  X-Dev-Key: <wrong>  →  401, no delay, no lockout
```

### Finding — `/docs`, `/redoc`, `/openapi.json` are publicly reachable — `LOW`

FastAPI's default schema endpoints disclose the full shape of the dev-only bulk endpoints
(header name, request/response models) to any unauthenticated scanner. The auth gate itself
isn't affected — this only aids reconnaissance.

### Finding — Dependency pinning & supply-chain hygiene — `INFORMATIONAL`

`fastapi`, `uvicorn`, `pydantic`, `python-multipart`, `joblib`, `pytest`, `httpx` are unpinned in
`requirements.txt`, unlike the ML stack. Separately, `joblib.load()` in `core/registry.py`
deserializes a pickle-based file — confirmed no HTTP endpoint currently writes into
`models/artifacts/`, so this is a supply-chain/insider concern, not a live remote vulnerability
today.

---

## 2. Bulk upload & input handling

*Red team · `app/main.py`* — targeted `/api/bulk-check` and `/api/bulk-check-file`, the two
dev-key-gated endpoints that accept attacker-shaped input at volume.

### Finding — Event-loop-blocking DoS via oversized bulk upload — `HIGH` (confirmed)

`bulk_check_file` is declared `async def` but does 100% synchronous CPU/IO work — reading,
parsing, feature extraction, and prediction all run directly on Uvicorn's single event-loop
thread. There is no upload size limit and no per-URL length cap on either bulk endpoint;
`MAX_BULK_URLS=5000` only caps the parsed URL *count*, not byte size.

**A single request froze the entire server — including the public, unauthenticated `/api/check`
endpoint — for 35 seconds.**

```
Repro:
1. Built 19.08 MB .txt: 100 lines × ~200,000-char "URL" each
2. POST /api/bulk-check-file (valid X-Dev-Key) with that file
3. Concurrently: GET /health from a second process while (2) was in flight

Result:
  big upload  → HTTP 200 in 35.11s
  /health     → HTTP 200 but took 34,646 ms (blocked for ~the entire duration)
```

### Finding — CSV/formula injection in exported results — `MEDIUM` (confirmed)

Values from the uploaded `url` column are written verbatim, unescaped, into
`bulk_check_results.csv`. Payloads starting with `=`, `+`, `-`, or `@` survive untouched — if a
developer opens the exported file in Excel or Sheets, those cells are evaluated as formulas by
default.

```
Repro — uploaded url column:
  =cmd|' /C calc'!A1
  +2+5+cmd|' /C calc'!A1
  -2+3
  @SUM(1+1)

Downloaded CSV, column 1 (unmodified):
  =cmd|' /C calc'!A1,unsafe,model,0.99999,...
  +2+5+cmd|' /C calc'!A1,unsafe,model,0.99999,...
  -2+3,unsafe,model,0.99984,...
  @SUM(1+1),unsafe,model,0.99994,...
```

### Finding — No per-URL length cap on bulk endpoints — `MEDIUM` (confirmed)

`/api/check` enforces `max_length=2048` via Pydantic. `/api/bulk-check`'s JSON list items and
the file-upload path enforce nothing — a 500,000-character single "URL" was accepted and
processed as-is. This is what makes the DoS above reachable through plain JSON too, no file
upload required.

### Finding — Malformed CSV handling — `PASSED`

Ragged rows, short rows, header-case variants, and a BOM-only file all degraded gracefully — no
unhandled exceptions or stack-trace leaks in the time tested.

---

## 3. URL parsing & model evasion

*Red team · `core/lists.py`, `core/typosquat.py`, `core/wordplay.py`* — tried to get a
genuinely suspicious URL a `safe` verdict: host-spoofing tricks, typosquat gaps, homoglyph gaps,
and boundary cases against the public `/api/check` endpoint. **No live safe-verdict bypass was
achieved** — the two findings below are confirmed gaps in the deterministic layers' own logic
that happen to be caught as a fallback by the ML model today.

### Finding — Typosquat detection misses exact short-brand-core subdomain abuse — `MEDIUM` (code-level gap)

`_brand_core()` takes `host.split(".")[0]` with no registrable-domain awareness. For short
protected cores (≤4 chars — `sbi`, `rbi`, `pnb`, `irs`, `usa`, `nih`), the matcher requires edit
distance **exactly 1** — so a host like `pnb.mynewsblog.net`, whose core is an *exact* match
(distance 0), is excluded by the "near-miss only" rule and isn't caught by the allowlist either.

```
Repro — tested (bland domains, no suspicious keywords, to isolate this layer):
  pnb.mynewsblog.net, irs.mynewsblog.net, usa.mynewsblog.net,
  nih.mynewsblog.net, pnb.recipeswap.org, irs.recipeswap.org

All 6 fell through typosquat/allowlist to stage="model" —
but the ML model independently scored every one >99.99% phishing.
```

No live bypass — the model caught every case as a fallback — but the typosquat layer's own
stated purpose is to be a deterministic guarantee that doesn't depend on model coverage, and
today it accidentally isn't one for its highest-value targets.

### Finding — `HOMOGLYPH_MAP` is a hand-picked subset of real Unicode confusables — `LOW` (code-level gap)

Cyrillic `м`/`һ` and the entire Fullwidth Forms block (`ａ-ｚ`) aren't in `HOMOGLYPH_MAP`. For
brand impersonation this is masked: `_damerau_levenshtein` compares raw characters, so any
single-char, length-preserving substitution still costs exactly 1 edit regardless of which map
covers it. `gмail.com`, `yaһoo.com`, and `ａmazon.com` were all still caught — via the typosquat
edit-distance fallback, not the homoglyph map itself.

No equivalent safety net exists for the generic suspicious-term path
(`contains_obfuscated_suspicious_term`), which only ever compares against its own small map with
nothing backing it up.

---

## 4. Remediation plan

*Blue team · guidance only, no code changed.* Ordered by real-world impact — the first fix alone
closes the only finding that reaches the public endpoint.

### 01 — Stop the bulk path from blocking the event loop — `HIGH`

Change `bulk_check_file` to a plain `def` (FastAPI then runs it in its threadpool automatically,
same as `bulk_check_json` already gets) or wrap the heavy call in `run_in_threadpool`. Add a
`Content-Length` check before `await file.read()` and reject anything past a few MB. In
production, back this with a reverse-proxy body-size limit too.

→ addresses the High finding in [§2 Bulk upload](#2-bulk-upload--input-handling)

### 02 — Escape leading formula characters before writing the export CSV — `MEDIUM`

At the `writer.writerow(...)` call in `bulk_check_file`, prefix any field starting with `=`,
`+`, `-`, `@`, tab, or CR with a single quote — the standard OWASP CSV-injection mitigation. A
few lines, contained to one function.

→ addresses the CSV-injection finding in [§2 Bulk upload](#2-bulk-upload--input-handling)

### 03 — Apply the same 2048-char cap to bulk endpoints — `MEDIUM`

Give `BulkCheckRequest.urls` items the same `max_length` constraint `CheckRequest` already has,
and reject/truncate oversized lines or CSV cells in `bulk_check_file` before they reach feature
extraction. This is what makes the JSON path exploitable without any file upload at all —
closing it also shrinks the blast radius of fix 01.

→ addresses the length-cap finding in [§2 Bulk upload](#2-bulk-upload--input-handling)

### 04 — Close the short-brand-core typosquat gap — `MEDIUM`

In `core/typosquat.py`, add an explicit, distance-independent rule: if a host's brand core
exactly equals a protected brand's core, the host isn't the protected domain itself, and it
doesn't satisfy the allowlist's subdomain check — flag it immediately, rather than requiring a
distance-1 "near miss." Pin it with a permanent regression test (e.g.
`sbi.some-unrelated-site.net`) following the same pattern as
`test_regression_known_sites.py` — this project has already closed two adjacent gaps in this
exact file (subdomain matching, then transposition handling); this is the same class of fix a
third time.

→ addresses the typosquat finding in [§3 URL / model evasion](#3-url-parsing--model-evasion)

### 05 — Broaden Unicode confusables coverage — `LOW`

Run hostnames/paths through `unicodedata.normalize("NFKC", ...)` before
`normalize_confusables()` — closes the fullwidth-Unicode gap essentially for free. For the
remaining Cyrillic/Greek gaps, extend `HOMOGLYPH_MAP` by hand or adopt the Unicode Consortium's
published confusables table — a 1:1 character map doesn't carry the false-positive risk that
already ruled out a big fuzzy dictionary (AUDIT_NOTES §3.15), so that earlier rejection doesn't
apply here.

→ addresses the homoglyph finding in [§3 URL / model evasion](#3-url-parsing--model-evasion)

### 06 — Rate-limit dev-key auth attempts — `LOW`

A modest cap (e.g. 20 req/min via `slowapi` or a small in-memory token bucket keyed by client
IP) on `/api/bulk-check*` closes this without adding real friction for a single-developer tool.

### 07 — Gate the schema endpoints in production — `LOW`

`FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` behind an `ENV=production` flag. One
line in the `FastAPI(...)` constructor.

### 08 — Pin remaining dependencies and add periodic auditing — `INFORMATIONAL`

Pin `fastapi`, `uvicorn`, `pydantic`, `python-multipart`, `joblib`, `pytest`, `httpx` to exact
versions, matching the ML stack's existing discipline, and add a periodic `pip-audit` pass.
Document that `models/artifacts/` must never accept externally-supplied files, so any future
"sync/upload a model" feature is forced to reckon with the `joblib.load()` deserialization risk
deliberately.

---

## 5. What's already solid

*No action needed.*

- ✅ **Host-spoofing tricks** — userinfo (`user@host`), query-string, and fragment tricks aiming
  to spoof a protected brand were all parsed correctly; the real destination host was always
  what got evaluated.
- ✅ **Allowlist dot-boundary matching** — substring tricks like `sbi.co.in.evil-login.com` did
  not falsely match the real `sbi.co.in` entry.
- ✅ **2048-char length boundary on `/api/check`** — enforced correctly at the edge, with no
  partial processing of oversized input.
- ✅ **Null bytes / control characters** — no crashes or misleading "checked URL" echoes under
  any input tried.
- ✅ **Error responses** — malformed JSON, wrong content-type, and invalid routes all returned
  clean, generic errors with no stack traces or internal paths leaked.
- ✅ **Secret storage** — `config/dev_key.txt` has correctly scoped OS permissions and is
  properly gitignored alongside `.env`.
- ✅ **Wildcard CORS** — confirmed there is no cookie/session/ambient credential anywhere in the
  app, so `allow_origins=["*"]` exposes nothing today. Re-audit only if credentialed browser
  state is ever added.
