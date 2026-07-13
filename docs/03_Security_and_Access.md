# Security & Access Document — Phishing URL Detector

## Authentication Method

There is **no end-user login** — the product is deliberately anonymous and
public-facing (checking a URL, paste, or file needs no account). The only
gated capability is developer/operator tooling:

- **`/api/admin/reload`** — protected by a single shared secret key sent as
  the `X-Dev-Key` header, checked with `secrets.compare_digest` (constant-time
  comparison, prevents timing attacks). The key is either:
  - set explicitly via the `PHISHING_DETECTOR_DEV_KEY` environment variable
    (recommended for deployed environments, since it persists across
    redeploys where the filesystem doesn't), or
  - auto-generated on first run (`secrets.token_urlsafe(24)`, 192 bits of
    entropy) and written to `config/dev_key.txt`, which is gitignored.

This is intentionally a single shared secret, not per-user accounts — the
stated requirement is "only me/developers can trigger a reload," not
"multiple users with different permission levels." If that need grows, this
should be replaced with real auth (e.g. FastAPI's OAuth2/JWT support) rather
than extended in place — see `core/auth.py`'s module docstring.

## User Roles & Permissions

| Role | Can do | Cannot do |
|---|---|---|
| **Public/anonymous user** | Single URL check (`POST /api/check`), bulk paste check (`POST /api/bulk-check-paste`), bulk file upload check (`POST /api/bulk-check-upload`), export bulk results (`POST /api/bulk-check-export`), read `/health` | Trigger a model/list reload; access `/docs`/`/redoc`/`/openapi.json` when `APP_ENV=production` |
| **Developer/operator (holds the dev key)** | Everything the public user can, plus `POST /api/admin/reload` (hot-swaps the model/lists after a retrain) | N/A — this is the highest privilege level in the system; there is no admin UI or broader control plane |
| **Browser extension (client)** | Calls the same public endpoints as any anonymous user, from a `chrome-extension://` origin | Nothing extra — the extension carries no special credential; it's just another public client |

There is no "regular user with an account" tier and no "guest vs. member"
distinction, by design — see PRD's "deliberately NOT in this version."

## Row-Level Security Rules

Not applicable — there is no database with per-user rows (see Technical
Architecture Document's Database Schema section: state lives in JSON config
files and versioned model artifacts, not a queryable multi-tenant store).
Nothing in this system needs "user A cannot see user B's data" rules because
no user-scoped data is ever stored.

The closest analogue — bulk-check-upload's file handling — is scoped
per-request instead: an uploaded file is read directly from the request
stream into memory, processed, and discarded when the response is sent.
Nothing about one user's upload is ever visible to, or retained for, another
request.

## Error Handling

| Failure point | Response |
|---|---|
| Invalid/non-URL input to `/api/check` or bulk endpoints | `status: "invalid"`, `verdict: null`, user-facing `message`: "This doesn't look like a valid URL. Please enter a full website address." (single shared message/constant across single and bulk paths, so wording never drifts). |
| Model artifact missing/not loadable | `503 Service Unavailable` with the underlying `ModelNotFoundError` detail — surfaced from `/health`, `/api/check`, and bulk endpoints alike. |
| Wrong/missing `X-Dev-Key` on `/api/admin/reload` | `401 Unauthorized`, `"Missing or invalid X-Dev-Key header."` |
| Too many failed dev-key attempts from one client within 60s | `429 Too Many Requests` (limit: 20 failed attempts/min/client; **successful** requests never count against this limit, so a legitimate scripted session with the right key is never locked out). |
| Bulk paste with no URLs after splitting | `400 Bad Request`, `"Please paste at least one URL."` |
| Bulk paste over 50 URLs | `400 Bad Request`, `"Please check up to 50 URLs at a time."` (rejected outright — never silently truncated to the first 50). |
| Upload with wrong extension | `400 Bad Request`, `"Only .txt and .csv files are supported."` |
| Upload over 2MB | `413 Payload Too Large`, with the exact limit stated; enforced twice — once from the declared `Content-Length`, once again from actual bytes read, so a client lying about size can't bypass the cap. |
| Upload that can't be decoded/parsed | `400 Bad Request`, `"Could not read this file. Please upload a plain .txt or .csv file."` — a broad `except` deliberately catches anything, since this endpoint is public/unauthenticated and must never leak an internal stack trace via a 500. |
| Upload with no URL-like content found | `400 Bad Request`, `"No URLs found in the uploaded file."` |
| Upload extracts more than 75 URLs | `400 Bad Request`, `"This file contains too many URLs - please limit to 75 URLs per file."` |
| A stale/in-flight single-check request superseded by a newer one | Client-side: the frontend's `AbortController` cancels the stale request, so its response can never overwrite the newer result on screen. |

## Edge Cases

- **Empty form submission** — caught by Pydantic's `min_length=1` on
  `CheckRequest.url` / `BulkPasteRequest.text` before any handler logic runs.
- **Extremely long URL** — capped at `MAX_URL_LENGTH` (2048 chars) at the
  Pydantic level for single checks; bulk-paste tokens longer than that are
  truncated rather than rejected outright, per `_split_paste_urls`.
- **Non-URL text mixed into bulk input** — never silently dropped: each
  token is validated and returned as an explicit `"Invalid"` row (paste
  path keeps every token the user typed; upload path extracts only
  URL-shaped substrings from free-form file content, ignoring the rest).
- **Adversarial file content causing regex catastrophic backtracking** — a
  prior version's single combined tokenize+validate regex could be forced
  into multi-hour hangs by crafted input (confirmed: 50,000 adversarial
  characters took 107 seconds). Fixed by splitting tokenization (one flat,
  non-backtracking character class) from shape validation (run only against
  already-bounded tokens); verified 2,000,000 adversarial characters now
  complete in ~0.27s.
- **CSV/Excel formula injection in exported results** — a URL value
  starting with `=`, `+`, `-`, `@`, tab, or carriage return is prefixed with
  a single quote before being written to CSV/XLSX exports, preventing it
  from executing as a spreadsheet formula when opened in Excel/Sheets.
  Confirmed exploit this closes: an uploaded value like
  `=cmd|' /C calc'!A1` previously wrote through verbatim and would execute.
- **Deployment behind a reverse proxy (Render)** — rate limiting must
  identify the real client, not the proxy. `X-Forwarded-For`'s *last* hop
  (the value Render's proxy itself appends) is trusted only when
  `APP_ENV=production`; trusting it unconditionally would let any client
  spoof an arbitrary IP to either evade its own rate limit or lock out the
  real developer by spoofing their IP.
- **Rate-limiter memory growth** — stale per-client entries are purged once
  the tracking table exceeds a threshold, so a scanner cycling
  spoofed/rotating source IPs can't grow it unbounded on a long-running
  instance.
- **Large uploaded file blocking the whole server** — `bulk_check_upload` is
  a synchronous `def`, not `async def`, so FastAPI runs it in a threadpool
  instead of on the single event-loop thread — confirmed via this project's
  own testing history that an `async def` version blocks every other
  request (including `/api/check`) for the duration of a large upload.
- **Slow/cold-start connection (Render free tier)** — documented in the
  README rather than hidden: the first request after ~15 minutes of
  inactivity can take 20-60 seconds while the instance wakes up; this is a
  platform-tier limitation, not a bug, but should be surfaced to users
  (e.g. a loading state) rather than read as a hang or failure.
- **Domain lookalike with no other suspicious signal** (e.g.
  `redfin.com`/`reddit.com`) — the verdict-deciding typosquat stage requires
  corroborating evidence before flagging a match, specifically to avoid
  false positives on coincidental short-domain similarity; a separate,
  looser "advisory" match (`require_corroboration=False`) is used only to
  suggest a possible real site on verdicts that were already unsafe for
  other reasons — it never drives the verdict itself.
