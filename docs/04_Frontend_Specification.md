# Frontend Specification Document — Phishing URL Detector

The frontend is a single static file, `app/static/index.html`, served
directly by FastAPI's `GET /` route — no build step, no framework, no bundler.
The extension (`extension/popup.html`, `extension/options.html`) is a
separate, smaller surface but should visually match the same system where
practical (same font stack, same safe/unsafe color language).

## Color Palette

Colors below are pulled directly from `app/static/index.html`'s current
stylesheet (dark-first design).

| Role | Hex | Usage |
|---|---|---|
| Page background (darkest) | `#0b0b0f` | Outer page background |
| Surface / card background | `#17171b`, `#1e1e1e` | Panels, cards, the check-result container |
| Elevated surface / borders | `#232329`, `#2a2a2a`, `#2c2c33`, `#34343c` | Input borders, dividers, hover states |
| Primary text | `#e8eaed`, `#f1f3f4`, `#fff` | Headings, primary body copy |
| Secondary/muted text | `#8a8f98`, `#b8bcc4` | Helper text, captions, placeholder text |
| Primary action / brand blue | `#2563eb`, `#3b74f0` | Primary buttons, links, focus rings |
| Success / safe | `#064e3b` (deep bg), `#6ee7b7` (accent) | "Safe" verdict badge/border |
| Danger / unsafe | `#4c0519` (deep bg), `#f87171`, `#fca5a5` | "Unsafe" verdict badge/border |
| Warning / caution | `#1c1500` (deep bg), `#facc15` | Rate-limit / caution states, invalid-input hints |
| Neutral off-white | `#f5f5f5` | Rare light-surface accents |

**Rule going forward:** any new UI element reuses one of the above — do not
introduce new arbitrary hex values. Safe = green family, Unsafe = red
family, Invalid/caution = yellow family. This mapping must stay consistent
between the web UI and the extension's warning page.

## Typography

| Role | Font | Fallback stack |
|---|---|---|
| Body / UI text | `Inter` | `-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif` |
| Secondary body use | `Inter` | `sans-serif` |
| Headings / display | `Manrope` | `sans-serif` |

- Headings (`Manrope`) are used for page title and section headers only —
  everything else (labels, inputs, table content, buttons) uses `Inter`.
- No serif or monospace fonts anywhere in the current UI, including in
  displayed URLs — URLs render in the body font, not `<code>`/monospace,
  to keep the non-technical audience comfortable.

## Component Styles

- **Buttons** — primary action (Check) uses the brand blue (`#2563eb`/`#3b74f0`)
  fill with white/near-white text; hover/focus states shift to the lighter
  blue variant. Secondary actions (e.g. "download CSV") use a lower-emphasis
  outlined or ghost style on the surface color.
- **Input fields** — the URL/search-bar input sits on the surface background
  (`#17171b`/`#1e1e1e`) with a subtle border (`#2a2a2a`/`#2c2c33`) that
  brightens to the brand blue on focus. Placeholder text uses the muted
  secondary color (`#8a8f98`).
- **Verdict cards** — the single-check result renders as a card whose
  border/background tints toward the safe (green) or unsafe (red) palette
  depending on verdict, with the plain-language `reason` shown directly
  beneath the verdict — never shown for `safe` verdicts (a reason next to
  "safe" reads as suspicious/unearned, so it's withheld by design; see
  `app/main.py`'s `CheckResponse.reason` docstring).
- **Bulk results table** — one row per URL: URL, status badge
  (Safe/Unsafe/Invalid, same color language as the single-check card),
  percent chance, and reason (unsafe rows only). Table lives inside its own
  horizontally-scrollable container so long URLs never force the whole page
  to scroll sideways.
- **Modals/expandable panels** — the bulk-check paste/upload UI opens from
  the **+** control next to the main search bar rather than navigating to a
  new page, keeping the single-check flow as the default, fastest path.
- **Extension popup/options** — mirrors the same card and color language at
  a smaller scale; the warning page shown on an unsafe site navigation uses
  the same red/unsafe palette as the web app's verdict card, plus a "go to
  the real site" action when a `legit_domain` is present.

## Spacing & Layout Rules

- Content is centered in a constrained max-width column (search-bar-first
  layout, not a dashboard grid) — the product's core interaction is one
  input and one result, so layout stays narrow and vertical.
- Card padding and inter-element spacing follow a consistent step scale
  (do not introduce arbitrary one-off pixel values); match existing spacing
  already present in `index.html` when adding new sections.
- The bulk-results table and any wide content must scroll within its own
  container (`overflow-x: auto`), never the page body — matches this
  project's general policy against horizontal page scroll.
- Dark theme is the default and currently the only implemented theme; any
  future light-mode work should reuse the same semantic color roles
  (background/surface/text/success/danger/warning) rather than hardcoding a
  second set of literals.

## API & Integration Spec

The frontend talks to exactly one backend — this project's own FastAPI
service — no third-party services are integrated (no Stripe, no Firebase,
no external auth provider, no external AI API). All calls are same-origin
for the web UI, and cross-origin (`chrome-extension://`) for the browser
extension, which is why CORS is wide open (`allow_origins=["*"]`) — these
endpoints carry no cookies/session state, so open CORS does not expose
user-specific data.

| Endpoint | Method | Request body | Response | Used by |
|---|---|---|---|---|
| `/` | GET | — | `index.html` | Web UI shell |
| `/health` | GET | — | `{status, model_version}` or 503 | Uptime checks, extension startup check |
| `/api/check` | POST | `{"url": string}` | `CheckResponse` (see below) | Single-check UI, extension's per-navigation check |
| `/api/bulk-check-paste` | POST | `{"text": string}` | `BulkCheckResponse` | Bulk-paste UI |
| `/api/bulk-check-upload` | POST | multipart file (`.txt`/`.csv`, ≤2MB) | `BulkCheckResponse` | Bulk-upload UI |
| `/api/bulk-check-export` | POST | `{"results": CheckResponse[], "format": "csv"\|"xlsx"}` | File stream (attachment) | "Download results" button after a bulk check |
| `/api/admin/reload` | POST | — (header `X-Dev-Key`) | `{status, model_version}` or 401/429 | Operator tooling only — not called from the public UI |

**`CheckResponse` shape** (what every check-driven UI element renders from):

```
{
  checked_url: string,
  status: "ok" | "invalid",
  verdict: "safe" | "unsafe" | null,
  stage: "blocklist" | "allowlist" | "typosquat" | "model" | null,
  confidence: number | null,       // model's raw phishing-probability score
  model_version: string | null,
  note: string | null,
  message: string | null,          // only set when status = "invalid"
  reason: string | null,           // only set when verdict = "unsafe"
  legit_domain: string | null      // only set for typosquat / advisory matches
}
```

- The UI derives "percent chance" client-side the same way the backend does
  for exports: `safe` verdict → `(1 - confidence) * 100`; `unsafe` verdict →
  `confidence * 100`. Keep this calculation identical in both places — the
  export endpoint (`_percent_chance` in `app/main.py`) is the source of
  truth if the two ever drift.
- Every in-flight single-check request must be abortable so a slower,
  stale response can never overwrite a faster, newer one on screen — use
  `AbortController` (or equivalent) on every new submission.
