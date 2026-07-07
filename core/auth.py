"""
core/auth.py
============
Gates developer-only features (bulk checking) behind a secret key, so this
isn't accidentally exposed to anyone who finds the URL. The key is
auto-generated on first run and stored in config/dev_key.txt, which is
gitignored - nothing to accidentally commit or hardcode.

This is intentionally simple (a single shared secret, not per-user
accounts) because the stated requirement is "only me/developers," not
"multiple users with different permission levels." If that need grows,
swap this for real auth (e.g. FastAPI's OAuth2/JWT support) rather than
extending this file.
"""
from __future__ import annotations
import os
import secrets
import time
from collections import defaultdict, deque
from pathlib import Path
from fastapi import Header, HTTPException, Request

PROJECT_ROOT = Path(__file__).resolve().parents[1]
KEY_PATH = PROJECT_ROOT / "config" / "dev_key.txt"
ENV_VAR_NAME = "PHISHING_DETECTOR_DEV_KEY"

# Simple in-memory sliding-window rate limit on dev-key endpoints. Brute
# force isn't realistically feasible against a 192-bit token (see
# get_or_create_dev_key), so this is defense-in-depth/log-hygiene, not a
# response to a real bypass risk - closes a LOW finding from security
# testing (30 rapid wrong-key requests all returned plain 401s with no
# throttling). In-memory is fine for this single-instance, single-developer
# tool; a multi-instance deployment would need a shared store instead.
RATE_LIMIT_MAX_REQUESTS = 20
RATE_LIMIT_WINDOW_SECONDS = 60
_request_log: dict[str, deque] = defaultdict(deque)


def _check_rate_limit(client_id: str) -> None:
    now = time.monotonic()
    log = _request_log[client_id]
    while log and now - log[0] > RATE_LIMIT_WINDOW_SECONDS:
        log.popleft()
    if len(log) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {RATE_LIMIT_MAX_REQUESTS} requests "
                    f"per {RATE_LIMIT_WINDOW_SECONDS}s on this endpoint.",
        )
    log.append(now)


def get_or_create_dev_key() -> str:
    # Production (Render, etc.): filesystem resets on every deploy, so an
    # env var set once in the host's dashboard is the only thing that
    # actually persists. Checked first for that reason.
    env_key = os.environ.get(ENV_VAR_NAME)
    if env_key:
        return env_key.strip()

    if KEY_PATH.exists():
        return KEY_PATH.read_text().strip()
    key = secrets.token_urlsafe(24)
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEY_PATH.write_text(key)
    print(f"\n[phishing_detector] Generated new dev key at {KEY_PATH}")
    print(f"[phishing_detector] Dev key: {key}")
    print("[phishing_detector] Use this in the X-Dev-Key header for /api/bulk-check\n")
    return key


def require_dev_key(request: Request, x_dev_key: str = Header(default=None)) -> None:
    """FastAPI dependency - raises 401 if the header is missing/wrong,
    429 if this client has exceeded the rate limit."""
    client_id = request.client.host if request.client else "unknown"
    _check_rate_limit(client_id)
    expected = get_or_create_dev_key()
    if not x_dev_key or not secrets.compare_digest(x_dev_key, expected):
        raise HTTPException(status_code=401, detail="Missing or invalid X-Dev-Key header.")
