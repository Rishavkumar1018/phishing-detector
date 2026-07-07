"""
core/lists.py
=============
Fixes audit finding: "Large hardcoded allowlists become stale... Move to
configuration/database with automated updates."

Lists live in config/*.json (data), not in Python source (code). Loading
is cached but explicitly reloadable, so a refresh job can call
reload_lists() after updating the JSON/DB without restarting the process.

This is the front gate from the blueprint's defense-in-depth diagram:
    blocklist hit  -> UNSAFE immediately, skip the model entirely
    allowlist hit  -> SAFE immediately, skip the model entirely
    neither        -> fall through to the ML model

Matching is by registrable-ish domain (host with a leading "www." stripped),
so "https://www.discord.com/anything?x=1" matches the "discord.com" entry.
"""
from __future__ import annotations
import json
from pathlib import Path
from functools import lru_cache
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = PROJECT_ROOT / "config"


def _normalize_host(url_or_host: str) -> str:
    if "://" not in url_or_host:
        url_or_host = "http://" + url_or_host
    host = urlparse(url_or_host).hostname or ""
    return host[4:] if host.startswith("www.") else host


def _host_matches_entry(host: str, entry: str) -> bool:
    """Exact match OR host is a subdomain of the entry (en.wikipedia.org
    matches wikipedia.org; evil-wikipedia.org must NOT match, hence the
    dot-boundary check rather than a bare .endswith(entry))."""
    return host == entry or host.endswith("." + entry)


@lru_cache(maxsize=1)
def _load(name: str) -> dict:
    path = CONFIG_DIR / f"{name}.json"
    data = json.loads(path.read_text())
    data["_domain_set"] = set(data["domains"])
    return data


def reload_lists():
    """Call after updating config/*.json or after a scheduled refresh sync
    (see docstring: production should sync allowlist from Tranco/Umbrella
    and blocklist from PhishTank/OpenPhish/URLHaus on a short interval)."""
    _load.cache_clear()


def is_allowlisted(url: str) -> bool:
    host = _normalize_host(url)
    return any(_host_matches_entry(host, e) for e in _load("allowlist")["_domain_set"])


def is_blocklisted(url: str) -> bool:
    host = _normalize_host(url)
    return any(_host_matches_entry(host, e) for e in _load("blocklist")["_domain_set"])


def list_metadata() -> dict:
    return {
        "allowlist": {k: v for k, v in _load("allowlist").items() if not k.startswith("_")},
        "blocklist": {k: v for k, v in _load("blocklist").items() if not k.startswith("_")},
    }
