"""
core/typosquat.py
==================
Catches the exact gap flagged during testing: "sbl.co.in" (one character
off from "sbi.co.in") was scored SAFE at 0.06% phishing probability,
because it's structurally clean - no suspicious keywords, no odd TLD, no
obfuscation. The ONLY way to catch it is recognizing it's a near-miss of a
protected brand's domain. That's a high-precision pattern, better done as
an explicit, deterministic rule than hoped for from a handful of ML
training examples - false positives here (flagging a genuinely unrelated
domain) are cheap to avoid with a tight distance threshold, and false
negatives (missing a typosquat) are exactly what this exists to prevent.

Reuses the allowlist as the protected-brand reference set, so there's one
list to maintain, not two (see core/lists.py's staleness-risk fix - the
same principle applies here: don't hardcode a second brand list in code).

IMPORTANT - how brand cores are extracted (see AUDIT_NOTES.md 3.16):
The original version took host.split(".")[0] - the first DNS label of the
WHOLE hostname - as "the core" to compare, with no awareness of where the
registrable domain actually starts. This caused a real, confirmed bug:
"mail.chase.com" extracted core "mail", which sits 1 edit from the
allowlisted "gmail.com"'s core "gmail" - flagging any company's ordinary
mail subdomain as a Gmail impersonation attempt.

The fix is NOT to adopt a general public-suffix-list library (tldextract
was tried and rejected: its bundled PSL doesn't recognize "bank.in" as a
compound suffix, so it would mis-parse our OWN allowlist entry
"icici.bank.in" as domain="bank"/subdomain="icici" - backwards). Instead,
since we always know the EXACT structure of each protected domain we're
comparing against (they're literal strings in config/allowlist.json), we
size-match: take the host's last N labels, where N is THAT SPECIFIC
protected domain's own label count. This correctly extracts "chase" (not
"mail") when comparing "mail.chase.com" against 2-label "gmail.com", and
correctly leaves "icici.bank.in" (3 labels) alone when comparing against
other 3-label protected domains, without needing any general suffix data.

This also fixes a second, related gap: a brand name used as a SUBDOMAIN
PREFIX to impersonate ("irs.mynewsblog.net") wasn't caught, because the
old distance-based check required distance EXACTLY 1 for short cores,
excluding an exact match (distance 0). The new subdomain-prefix check
looks at exactly this case: any label BEFORE the size-matched suffix that
EXACTLY equals a protected core is flagged immediately - high precision,
since no legitimate business coincidentally names a subdomain "irs" or
"paypal".
"""
from __future__ import annotations
import unicodedata
from core.lists import _load, is_allowlisted  # reuse the same cached JSON loader
from core.wordplay import normalize_confusables, count_confusable_chars, GENERIC_SUSPICIOUS_TERMS
from core.features import COMMON_TLDS, _safe_urlparse


def _damerau_levenshtein(a: str, b: str) -> int:
    """Like Levenshtein, but an adjacent-character transposition (e.g.
    'flipkart' -> 'filpkart', swapping 'li' to 'il') counts as ONE edit,
    not two. Plain Levenshtein misses exactly this class of typosquat -
    found via testing: 'filpkart.com' scored safe because standard edit
    distance to 'flipkart' is 2, past the distance-1 threshold, even
    though a human reads it as a single obvious swap."""
    if a == b:
        return 0
    len_a, len_b = len(a), len(b)
    d = [[0] * (len_b + 1) for _ in range(len_a + 1)]
    for i in range(len_a + 1):
        d[i][0] = i
    for j in range(len_b + 1):
        d[0][j] = j
    for i in range(1, len_a + 1):
        for j in range(1, len_b + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,        # deletion
                d[i][j - 1] + 1,        # insertion
                d[i - 1][j - 1] + cost,  # substitution
            )
            if (i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]):
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)  # transposition
    return d[len_a][len_b]


def _levenshtein_no_transposition(a: str, b: str) -> int:
    """Plain Levenshtein (substitution/insertion/deletion only, no
    transposition credit) - used ALONGSIDE _damerau_levenshtein to detect
    whether a transposition was actually involved in reaching a given
    distance. If this is higher than the Damerau distance, a transposition
    was used - see _has_corroborating_signal's caller for why that
    matters: a transposition-involving distance-2 match (filpcart ->
    flipkart: swap + substitute) is a much stronger deliberate-typosquat
    signal than a pure-substitution distance-2 match (redfin/reddit,
    shopify/spotify - two coincidentally-placed different letters), so
    only the latter needs a corroborating keyword/TLD before flagging."""
    if a == b:
        return 0
    len_a, len_b = len(a), len(b)
    prev = list(range(len_b + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len_b
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _normalize_host(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    host = _safe_urlparse(url).hostname or ""
    # NFKC normalization folds fullwidth Unicode forms (e.g. 'ａ'-'ｚ') to
    # their ASCII equivalents essentially for free - closes a real gap
    # (fullwidth Unicode wasn't in HOMOGLYPH_MAP) without hand-maintaining
    # a bigger confusables table. See AUDIT_NOTES.md 3.16.
    host = unicodedata.normalize("NFKC", host)
    return host[4:] if host.startswith("www.") else host


def _size_matched_core_and_prefix(host: str, protected: str) -> tuple[str, list[str]] | None:
    """For a SPECIFIC protected domain, splits the host into (a) the core
    to compare for registrable-domain typosquatting, sized to match that
    protected domain's own label count, and (b) any leading labels beyond
    that, checked separately for subdomain-prefix abuse. Returns None if
    the host has fewer labels than the protected domain (can't meaningfully
    compare)."""
    host_labels = host.split(".")
    protected_labels = protected.split(".")
    n = len(protected_labels)
    if len(host_labels) < n:
        return None
    suffix_slice = host_labels[-n:]
    prefix_labels = host_labels[:-n] if len(host_labels) > n else []
    return suffix_slice[0], prefix_labels


def _has_corroborating_signal(url: str, host: str) -> bool:
    """For the fuzzy distance-2 branch only (5+ char cores): require a
    suspicious keyword in the path/query OR an unusual TLD alongside the
    near-miss, before treating it as a match. Found via 100K-URL
    evaluation: without this, coincidental collisions between distinct
    real companies whose names happen to sit distance-2 apart
    (redfin.com/reddit.com, shopify.com/spotify.com, slate.com/slack.com,
    usbank.com/yesbank.in) get flagged with no other evidence. Every
    actual reported attack in this distance class (filpkart.com,
    filpcart.com) carried a suspicious path or was tested standalone
    without this gate, but a REAL attack of this shape would essentially
    always pair the near-miss domain with a credential-harvesting path or
    a free/unusual TLD - a bare, path-less near-miss with an ordinary TLD
    and no suspicious wording is far more likely a coincidental real
    company than an active attack."""
    parsed = _safe_urlparse(url if "://" in url else "http://" + url)
    path_query = f"{parsed.path or ''} {parsed.query or ''}".lower()
    normalized_path_query = normalize_confusables(path_query)
    has_keyword = any(
        term in path_query or term in normalized_path_query
        for term in GENERIC_SUSPICIOUS_TERMS
    )
    tld = host.split(".")[-1] if "." in host else host
    has_unusual_tld = tld not in COMMON_TLDS
    return has_keyword or has_unusual_tld


def find_typosquat_match(url: str, max_distance: int = 2) -> str | None:
    """Returns the protected domain this URL suspiciously resembles, or
    None. Two independent checks, both against every protected domain:
    (1) registrable-core typosquat (near-miss of the actual domain), and
    (2) subdomain-prefix abuse (protected brand name used as a label
    before the real registrable domain, e.g. 'irs.mynewsblog.net')."""
    host = _normalize_host(url)
    if not host:
        return None
    if is_allowlisted(url):
        return None  # a real protected domain is never "its own typosquat"

    protected_domains = _load("allowlist")["domains"]

    for protected in protected_domains:
        if host == protected:
            continue  # exact match is legitimate, not a typosquat
        match = _size_matched_core_and_prefix(host, protected)
        if match is None:
            continue
        host_core, prefix_labels = match
        protected_core = protected.split(".")[0]

        # --- Check 1: subdomain-prefix abuse (exact match only - high
        # precision, catches "irs.mynewsblog.net" style impersonation) ---
        if any(label == protected_core for label in prefix_labels):
            return protected

        # --- Check 2: registrable-core typosquat (fuzzy, same rules as
        # before, now operating on the CORRECTLY size-matched core) ---
        if len(protected_core) < 3:
            continue  # too short/generic to ever compare safely (e.g. "co")
        if len(protected_core) <= 4:
            if len(host_core) != len(protected_core):
                continue
            if _damerau_levenshtein(host_core, protected_core) == 1:
                return protected
            continue
        if abs(len(host_core) - len(protected_core)) > 1:
            continue
        distance = _damerau_levenshtein(host_core, protected_core)
        if distance == 1:
            return protected  # distance-1 on a long core is unambiguous, no gate needed
        if distance == 2:
            transposition_involved = (
                _levenshtein_no_transposition(host_core, protected_core) > distance
            )
            if transposition_involved or _has_corroborating_signal(url, host):
                return protected

        # --- Check 3: leetspeak/homoglyph normalized exact match ---
        if count_confusable_chars(host_core) > 0:
            if normalize_confusables(host_core) == protected_core:
                return protected

    return None
