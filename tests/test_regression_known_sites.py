"""
tests/test_regression_known_sites.py
=====================================
This is the test that would have caught the legacy bug BEFORE it shipped.
Run it in CI on every PR and every retrain; a failure here blocks deploy.

Includes the exact URLs from the audit screenshots that were incorrectly
flagged "UNSAFE": perplexity.ai, discord.com, india.gov.in, icici.bank.in.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

# These four are the exact failures from the audit screenshots.
SCREENSHOT_REGRESSION_CASES = [
    "https://www.perplexity.ai/",
    "https://discord.com/",
    "https://www.india.gov.in/",
    "https://www.icici.bank.in",
]

ADDITIONAL_KNOWN_BENIGN = [
    "https://www.google.com/",
    "https://en.wikipedia.org/wiki/Main_Page",
    "https://github.com/",
    "https://www.microsoft.com/",
    "https://www.amazon.com/",
    "https://www.reddit.com/",
    "https://www.linkedin.com/",
    "https://www.apple.com/",
    "https://www.youtube.com/",
    "https://www.sbi.co.in/",
    "https://www.rbi.org.in/",
    "https://www.irs.gov/",
]

# Generic, non-brand-specific structural phishing patterns (not modeled on
# any single real company) - testing that obviously suspicious STRUCTURE
# is still caught, so the fix isn't "just allowlist everything."
SYNTHETIC_SUSPICIOUS_CASES = [
    "http://secure-verify-account-update.tk/login/confirm.php?user=1&id=39fh2k",
    "http://192.168.10.5/wp-admin/login.php?redirect=confirm",
    "http://account-signin-verify.ml/secure/banking/update.php?token=8x92kf",
    "http://login.confirm-secure.ga/verify/account.php?session=aa11bb22cc",
]


@pytest.mark.parametrize("url", SCREENSHOT_REGRESSION_CASES)
def test_screenshot_regressions_are_now_safe(url):
    resp = client.post("/api/check", json={"url": url})
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "safe", (
        f"REGRESSION: {url} flagged '{data['verdict']}' via stage={data['stage']} "
        f"(confidence={data.get('confidence')}). This is one of the exact URLs "
        f"that was wrong in the legacy system."
    )
    # The response must echo back exactly what was checked - this is the
    # direct test for the "Checked URL doesn't match input" bug.
    assert data["checked_url"] == url


@pytest.mark.parametrize("url", ADDITIONAL_KNOWN_BENIGN)
def test_additional_known_benign_sites(url):
    resp = client.post("/api/check", json={"url": url})
    data = resp.json()
    assert data["verdict"] == "safe", f"{url} -> {data}"


@pytest.mark.parametrize("url", SYNTHETIC_SUSPICIOUS_CASES)
def test_synthetic_suspicious_structure_still_caught(url):
    """Guards against overcorrecting into 'allowlist everything.' These are
    synthetic, generic patterns - not modeled on any specific real brand."""
    resp = client.post("/api/check", json={"url": url})
    data = resp.json()
    assert data["verdict"] == "unsafe", f"{url} -> {data}"


def test_response_always_echoes_the_request_url():
    """Direct regression test for screenshot 4's state bug: fire two
    different URLs and confirm each response matches ITS OWN request,
    never a previous one."""
    r1 = client.post("/api/check", json={"url": "https://www.india.gov.in/"})
    r2 = client.post("/api/check", json={"url": "https://www.icici.bank.in"})
    assert r1.json()["checked_url"] == "https://www.india.gov.in/"
    assert r2.json()["checked_url"] == "https://www.icici.bank.in"


BROADER_REAL_WORLD_SWEEP = [
    "https://www.yesbank.in/", "https://www.idfcfirstbank.com/", "https://www.bankofbaroda.in/",
    "https://www.pnbindia.in/", "https://www.kotak.com/", "https://www.hdfcbank.com/",
    "https://www.globalgiving.ngo/", "https://www.techsoup.ngo/", "https://elevenlabs.io/",
    "https://www.notion.so/", "https://openai.com/", "https://www.who.int/",
    "https://www.doctorswithoutborders.org/", "https://www.whitehouse.gov/",
    "https://www.icicibank.com/", "https://www.axisbank.com/",
]


def test_broader_real_world_sweep_mostly_safe():
    """A wider, less hand-picked sweep than the curated lists above -
    guards against the kind of broad regression found 2026-07-07, where a
    small augmentation set fixed the exact reported cases but nothing else.
    Not 100% yet (paths on unaugmented domains remain a known limitation) -
    this asserts the CURRENT honest bar, not aspirational perfection, and
    should be tightened as coverage improves."""
    results = {}
    for url in BROADER_REAL_WORLD_SWEEP:
        resp = client.post("/api/check", json={"url": url})
        results[url] = resp.json()["verdict"]
    wrong = [u for u, v in results.items() if v != "safe"]
    assert len(wrong) <= 1, f"Regression: too many false positives: {wrong}"


def test_typosquat_of_known_bank_is_caught():
    """The exact gap the user found: 'sbl.co.in' (one character off from
    the allowlisted 'sbi.co.in') was scored SAFE at 0.06% phishing
    probability by the ML model alone, because it's structurally clean.
    core/typosquat.py catches this as a deterministic rule."""
    resp = client.post("/api/check", json={"url": "https://www.sbl.co.in/"})
    data = resp.json()
    assert data["verdict"] == "unsafe"
    assert data["stage"] == "typosquat"


def test_real_short_bank_codes_dont_falsely_flag_each_other():
    """sbi.co.in and rbi.org.in are both real, both allowlisted, and are
    edit-distance-1 from each other's brand core - neither should be
    flagged just for existing."""
    for url in ["https://www.sbi.co.in/", "https://www.rbi.org.in/"]:
        resp = client.post("/api/check", json={"url": url})
        assert resp.json()["verdict"] == "safe", f"{url} -> {resp.json()}"


def test_transposition_typosquat_is_caught():
    """User-reported gap: 'filpkart.com' (flipkart with 'li' and 'il'
    swapped - a transposition) scored SAFE at 1.0%, because standard edit
    distance counts a transposition as 2 edits, past the old distance-1
    threshold. core/typosquat.py now uses Damerau-Levenshtein (counts an
    adjacent transposition as ONE edit) and flipkart.com is in the
    allowlist. Also covers the compound case: 'filpcart.com' (transposition
    AND a substitution, k->c)."""
    for url, expected_match in [
        ("https://filpkart.com/", "flipkart.com"),
        ("https://filpcart.com/", "flipkart.com"),
        ("https://lnstagram.com/", "instagram.com"),
    ]:
        resp = client.post("/api/check", json={"url": url})
        data = resp.json()
        assert data["verdict"] == "unsafe", f"{url} -> {data}"
        assert data["stage"] == "typosquat", f"{url} -> {data}"


def test_similar_real_brands_dont_false_flag_each_other():
    """Found during testing: a looser distance threshold needed to catch
    transpositions almost caused 'slacker.com' (a real, different company)
    to be flagged as a typosquat of 'slack.com'. Locks in the fix."""
    for url in ["https://slacker.com/", "https://instacart.com/",
                "https://instapaper.com/", "https://zoomcar.com/"]:
        resp = client.post("/api/check", json={"url": url})
        assert resp.json()["stage"] != "typosquat", f"{url} -> {resp.json()}"


def test_mail_subdomain_not_falsely_flagged_as_gmail_typosquat():
    """Bug found in 100K-URL model evaluation: _brand_core() used to take
    hostname.split('.')[0] with no registrable-domain awareness, so ANY
    company's mail.* subdomain extracted core 'mail' - one edit from
    'gmail'. Any ordinary company's mail subdomain got accused of
    impersonating Gmail. Confirmed live for mail.skrill.com, mail.shein.com,
    mail.chase.com in the evaluation; this locks in the fix."""
    for url in ["https://mail.chase.com/", "https://mail.skrill.com/",
                "https://mail.example-company.com/"]:
        resp = client.post("/api/check", json={"url": url})
        assert resp.json()["stage"] != "typosquat", f"{url} -> {resp.json()}"


def test_brand_name_as_subdomain_prefix_is_caught():
    """The other side of the same bug: 'irs.mynewsblog.net' - a protected
    brand's name used as a subdomain PREFIX of an unrelated domain, to
    superficially look IRS-related. Confirmed in the security assessment
    as an undetected gap (excluded by the old 'distance must be exactly 1'
    rule, since this is an exact match). Now caught via the dedicated
    subdomain-prefix check."""
    resp = client.post("/api/check", json={"url": "https://irs.mynewsblog.net/"})
    data = resp.json()
    assert data["verdict"] == "unsafe"
    assert data["stage"] == "typosquat"


def test_coincidental_brand_collisions_not_flagged_without_corroboration():
    """100K-URL evaluation found these as false positives: distinct real
    companies whose names happen to sit distance-2 apart from a protected
    brand, with no other suspicious signal. A bare domain with no
    suspicious path/TLD is far more likely a coincidental real company
    than an active attack."""
    for url in ["https://redfin.com/", "https://shopify.com/",
                "https://slate.com/", "https://usbank.com/"]:
        resp = client.post("/api/check", json={"url": url})
        assert resp.json()["stage"] != "typosquat", f"{url} -> {resp.json()}"


def test_transposition_attacks_bypass_corroboration_gate():
    """filpcart.com (the user's original reported attack - transposition
    'li'->'il' PLUS a substitution 'k'->'c') has NO suspicious path or
    TLD, unlike what the corroboration-gate recommendation assumed. A
    transposition-involving distance-2 match is unambiguous enough on its
    own (see core/typosquat.py's _levenshtein_no_transposition check) -
    this must keep working even without any corroborating signal."""
    for url in ["https://filpkart.com/", "https://filpcart.com/"]:
        resp = client.post("/api/check", json={"url": url})
        data = resp.json()
        assert data["verdict"] == "unsafe", f"{url} -> {data}"
        assert data["stage"] == "typosquat", f"{url} -> {data}"


def test_augmentation_generalizes_to_unaugmented_domains():
    """100K-URL evaluation proved the old ~69-URL augmentation set caused
    MEMORIZATION: numpy.org (never augmented, same shape as the heavily
    augmented pandas.pydata.org) scored 99.94% phishing. After expanding
    to ~144 URLs across ~94 distinct domains and cutting replication from
    40x to 8x, this must now score as safe - genuine generalization, not
    memorization of the pandas.pydata.org strings specifically."""
    resp = client.post("/api/check", json={
        "url": "https://numpy.org/doc/stable/reference/generated/numpy.mean.html"
    })
    data = resp.json()
    assert data["verdict"] == "safe", (
        f"Regression: augmentation may have collapsed back to memorization. Got {data}"
    )
