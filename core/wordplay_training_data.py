"""
core/wordplay_training_data.py
================================
PhiUSIIL almost certainly has few or no examples of leetspeak/homoglyph
character-substitution phishing (it predates this being flagged as a gap
here), so the new features in core/features.py (has_mixed_script,
is_punycode, num_confusable_chars, domain_has_obfuscated_suspicious_term)
would have no real training signal to learn from without this. This
generates synthetic-but-structurally-realistic examples of the ATTACK
TECHNIQUE - not scraped from anywhere, not modeled on any single real
phishing campaign - purely mechanical substitution applied to generic
terms and (separately) to already-public brand names from our own
allowlist, which is standard, legitimate ML security practice (adversarial
data augmentation), the same category of thing as the SYNTHETIC_SUSPICIOUS
test cases already in tests/.

Equally important: generates LEGITIMATE counter-examples (1Password,
9gag, Web3 Foundation, etc.) so the model learns to distinguish
deliberate obfuscation from ordinary numeric branding, rather than
over-penalizing any digit-near-letters pattern - see AUDIT_NOTES.md 3.15
for the 1Password false-positive this caught during testing.
"""
import random
from core.wordplay import GENERIC_SUSPICIOUS_TERMS

random.seed(42)  # reproducible training data across runs

LEET_GEN_MAP = {"e": "3", "a": "4", "o": "0", "i": "1", "s": "5", "t": "7"}

SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "top", "xyz"]
NEUTRAL_TLDS = ["com", "net", "info", "online"]

BRAND_CORES_SAMPLE = [
    "google", "amazon", "instagram", "facebook", "paypal", "flipkart",
    "netflix", "microsoft", "apple", "whatsapp", "linkedin", "dropbox",
]

# Cyrillic homoglyphs for a few brands - real IDN-homograph-style examples
HOMOGLYPH_BRANDS = {
    "google": "gооgle",     # Cyrillic о
    "amazon": "аmazon",     # Cyrillic а
    "paypal": "paypаl",     # Cyrillic а
    "facebook": "facebооk",  # Cyrillic о
}


def _leetspeak_variant(word: str, rate: float = 0.5) -> str:
    """Substitutes SOME (not all) substitutable letters - phishers
    typically obfuscate a character or two, not the whole word, since
    over-obfuscating makes the deception less convincing to a human."""
    chars = list(word)
    substitutable = [i for i, c in enumerate(chars) if c in LEET_GEN_MAP]
    if not substitutable:
        return word
    n_to_sub = max(1, int(len(substitutable) * rate))
    for i in random.sample(substitutable, min(n_to_sub, len(substitutable))):
        chars[i] = LEET_GEN_MAP[chars[i]]
    return "".join(chars)


def generate_phishing_examples() -> list[str]:
    urls = []

    # Generic suspicious terms, leetspeak-obfuscated, in both domain and
    # path positions - this is the general (not brand-specific) case.
    for term in GENERIC_SUSPICIOUS_TERMS:
        for _ in range(3):
            variant = _leetspeak_variant(term)
            if variant == term:
                continue
            tld = random.choice(SUSPICIOUS_TLDS + NEUTRAL_TLDS)
            # domain-level obfuscation
            urls.append(f"http://{variant}-portal.{tld}/")
            urls.append(f"http://user-{variant}.{tld}/index.php")
            # path-level obfuscation
            other_term = random.choice(GENERIC_SUSPICIOUS_TERMS)
            urls.append(f"http://myaccount-support.{tld}/{variant}/{other_term}.php?id={random.randint(1000,9999)}")

    # Brand impersonation via leetspeak
    for brand in BRAND_CORES_SAMPLE:
        for _ in range(3):
            variant = _leetspeak_variant(brand, rate=0.4)
            if variant == brand:
                continue
            tld = random.choice(SUSPICIOUS_TLDS + NEUTRAL_TLDS)
            urls.append(f"http://{variant}.{tld}/")
            urls.append(f"http://{variant}-support.{tld}/login")
            urls.append(f"http://secure-{variant}.{tld}/account/verify")

    # Brand impersonation via Unicode homoglyphs
    for brand, homoglyph_variant in HOMOGLYPH_BRANDS.items():
        tld = random.choice(NEUTRAL_TLDS)
        urls.append(f"http://{homoglyph_variant}.{tld}/")
        urls.append(f"http://{homoglyph_variant}.{tld}/login")

    # A few realistic punycode-style examples (structurally representative
    # xn-- prefixed hosts, as a real IDN-homograph URL would appear)
    punycode_examples = [
        "xn--pypal-4ve.com", "xn--gogle-qta.com", "xn--mazon-3ve.com",
    ]
    for host in punycode_examples:
        urls.append(f"http://{host}/")
        urls.append(f"http://{host}/secure/login")

    return urls


def generate_legitimate_counter_examples() -> list[str]:
    """Real, legitimate domains that would trip a naive digit-substitution
    or suspicious-keyword heuristic if the model isn't taught the
    distinction. Found via testing: 1password.com legitimately normalizes
    to contain 'password' after leetspeak normalization - without this,
    the new features would likely over-penalize real numeric branding."""
    return [
        "https://1password.com/",
        "https://1password.com/features",
        "https://www.9gag.com/",
        "https://web3.foundation/",
        "https://auth0.com/",
        "https://auth0.com/docs",
        "https://id.me/",
        "https://www.23andme.com/",
        "https://c3.ai/",
        "https://www.office365.com/",
        "https://www.windows11.com/",
        "https://www.7-eleven.com/",
        "https://www.4chan.org/",
        "https://www.w3.org/",
        "https://www.3m.com/",
        "https://www.20thcenturystudios.com/",
    ]
