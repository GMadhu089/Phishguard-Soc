"""
domain_analyzer.py

Local, offline heuristic checks on a domain string. These are HEURISTICS —
patterns that correlate with (but do not prove) suspicious domains. Every
result from this module is labeled as a local heuristic so it is never
confused with a THREAT INTELLIGENCE result (which comes from
src/intelligence/virustotal.py and reflects actual external data).

This module does NOT and CANNOT determine domain registration age,
reputation, or WHOIS data — that would require an external service. If
asked for domain age, the honest answer is "not implemented without an
external data source."
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.utils.logger import get_logger

logger = get_logger(__name__)

_SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "work", "loan", "gq", "tk", "ml",
}

# A very small set of common brand tokens, used only to flag a domain that
# CONTAINS a brand name it does not officially belong to (e.g.
# "microsoft-login-example.test"). Not a trademark or ownership database.
_BRAND_TOKENS = [
    "microsoft", "office365", "google", "paypal", "apple", "amazon",
    "netflix", "bankofamerica", "wellsfargo", "docusign",
]

# Domains that legitimately use a brand token are not flagged if the token
# is immediately followed by the correct public suffix (best-effort check,
# not a full public-suffix-list implementation).
_LEGITIMATE_BRAND_DOMAINS = {
    "microsoft.com", "office365.com", "google.com", "paypal.com",
    "apple.com", "amazon.com", "netflix.com", "bankofamerica.com",
    "wellsfargo.com", "docusign.com", "docusign.net",
}


@dataclass
class DomainHeuristicResult:
    domain: str
    heuristic_flags: list[str] = field(default_factory=list)
    label_source: str = "local_heuristic"  # always explicit; never confused with threat intel
    brand_token_found: str | None = None


def analyze_domain(domain: str) -> DomainHeuristicResult:
    domain = (domain or "").strip().lower()
    result = DomainHeuristicResult(domain=domain)

    if not domain:
        return result

    if len(domain) > 40:
        result.heuristic_flags.append("unusually_long_domain")

    subdomain_count = domain.count(".")
    if subdomain_count >= 3:
        result.heuristic_flags.append("excessive_subdomains")

    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        result.heuristic_flags.append("hyphen_heavy_domain")

    if domain.startswith("xn--") or ".xn--" in domain:
        result.heuristic_flags.append("punycode_domain")

    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in _SUSPICIOUS_TLDS:
        result.heuristic_flags.append(f"suspicious_tld_.{tld}")

    brand = _find_brand_impersonation(domain)
    if brand:
        result.brand_token_found = brand
        result.heuristic_flags.append(f"brand_token_present_but_domain_not_official:{brand}")
    else:
        typo_brand = _find_typosquat(domain)
        if typo_brand:
            result.brand_token_found = typo_brand
            result.heuristic_flags.append(f"typosquat_suspected:{typo_brand}")

    if _looks_like_ip(domain):
        result.heuristic_flags.append("domain_is_raw_ip")

    return result


def _find_brand_impersonation(domain: str) -> str | None:
    if domain in _LEGITIMATE_BRAND_DOMAINS:
        return None

    for brand in _BRAND_TOKENS:
        if brand in domain:
            return brand
    return None


def _looks_like_ip(domain: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))


def _find_typosquat(domain: str) -> str | None:
    """
    Catches character-substitution / character-insertion typosquats that a
    literal substring check misses, e.g. 'paypa1-secure.test' vs 'paypal'
    (edit distance 1: '1' substituted for 'l').

    Compares the first dot-separated label of the domain (the part before
    the first '.') against each watched brand token. A small edit distance
    (<= 2) on a similarly-sized string is flagged as a suspected typosquat.
    This is a local heuristic, not a domain-registration or brand-protection
    database lookup, and can occasionally misfire on short, coincidentally
    similar legitimate domain names.
    """
    first_label = domain.split(".", 1)[0]
    # Split on hyphens too: typosquats commonly append "-secure", "-login",
    # etc., and we want to compare the brand-like token in isolation
    # (e.g. "paypa1" out of "paypa1-secure"), not the whole hyphenated label.
    tokens = first_label.split("-")

    for brand in _BRAND_TOKENS:
        if len(brand) < 5:
            continue  # too short: edit-distance checks on short strings are noisy
        for token in tokens:
            if abs(len(token) - len(brand)) > 2:
                continue  # skip tokens too different in length to be a close typo
            distance = _levenshtein_distance(token, brand)
            if 0 < distance <= 2:
                return brand
    return None


def _levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (char_a != char_b)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row

    return previous_row[-1]
