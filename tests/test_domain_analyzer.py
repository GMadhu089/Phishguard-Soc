"""
Tests for src/analysis/domain_analyzer.py
"""

from src.analysis.domain_analyzer import analyze_domain


def test_legitimate_brand_domain_not_flagged():
    """
    WHAT: The real, official domain for a watched brand.
    WHY: Must never flag a brand's own legitimate domain as impersonation.
    EXPECTED: No brand-related heuristic flags.
    """
    result = analyze_domain("paypal.com")
    assert result.heuristic_flags == []
    assert result.brand_token_found is None


def test_brand_token_substring_flagged():
    """
    WHAT: A domain containing a brand name as a literal substring, but
         not the brand's real domain (e.g. 'microsoft-login-example.test').
    WHY: RULE-009's primary signal.
    EXPECTED: brand_token_found == 'microsoft'.
    """
    result = analyze_domain("microsoft-login-example.test")
    assert result.brand_token_found == "microsoft"


def test_typosquat_character_substitution_flagged():
    """
    WHAT: A character-substitution typosquat that a literal substring
         check would miss ('paypa1' with a '1' instead of 'l').
    WHY: Regression test — this exact case was found to silently fail
         during development until edit-distance matching was added.
    EXPECTED: brand_token_found == 'paypal' via typosquat detection.
    """
    result = analyze_domain("paypa1-secure.test")
    assert result.brand_token_found == "paypal"
    assert any("typosquat_suspected" in f for f in result.heuristic_flags)


def test_unrelated_domain_not_flagged():
    """
    WHAT: A domain with no relation to any watched brand.
    WHY: Must not false-positive on ordinary domains.
    EXPECTED: No brand flags.
    """
    result = analyze_domain("mycompany-payroll.com")
    assert result.brand_token_found is None


def test_suspicious_tld_flagged():
    """
    WHAT: A domain using a TLD commonly associated with low-cost/abused registrations.
    WHY: Feeds local heuristic evidence; not proof on its own.
    EXPECTED: A 'suspicious_tld_...' flag present.
    """
    result = analyze_domain("free-prize-claim.xyz")
    assert any(f.startswith("suspicious_tld_") for f in result.heuristic_flags)


def test_excessive_subdomains_flagged():
    """
    WHAT: A domain with many dot-separated labels.
    WHY: Excessive subdomains are a known evasion pattern.
    EXPECTED: 'excessive_subdomains' flag present.
    """
    result = analyze_domain("login.secure.account.verify.example.test")
    assert "excessive_subdomains" in result.heuristic_flags


def test_empty_domain_does_not_crash():
    """
    WHAT: An empty string domain (e.g. a URL that failed to parse a hostname).
    WHY: Must never raise on missing/empty input.
    EXPECTED: Empty flags list, no exception.
    """
    result = analyze_domain("")
    assert result.heuristic_flags == []


def test_result_always_labeled_local_heuristic():
    """
    WHAT: Any domain analysis result.
    WHY: Per project design, this module's output must never be
         confused with a threat-intelligence (VirusTotal) result.
    EXPECTED: label_source == 'local_heuristic'.
    """
    result = analyze_domain("example.com")
    assert result.label_source == "local_heuristic"
