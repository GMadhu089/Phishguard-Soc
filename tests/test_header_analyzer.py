"""
Tests for src/analysis/header_analyzer.py
"""

from src.analysis.header_analyzer import analyze_headers


def test_reply_to_mismatch_detected():
    """
    WHAT: From and Reply-To addresses on different domains.
    WHY: This is RULE-001's core signal; must be detected reliably.
    EXPECTED: from_reply_to_mismatch is True with correct domains recorded.
    """
    result = analyze_headers(
        from_header="Billing <billing@example.com>",
        reply_to_header="support@example.test",
    )
    assert result.from_reply_to_mismatch is True
    assert result.from_domain == "example.com"
    assert result.reply_to_domain == "example.test"


def test_no_mismatch_when_domains_match():
    """
    WHAT: From and Reply-To on the same domain.
    WHY: Must not false-positive on the overwhelmingly common legitimate case.
    EXPECTED: from_reply_to_mismatch is False.
    """
    result = analyze_headers(
        from_header="IT <it@example.com>",
        reply_to_header="it@example.com",
    )
    assert result.from_reply_to_mismatch is False


def test_missing_reply_to_does_not_crash():
    """
    WHAT: No Reply-To header at all.
    WHY: Most legitimate emails have no Reply-To; must not raise or falsely flag.
    EXPECTED: from_reply_to_mismatch is False; reply_to_domain is None.
    """
    result = analyze_headers(from_header="a@example.com", reply_to_header=None)
    assert result.from_reply_to_mismatch is False
    assert result.reply_to_domain is None


def test_suspicious_display_name_brand_mismatch():
    """
    WHAT: Display name claims 'Microsoft' but sends from an unrelated domain.
    WHY: Classic brand-impersonation display-name spoof; feeds RULE-009-adjacent evidence.
    EXPECTED: suspicious_display_name True, claimed brand and actual domain recorded.
    """
    result = analyze_headers(
        from_header="Microsoft Account Team <account-security@example.com>",
        reply_to_header=None,
    )
    assert result.suspicious_display_name is True
    assert result.display_name_claimed_brand == "microsoft"
    assert result.display_name_actual_domain == "example.com"


def test_legitimate_brand_domain_not_flagged():
    """
    WHAT: Display name claims 'Microsoft' AND sends from an actual microsoft.com address.
    WHY: Must not flag the brand's own legitimate mail.
    EXPECTED: suspicious_display_name is False.
    """
    result = analyze_headers(
        from_header="Microsoft Account Team <no-reply@microsoft.com>",
        reply_to_header=None,
    )
    assert result.suspicious_display_name is False


def test_external_sender_flag_with_recipient_domain():
    """
    WHAT: recipient_domain is provided and differs from the From domain.
    WHY: Some deployments know their own org domain and want an explicit
         internal-vs-external signal.
    EXPECTED: external_sender is True.
    """
    result = analyze_headers(
        from_header="a@example.test",
        reply_to_header=None,
        recipient_domain="example.com",
    )
    assert result.external_sender is True


def test_external_sender_unknown_without_recipient_domain():
    """
    WHAT: recipient_domain not provided (the common CLI case, since the
         tool doesn't always know the org's own domain).
    WHY: Must not guess; unknown should stay unknown rather than default
         to True or False.
    EXPECTED: external_sender is None.
    """
    result = analyze_headers(from_header="a@example.test", reply_to_header=None)
    assert result.external_sender is None
