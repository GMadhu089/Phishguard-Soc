"""
Tests for src/analysis/url_analyzer.py
"""

from src.analysis.url_analyzer import extract_urls_from_html, extract_urls_from_text


def test_extract_url_from_plain_text():
    """
    WHAT: A plain-text body containing one bare URL.
    WHY: Baseline extraction correctness.
    EXPECTED: Exactly one URL extracted with source 'text'.
    """
    urls = extract_urls_from_text("Please visit https://example.test/reset for details.")
    assert len(urls) == 1
    assert urls[0].url == "https://example.test/reset"
    assert urls[0].source == "text"


def test_visible_href_mismatch_detected():
    """
    WHAT: An HTML anchor whose visible text is one URL/domain but whose
         href points somewhere else entirely.
    WHY: This is the single strongest phishing indicator this module
         produces (RULE-006). Must be detected reliably.
    EXPECTED: visible_href_mismatch is True and 'visible_href_mismatch' is
              in suspicious_flags for that URL.
    """
    html = '<a href="https://attacker-example.test/login">https://www.microsoft.com</a>'
    urls = extract_urls_from_html(html)
    assert len(urls) == 1
    assert urls[0].visible_href_mismatch is True
    assert "visible_href_mismatch" in urls[0].suspicious_flags


def test_no_mismatch_when_visible_text_is_not_a_url():
    """
    WHAT: An HTML anchor with ordinary prose as visible text ("Click here").
    WHY: Opaque link text is a much weaker, different signal and must NOT
         be classified as a visible/href mismatch (that would inflate
         false positives on virtually every legitimate email with a button).
    EXPECTED: visible_href_mismatch is False.
    """
    html = '<a href="https://example.com/reset">Click here to reset your password</a>'
    urls = extract_urls_from_html(html)
    assert len(urls) == 1
    assert urls[0].visible_href_mismatch is False


def test_no_mismatch_when_visible_and_href_agree():
    """
    WHAT: Visible text is a URL and matches the actual href.
    WHY: Must not false-positive on the common case of a URL literally
         shown as its own link text.
    EXPECTED: visible_href_mismatch is False.
    """
    html = '<a href="https://example.com/page">https://example.com/page</a>'
    urls = extract_urls_from_html(html)
    assert urls[0].visible_href_mismatch is False


def test_www_prefix_does_not_cause_false_mismatch():
    """
    WHAT: Visible text has a 'www.' prefix the href lacks (or vice versa),
         otherwise the same host.
    WHY: Regression test for a real bug found during development: an
         earlier implementation used str.lstrip('www.') which strips
         characters, not the literal prefix, corrupting hosts like
         'wallet.com' into 'allet.com' and causing false mismatches.
    EXPECTED: No mismatch flagged when only the www. prefix differs.
    """
    html = '<a href="https://example.com/page">https://www.example.com/page</a>'
    urls = extract_urls_from_html(html)
    assert urls[0].visible_href_mismatch is False


def test_wallet_domain_not_corrupted_by_www_stripping():
    """
    WHAT: A host beginning with 'w' that is NOT a www-prefixed host
         (e.g. 'wallet.example.test').
    WHY: Same regression as above — guards against character-based
         stripping silently truncating real hostnames.
    EXPECTED: hostname is preserved exactly as 'wallet.example.test'.
    """
    html = '<a href="https://wallet.example.test/pay">https://wallet.example.test/pay</a>'
    urls = extract_urls_from_html(html)
    assert urls[0].hostname == "wallet.example.test"
    assert urls[0].visible_href_mismatch is False


def test_ip_based_url_flagged():
    """
    WHAT: A URL whose host is a raw IPv4 address.
    WHY: IP-based URLs in email are unusual and a known phishing pattern
         (bypassing domain-based blocklists).
    EXPECTED: 'ip_based_url' in suspicious_flags.
    """
    urls = extract_urls_from_text("Login at http://203.0.113.5/login")
    assert "ip_based_url" in urls[0].suspicious_flags


def test_known_shortener_flagged():
    """
    WHAT: A URL using a known shortener domain.
    WHY: Shorteners obscure the true destination — a common phishing
         evasion technique, though also used legitimately.
    EXPECTED: 'known_shortener' in suspicious_flags.
    """
    urls = extract_urls_from_text("Click https://bit.ly/abc123")
    assert "known_shortener" in urls[0].suspicious_flags


def test_no_urls_returns_empty_list_not_crash():
    """
    WHAT: Empty text and HTML bodies.
    WHY: Many benign emails have no links at all; must not crash on empty input.
    EXPECTED: Both functions return an empty list.
    """
    assert extract_urls_from_text("") == []
    assert extract_urls_from_html("") == []


def test_at_symbol_userinfo_trick_flagged():
    """
    WHAT: A URL using the userinfo@host trick, e.g.
         https://www.microsoft.com@attacker.test/.
    WHY: Classic obfuscation where everything before '@' is ignored by the
         browser as userinfo, and the real host is after '@'.
    EXPECTED: 'at_symbol_in_url' in suspicious_flags.
    """
    urls = extract_urls_from_text("Visit https://www.microsoft.com@attacker.test/login")
    assert "at_symbol_in_url" in urls[0].suspicious_flags
