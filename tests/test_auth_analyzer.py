"""
Tests for src/analysis/auth_analyzer.py
"""

from src.analysis.auth_analyzer import analyze_authentication


def test_spf_pass_is_parsed():
    """
    WHAT: Authentication-Results containing spf=pass.
    WHY: SPF pass is the most common real-world case; must parse cleanly.
    EXPECTED: spf.result == 'pass'.
    """
    result = analyze_authentication(["mx.example.com; spf=pass smtp.mailfrom=example.com"])
    assert result.spf.result == "pass"


def test_spf_fail_is_parsed_but_not_flagged_malicious():
    """
    WHAT: Authentication-Results containing spf=fail.
    WHY: Per project design, SPF fail must be reported as a fact, not
         escalated to a verdict inside this module (that's the detection
         engine's job, built later, with correlation).
    EXPECTED: spf.result == 'fail'; no field on AuthAnalysis claims
              maliciousness.
    """
    result = analyze_authentication(["mx.example.com; spf=fail smtp.mailfrom=example.test"])
    assert result.spf.result == "fail"
    assert not hasattr(result, "is_malicious")


def test_dkim_pass_with_domain_and_selector():
    """
    WHAT: Authentication-Results with dkim=pass and header.d=/header.s=.
    WHY: Domain and selector feed IOC extraction and correlation later.
    EXPECTED: dkim.result == 'pass'; domain and selector correctly captured.
    """
    header = "mx.example.com; dkim=pass header.d=example.com header.s=default"
    result = analyze_authentication([header])
    assert result.dkim.result == "pass"
    assert result.dkim.domain == "example.com"
    assert result.dkim.selector == "default"


def test_dkim_fail_is_parsed():
    """
    WHAT: Authentication-Results with dkim=fail.
    WHY: Must be captured as a fact for the detection engine to weigh.
    EXPECTED: dkim.result == 'fail'.
    """
    result = analyze_authentication(["mx.example.com; dkim=fail header.d=example.test"])
    assert result.dkim.result == "fail"


def test_dmarc_pass_is_parsed():
    """
    WHAT: Authentication-Results with dmarc=pass and a policy.
    WHY: Baseline correctness for the most common legitimate case.
    EXPECTED: dmarc.result == 'pass'; policy captured.
    """
    result = analyze_authentication(["mx.example.com; dmarc=pass (p=reject) header.from=example.com"])
    assert result.dmarc.result == "pass"
    assert result.dmarc.policy == "reject"


def test_dmarc_fail_is_parsed():
    """
    WHAT: Authentication-Results with dmarc=fail.
    WHY: Must be captured as a fact, not auto-escalated to malicious here.
    EXPECTED: dmarc.result == 'fail'.
    """
    result = analyze_authentication(["mx.example.com; dmarc=fail (p=reject) header.from=example.test"])
    assert result.dmarc.result == "fail"


def test_missing_authentication_results_returns_none_not_crash():
    """
    WHAT: No Authentication-Results header at all (empty list passed in).
    WHY: Some samples (misconfigured relays, incomplete forwards) lack this
         header entirely; the tool must not crash on real-world gaps.
    EXPECTED: All three results are None; no exception raised.
    """
    result = analyze_authentication([])
    assert result.spf.result is None
    assert result.dkim.result is None
    assert result.dmarc.result is None


def test_dmarc_alignment_note_detects_misalignment():
    """
    WHAT: DMARC header.from domain differs from the visible From address domain.
    WHY: From/DMARC misalignment is a useful correlation signal for the
         detection engine (RULE-004 territory), so it must be computed
         correctly here.
    EXPECTED: dmarc_alignment_note reports 'misaligned'.
    """
    header = "mx.example.com; dmarc=fail (p=reject) header.from=example.com"
    result = analyze_authentication([header], from_header="Someone <attacker@example.test>")
    assert "misaligned" in result.dmarc_alignment_note
