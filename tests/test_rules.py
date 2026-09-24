"""
Tests for src/detection/rules.py
"""

from src.analysis.attachment_analyzer import AttachmentAnalysis
from src.analysis.auth_analyzer import DKIMResult, DMARCResult, SPFResult, AuthAnalysis
from src.analysis.domain_analyzer import DomainHeuristicResult
from src.analysis.header_analyzer import HeaderAnomalies
from src.analysis.url_analyzer import ExtractedURL
from src.detection.rules import RuleContext, evaluate_rules
from src.intelligence.virustotal import VTLookupResult


def _blank_auth() -> AuthAnalysis:
    return AuthAnalysis(
        spf=SPFResult(), dkim=DKIMResult(), dmarc=DMARCResult(),
        spf_dkim_alignment_note="", dmarc_alignment_note="",
    )


def _blank_anomalies() -> HeaderAnomalies:
    return HeaderAnomalies()


def test_no_rules_fire_on_clean_context():
    """
    WHAT: A context with no anomalies, all auth results passing/absent,
         no suspicious URLs/attachments/IOCs.
    WHY: A clean benign email must not trigger any false positives.
    EXPECTED: evaluate_rules returns an empty list.
    """
    ctx = RuleContext(header_anomalies=_blank_anomalies(), auth=_blank_auth())
    assert evaluate_rules(ctx) == []


def test_spf_fail_fires_rule_002_only():
    """
    WHAT: Only SPF fail set, everything else clean.
    WHY: Rules must fire independently and not leak into unrelated rules.
    EXPECTED: Exactly RULE-002 fires.
    """
    auth = _blank_auth()
    auth.spf.result = "fail"
    ctx = RuleContext(header_anomalies=_blank_anomalies(), auth=auth)
    fired = evaluate_rules(ctx)
    assert [r.rule_id for r in fired] == ["RULE-002"]


def test_visible_href_mismatch_fires_rule_006_not_rule_005():
    """
    WHAT: A URL whose ONLY suspicious flag is visible_href_mismatch.
    WHY: RULE-005 and RULE-006 must not double-count the same evidence —
         RULE-005 is for OTHER suspicious characteristics, RULE-006 is
         specifically for the mismatch.
    EXPECTED: RULE-006 fires; RULE-005 does not.
    """
    url = ExtractedURL(url="https://evil.test/login", source="html_href",
                        visible_text="https://www.microsoft.com",
                        hostname="evil.test", visible_href_mismatch=True,
                        suspicious_flags=["visible_href_mismatch"])
    ctx = RuleContext(header_anomalies=_blank_anomalies(), auth=_blank_auth(), urls=[url])
    fired_ids = {r.rule_id for r in evaluate_rules(ctx)}
    assert "RULE-006" in fired_ids
    assert "RULE-005" not in fired_ids


def test_suspicious_url_without_mismatch_fires_rule_005():
    """
    WHAT: A URL with a suspicious flag OTHER than visible_href_mismatch
         (e.g. ip_based_url), and no mismatch.
    WHY: RULE-005 must still catch non-mismatch suspicious URLs.
    EXPECTED: RULE-005 fires; RULE-006 does not.
    """
    url = ExtractedURL(url="http://203.0.113.5/login", source="text",
                        hostname="203.0.113.5", visible_href_mismatch=False,
                        suspicious_flags=["ip_based_url"])
    ctx = RuleContext(header_anomalies=_blank_anomalies(), auth=_blank_auth(), urls=[url])
    fired_ids = {r.rule_id for r in evaluate_rules(ctx)}
    assert "RULE-005" in fired_ids
    assert "RULE-006" not in fired_ids


def test_risky_attachment_fires_rule_007_with_mitre():
    """
    WHAT: An attachment flagged as risky extension.
    WHY: RULE-007 must fire and carry a justified MITRE mapping
         (T1566.001 — spearphishing attachment).
    EXPECTED: RULE-007 fires with mitre_technique == 'T1566.001'.
    """
    att = AttachmentAnalysis(filename="bad.exe", content_type="application/octet-stream",
                              size_bytes=10, extension=".exe", sha256="a" * 64,
                              sha1=None, md5=None, is_risky_extension=True)
    ctx = RuleContext(header_anomalies=_blank_anomalies(), auth=_blank_auth(), attachments=[att])
    fired = evaluate_rules(ctx)
    rule_007 = next(r for r in fired if r.rule_id == "RULE-007")
    assert rule_007.mitre_technique == "T1566.001"


def test_known_malicious_ioc_fires_rule_008():
    """
    WHAT: A VT lookup result with malicious_votes > 0.
    WHY: RULE-008 is the threat-intel corroboration rule.
    EXPECTED: RULE-008 fires with critical severity contribution.
    """
    vt = VTLookupResult(ioc_type="domain", ioc_value="evil.test", available=True, malicious_votes=10)
    ctx = RuleContext(header_anomalies=_blank_anomalies(), auth=_blank_auth(), vt_results=[vt])
    fired = evaluate_rules(ctx)
    rule_008 = next(r for r in fired if r.rule_id == "RULE-008")
    assert rule_008.severity_contribution == "critical"


def test_unavailable_vt_result_does_not_fire_rule_008():
    """
    WHAT: A VT lookup result with available=False (e.g. no API key).
    WHY: RULE-008 must never fire on the ABSENCE of data — that would be
         a false signal, not corroboration.
    EXPECTED: RULE-008 does not fire.
    """
    vt = VTLookupResult(ioc_type="domain", ioc_value="unknown.test", available=False, error="No key")
    ctx = RuleContext(header_anomalies=_blank_anomalies(), auth=_blank_auth(), vt_results=[vt])
    fired_ids = {r.rule_id for r in evaluate_rules(ctx)}
    assert "RULE-008" not in fired_ids


def test_lookalike_domain_fires_rule_009():
    """
    WHAT: A domain heuristic result with a brand_token_found value.
    WHY: RULE-009's core signal.
    EXPECTED: RULE-009 fires.
    """
    domain_result = DomainHeuristicResult(
        domain="paypa1-secure.test",
        heuristic_flags=["typosquat_suspected:paypal"],
        brand_token_found="paypal",
    )
    ctx = RuleContext(header_anomalies=_blank_anomalies(), auth=_blank_auth(), domain_results=[domain_result])
    fired_ids = {r.rule_id for r in evaluate_rules(ctx)}
    assert "RULE-009" in fired_ids


def test_every_fired_rule_has_a_false_positive_note():
    """
    WHAT: A context that fires several rules at once.
    WHY: Per project design, every rule must explain to an L1 analyst how
         it could be a false positive — this is a hard requirement, not
         a nice-to-have.
    EXPECTED: Every FiredRule.false_positive_note is a non-empty string.
    """
    auth = _blank_auth()
    auth.spf.result = "fail"
    auth.dkim.result = "fail"
    auth.dmarc.result = "fail"
    anomalies = _blank_anomalies()
    anomalies.from_reply_to_mismatch = True
    anomalies.from_domain = "example.com"
    anomalies.reply_to_domain = "example.test"
    ctx = RuleContext(header_anomalies=anomalies, auth=auth)
    fired = evaluate_rules(ctx)
    assert len(fired) >= 4
    assert all(r.false_positive_note.strip() for r in fired)
