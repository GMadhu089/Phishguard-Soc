"""
Tests for src/reporting/report_generator.py
"""

import json
from pathlib import Path

from src.analysis.auth_analyzer import DKIMResult, DMARCResult, SPFResult, AuthAnalysis
from src.analysis.header_analyzer import HeaderAnomalies
from src.detection.correlation import CorrelationResult
from src.detection.rules import FiredRule
from src.detection.scoring import RiskAssessment, ContributingFactor
from src.parser.header_parser import ParsedHeaders
from src.reporting.report_generator import build_report, render_markdown, save_report


def _minimal_report(tmp_path=None):
    headers = ParsedHeaders(from_="attacker@example.test", to="victim@example.com",
                             subject="Test subject", reply_to=None, return_path=None)
    auth = AuthAnalysis(
        spf=SPFResult(result="fail"), dkim=DKIMResult(result="fail"),
        dmarc=DMARCResult(result="fail", policy="reject"),
        spf_dkim_alignment_note="note", dmarc_alignment_note="dmarc note",
    )
    anomalies = HeaderAnomalies()
    rule = FiredRule(
        rule_id="RULE-002", name="SPF failure", description="desc",
        evidence=["SPF result: fail"], score_contribution=15,
        severity_contribution="low", mitre_technique=None,
        false_positive_note="fp note",
    )
    correlation = CorrelationResult(
        fired=False, independent_categories=[], contributing_rule_ids=[],
        score_contribution=0, severity_contribution="none", evidence=[],
        false_positive_note="",
    )
    risk = RiskAssessment(
        score=15, severity="LOW", verdict="SUSPICIOUS",
        contributing_factors=[ContributingFactor(rule_id="RULE-002", name="SPF failure", points=15)],
        thresholds_used={"low": 25, "medium": 50, "high": 75},
    )
    return build_report(
        incident_id="INC-TEST-001", headers=headers, auth=auth, header_anomalies=anomalies,
        urls=[], domain_results=[], attachments=[], iocs=[], vt_results=[],
        fired_rules=[rule], correlation=correlation, risk=risk, mitre_mappings=[],
    )


def test_build_report_populates_core_fields():
    """
    WHAT: A minimal but complete set of analysis inputs.
    WHY: Baseline correctness — the report must carry through the key
         identifying fields the spec requires (subject, sender, severity, score).
    EXPECTED: All core fields present and correct on the IncidentReport.
    """
    report = _minimal_report()
    assert report.incident_id == "INC-TEST-001"
    assert report.subject == "Test subject"
    assert report.sender == "attacker@example.test"
    assert report.severity == "LOW"
    assert report.risk_score == 15
    assert report.verdict == "SUSPICIOUS"


def test_markdown_contains_required_sections():
    """
    WHAT: Rendered Markdown output for a minimal report.
    WHY: Per project spec, the report must contain specific sections
         (incident ID, severity, risk score, auth results, detection
         rules, scope questions, recommended actions, escalation).
    EXPECTED: Each required section header/label appears in the output.
    """
    report = _minimal_report()
    md = render_markdown(report)
    for required in [
        "INC-TEST-001", "**Severity:** LOW", "**Risk Score:** 15/100",
        "## Authentication Results", "## Detection Rules Triggered",
        "## Scope Investigation Questions", "## Recommended Actions",
        "## Escalation Recommendation",
    ]:
        assert required in md, f"Missing: {required}"


def test_markdown_never_claims_certainty_language():
    """
    WHAT: Rendered Markdown for a report with a fired SPF-fail rule.
    WHY: Per project design constraints, the tool must never claim
         cryptographic certainty or 100% accuracy language.
    EXPECTED: Phrases like 'guaranteed malicious' or '100% accurate' do
              not appear anywhere in the rendered report.
    """
    report = _minimal_report()
    md = render_markdown(report)
    forbidden = ["100% accurate", "guaranteed malicious", "definitely malicious", "proven compromise"]
    for phrase in forbidden:
        assert phrase.lower() not in md.lower()


def test_alert_vs_incident_distinction_present():
    """
    WHAT: Rendered Markdown output.
    WHY: Per project spec, the tool must explicitly distinguish an ALERT
         (what this tool produces) from an INCIDENT (requires corroborating
         evidence elsewhere).
    EXPECTED: The alert-vs-incident note text appears in the report.
    """
    report = _minimal_report()
    md = render_markdown(report)
    assert "ALERT" in md and "INCIDENT" in md


def test_save_report_writes_valid_md_and_json(tmp_path):
    """
    WHAT: Saving a report to a temporary output directory.
    WHY: Must write both required formats (spec: 'Generate: 1. Markdown
         report 2. JSON report') and the JSON must be valid/parseable.
    EXPECTED: Both files exist; JSON round-trips to a dict with matching
              incident_id.
    """
    report = _minimal_report()
    md_path, json_path = save_report(report, output_dir=str(tmp_path))

    assert Path(md_path).exists()
    assert Path(json_path).exists()

    with open(json_path) as f:
        data = json.load(f)
    assert data["incident_id"] == "INC-TEST-001"
    assert data["risk_score"] == 15


def test_clean_verdict_report_has_no_action_needed_text():
    """
    WHAT: A report built with verdict CLEAN (no fired rules).
    WHY: The recommended-actions section must reflect a clean verdict
         appropriately, not generic phishing warnings.
    EXPECTED: Recommended actions mention no action required.
    """
    headers = ParsedHeaders(from_="a@example.com", to="b@example.com", subject="Hi")
    auth = AuthAnalysis(
        spf=SPFResult(result="pass"), dkim=DKIMResult(result="pass"),
        dmarc=DMARCResult(result="pass"), spf_dkim_alignment_note="", dmarc_alignment_note="",
    )
    correlation = CorrelationResult(
        fired=False, independent_categories=[], contributing_rule_ids=[],
        score_contribution=0, severity_contribution="none", evidence=[], false_positive_note="",
    )
    risk = RiskAssessment(score=0, severity="NONE", verdict="CLEAN", contributing_factors=[], thresholds_used={})
    report = build_report(
        incident_id="INC-CLEAN-001", headers=headers, auth=auth, header_anomalies=HeaderAnomalies(),
        urls=[], domain_results=[], attachments=[], iocs=[], vt_results=[],
        fired_rules=[], correlation=correlation, risk=risk, mitre_mappings=[],
    )
    assert any("no action required" in a.lower() for a in report.recommended_actions)
