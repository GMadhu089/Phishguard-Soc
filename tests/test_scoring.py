"""
Tests for src/detection/scoring.py
"""

from src.detection.correlation import CorrelationResult
from src.detection.rules import FiredRule
from src.detection.scoring import calculate_risk


def _rule(rule_id: str, points: int, severity: str = "low") -> FiredRule:
    return FiredRule(
        rule_id=rule_id, name=rule_id, description="", evidence=[],
        score_contribution=points, severity_contribution=severity,
        mitre_technique=None, false_positive_note="",
    )


def _no_correlation() -> CorrelationResult:
    return CorrelationResult(
        fired=False, independent_categories=[], contributing_rule_ids=[],
        score_contribution=0, severity_contribution="none", evidence=[],
        false_positive_note="",
    )


def test_no_rules_fired_gives_zero_score_and_clean_verdict():
    """
    WHAT: No detection rules fired at all.
    WHY: A clean email must score 0 and verdict CLEAN, never SUSPICIOUS.
    EXPECTED: score == 0, severity == 'NONE', verdict == 'CLEAN'.
    """
    risk = calculate_risk([], _no_correlation())
    assert risk.score == 0
    assert risk.severity == "NONE"
    assert risk.verdict == "CLEAN"


def test_score_is_sum_of_rule_contributions():
    """
    WHAT: Two fired rules with known point values, no correlation.
    WHY: The score must be transparently additive — no hidden weighting.
    EXPECTED: score == sum of the two rules' points.
    """
    risk = calculate_risk([_rule("RULE-002", 15), _rule("RULE-005", 20)], _no_correlation())
    assert risk.score == 35
    assert risk.verdict == "SUSPICIOUS"


def test_score_caps_at_100():
    """
    WHAT: Rule contributions that would sum well past 100.
    WHY: A risk score is presented as X/100; it must never exceed that.
    EXPECTED: score == 100 even though raw sum is higher.
    """
    rules = [_rule(f"RULE-{i}", 40) for i in range(5)]  # sums to 200
    risk = calculate_risk(rules, _no_correlation())
    assert risk.score == 100


def test_correlation_bonus_is_included_as_a_visible_factor():
    """
    WHAT: A correlation result that fired, alongside contributing rules.
    WHY: The correlation bonus must be transparent — shown as its own
         line item (RULE-010), not silently folded into another rule.
    EXPECTED: contributing_factors includes an entry with rule_id 'RULE-010'.
    """
    correlation = CorrelationResult(
        fired=True, independent_categories=["authentication", "url"],
        contributing_rule_ids=["RULE-002", "RULE-005"], score_contribution=10,
        severity_contribution="medium", evidence=["..."], false_positive_note="...",
    )
    risk = calculate_risk([_rule("RULE-002", 15), _rule("RULE-005", 20)], correlation)
    assert risk.score == 45  # 15 + 20 + 10
    rule_ids = [f.rule_id for f in risk.contributing_factors]
    assert "RULE-010" in rule_ids


def test_severity_bands_follow_configured_thresholds(monkeypatch):
    """
    WHAT: Scores at and around each default threshold boundary (25/50/75).
    WHY: Severity must map deterministically to the documented bands, and
         a score BELOW the LOW threshold must round down to 'NONE' — that
         is the entire purpose of a configurable LOW threshold, not a
         floor of 'LOW' for any nonzero score.
    EXPECTED: 10 (below 25) -> NONE; 30 -> LOW; 55 -> MEDIUM;
              80 -> HIGH (without critical corroboration).
    """
    monkeypatch.delenv("RISK_THRESHOLD_LOW", raising=False)
    monkeypatch.delenv("RISK_THRESHOLD_MEDIUM", raising=False)
    monkeypatch.delenv("RISK_THRESHOLD_HIGH", raising=False)

    assert calculate_risk([_rule("R", 10)], _no_correlation()).severity == "NONE"
    assert calculate_risk([_rule("R", 30)], _no_correlation()).severity == "LOW"
    assert calculate_risk([_rule("R", 55)], _no_correlation()).severity == "MEDIUM"
    assert calculate_risk([_rule("R", 80)], _no_correlation()).severity == "HIGH"


def test_critical_requires_corroboration_not_just_high_score():
    """
    WHAT: A score of 80 (above the HIGH threshold) with NO rule carrying
         'critical' severity_contribution, vs the same score WITH one.
    WHY: Per design, CRITICAL should not be a routine outcome of
         accumulating heuristic points alone — it needs either an
         extreme score (>=90) or explicit strong corroboration (e.g. a
         confirmed malicious IOC).
    EXPECTED: Without corroboration -> HIGH. With a 'critical' rule -> CRITICAL.
    """
    without = calculate_risk([_rule("R", 80)], _no_correlation())
    assert without.severity == "HIGH"

    with_critical = calculate_risk(
        [_rule("R", 80), _rule("RULE-008", 0, severity="critical")], _no_correlation()
    )
    assert with_critical.severity == "CRITICAL"


def test_extremely_high_score_alone_reaches_critical():
    """
    WHAT: A score of 90+ with no explicit critical-severity rule.
    WHY: An extreme score (nearly every category firing at max weight)
         should reach CRITICAL even without a single named corroborating rule.
    EXPECTED: severity == 'CRITICAL'.
    """
    risk = calculate_risk([_rule("R", 95)], _no_correlation())
    assert risk.severity == "CRITICAL"


def test_custom_thresholds_from_environment(monkeypatch):
    """
    WHAT: RISK_THRESHOLD_MEDIUM overridden to a custom value via environment.
    WHY: Thresholds must be genuinely configurable, per project design.
    EXPECTED: A score that would be MEDIUM under defaults becomes LOW
              under a raised custom medium threshold.
    """
    monkeypatch.setenv("RISK_THRESHOLD_MEDIUM", "90")
    risk = calculate_risk([_rule("R", 55)], _no_correlation())
    assert risk.severity == "LOW"
