"""
Tests for src/detection/correlation.py (RULE-010)
"""

from src.detection.correlation import evaluate_correlation
from src.detection.rules import FiredRule


def _rule(rule_id: str) -> FiredRule:
    return FiredRule(
        rule_id=rule_id, name=rule_id, description="", evidence=[],
        score_contribution=10, severity_contribution="low",
        mitre_technique=None, false_positive_note="",
    )


def test_single_category_does_not_fire_correlation():
    """
    WHAT: SPF, DKIM, and DMARC all fail (3 rules, but all one category:
         'authentication' — one root cause, a misconfigured/spoofed sender).
    WHY: Correlation must require INDEPENDENT categories, not just a raw
         count, or three symptoms of one cause would inflate confidence.
    EXPECTED: RULE-010 does not fire.
    """
    fired = [_rule("RULE-002"), _rule("RULE-003"), _rule("RULE-004")]
    result = evaluate_correlation(fired)
    assert result.fired is False


def test_two_independent_categories_fires_with_moderate_bonus():
    """
    WHAT: One authentication rule + one URL rule (2 independent categories).
    WHY: Two genuinely independent signals is the minimum bar for correlation.
    EXPECTED: RULE-010 fires with the moderate (not maximum) bonus.
    """
    fired = [_rule("RULE-002"), _rule("RULE-005")]
    result = evaluate_correlation(fired)
    assert result.fired is True
    assert result.score_contribution == 10


def test_three_independent_categories_fires_with_higher_bonus():
    """
    WHAT: Authentication + sender_identity + url categories all present.
    WHY: More independent corroboration should score higher than two.
    EXPECTED: RULE-010 fires with a higher bonus than the 2-category case.
    """
    fired = [_rule("RULE-002"), _rule("RULE-001"), _rule("RULE-005")]
    result = evaluate_correlation(fired)
    assert result.fired is True
    assert result.score_contribution == 20


def test_threat_intel_co_occurrence_adds_extra_bonus():
    """
    WHAT: A known-malicious IOC (RULE-008, threat_intel category) plus one
         other independent category.
    WHY: External corroboration should be weighted more heavily than two
         purely local-heuristic categories agreeing.
    EXPECTED: Bonus is higher than the plain 2-category case.
    """
    fired = [_rule("RULE-008"), _rule("RULE-005")]
    result = evaluate_correlation(fired)
    assert result.fired is True
    assert result.score_contribution == 25  # 10 base + 15 threat-intel bonus


def test_no_fired_rules_does_not_fire_correlation():
    """
    WHAT: An empty fired-rules list (clean email).
    WHY: Must not crash or false-positive on the no-evidence case.
    EXPECTED: RULE-010 does not fire.
    """
    result = evaluate_correlation([])
    assert result.fired is False


def test_correlation_severity_scales_with_category_count():
    """
    WHAT: Two categories vs three-plus categories.
    WHY: Severity contribution should reflect how much independent
         evidence lines up, not be a flat value.
    EXPECTED: Two categories -> 'medium'; three or more -> 'high'.
    """
    two_cat = evaluate_correlation([_rule("RULE-002"), _rule("RULE-005")])
    three_cat = evaluate_correlation([_rule("RULE-002"), _rule("RULE-001"), _rule("RULE-005")])
    assert two_cat.severity_contribution == "medium"
    assert three_cat.severity_contribution == "high"
