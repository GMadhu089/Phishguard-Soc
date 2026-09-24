"""
scoring.py

Deterministic, transparent risk scoring. This is explicitly called a
"Risk Score", never a "probability of compromise" — it is a weighted sum
of rule contributions, capped at 100, with every contributing factor
shown. It is not a machine-learned or statistical estimate.

Severity bands are configurable via environment variables (see
.env.example): RISK_THRESHOLD_LOW / MEDIUM / HIGH. Defaults: 25/50/75.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from src.detection.correlation import CorrelationResult
from src.detection.rules import FiredRule

_DEFAULT_THRESHOLDS = {"low": 25, "medium": 50, "high": 75}


@dataclass
class ContributingFactor:
    rule_id: str
    name: str
    points: int


@dataclass
class RiskAssessment:
    score: int  # 0-100
    severity: str  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    verdict: str  # "CLEAN" | "SUSPICIOUS"
    contributing_factors: list[ContributingFactor] = field(default_factory=list)
    thresholds_used: dict = field(default_factory=dict)


def _get_thresholds() -> dict:
    thresholds = dict(_DEFAULT_THRESHOLDS)
    for key, env_name in (
        ("low", "RISK_THRESHOLD_LOW"),
        ("medium", "RISK_THRESHOLD_MEDIUM"),
        ("high", "RISK_THRESHOLD_HIGH"),
    ):
        raw = os.getenv(env_name)
        if raw:
            try:
                thresholds[key] = int(raw)
            except ValueError:
                pass  # keep default; malformed env value should not crash scoring
    return thresholds


def calculate_risk(
    fired_rules: list[FiredRule],
    correlation: CorrelationResult,
) -> RiskAssessment:
    factors = [
        ContributingFactor(rule_id=r.rule_id, name=r.name, points=r.score_contribution)
        for r in fired_rules
    ]

    if correlation.fired:
        factors.append(
            ContributingFactor(
                rule_id="RULE-010",
                name="Multiple correlated phishing indicators",
                points=correlation.score_contribution,
            )
        )

    raw_score = sum(f.points for f in factors)
    score = min(raw_score, 100)

    thresholds = _get_thresholds()
    has_critical_corroboration = any(r.severity_contribution == "critical" for r in fired_rules) or (
        correlation.fired and correlation.severity_contribution == "critical"
    )
    severity = _score_to_severity(score, thresholds, has_critical_corroboration)
    verdict = "SUSPICIOUS" if fired_rules else "CLEAN"

    return RiskAssessment(
        score=score,
        severity=severity,
        verdict=verdict,
        contributing_factors=factors,
        thresholds_used=thresholds,
    )


def _score_to_severity(score: int, thresholds: dict, has_critical_corroboration: bool) -> str:
    """
    LOW/MEDIUM/HIGH bands come directly from the three configurable
    thresholds. A score greater than 0 but below the LOW threshold maps
    to 'NONE', not 'LOW' — a single very-low-weight rule firing (e.g. a
    lone Reply-To mismatch worth 10 points) should not itself be labeled
    a "LOW risk" alert; it should round down to no meaningful risk band.
    Lowering RISK_THRESHOLD_LOW makes the tool more sensitive to small
    signals; raising it makes minor indicators disappear into 'NONE'.

    CRITICAL is intentionally NOT just "one more threshold crossed" —
    accumulating enough small heuristic points should top out at HIGH.
    CRITICAL is reserved for cases with independent, strong corroboration:
    either an extremely high score (>=90, meaning nearly every category of
    evidence fired at once) or explicit confirmation such as a known-
    malicious IOC from threat intelligence (RULE-008) or a correlation
    result explicitly marked critical. This keeps CRITICAL meaningful
    rather than a routine occurrence for heavily-flagged but still-
    heuristic-only emails.
    """
    if score >= 90 or (score >= thresholds["high"] and has_critical_corroboration):
        return "CRITICAL"
    if score >= thresholds["high"]:
        return "HIGH"
    if score >= thresholds["medium"]:
        return "MEDIUM"
    if score >= thresholds["low"]:
        return "LOW"
    return "NONE"
