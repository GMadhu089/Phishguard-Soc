"""
correlation.py

Implements RULE-010: "Multiple correlated phishing indicators."

DESIGN RATIONALE (per project spec): a single indicator — even a strong one
like an SPF failure — is not proof of phishing on its own. Confidence
should come from independent, unrelated signals lining up together, e.g.:

    DMARC fail + lookalike domain + credential-harvesting URL -> high confidence
    Known malicious IOC + multiple suspicious indicators -> critical confidence

Rather than a raw "3+ rules fired" count (which could just mean SPF+DKIM+
DMARC all failing — three rules from ONE root cause, a misconfigured
sender), this module groups fired rules into independent EVIDENCE
CATEGORIES and only fires RULE-010 when rules from multiple different
categories co-occur. This avoids inflating confidence from correlated
symptoms of a single underlying cause.

Evidence categories:
    "authentication" -> RULE-002, RULE-003, RULE-004 (SPF/DKIM/DMARC — these
                         often fail together for one root cause, so they
                         count as ONE category, not three)
    "sender_identity" -> RULE-001, RULE-009 (Reply-To mismatch, lookalike domain)
    "url"             -> RULE-005, RULE-006 (suspicious URL, visible/href mismatch)
    "attachment"      -> RULE-007
    "threat_intel"    -> RULE-008 (external corroboration — weighted heavily
                         when combined with anything else)
"""

from __future__ import annotations

from dataclasses import dataclass

from src.detection.rules import FiredRule

_RULE_TO_CATEGORY = {
    "RULE-001": "sender_identity",
    "RULE-002": "authentication",
    "RULE-003": "authentication",
    "RULE-004": "authentication",
    "RULE-005": "url",
    "RULE-006": "url",
    "RULE-007": "attachment",
    "RULE-008": "threat_intel",
    "RULE-009": "sender_identity",
    "RULE-011": "sender_identity",
    "RULE-012": "url",
    "RULE-013": "url",
    # "RULE-014": "url",
}

_MIN_INDEPENDENT_CATEGORIES = 2


@dataclass
class CorrelationResult:
    fired: bool
    independent_categories: list[str]
    contributing_rule_ids: list[str]
    score_contribution: int
    severity_contribution: str
    evidence: list[str]
    false_positive_note: str


def evaluate_correlation(fired_rules: list[FiredRule]) -> CorrelationResult:
    categories_present: dict[str, list[str]] = {}
    for rule in fired_rules:
        category = _RULE_TO_CATEGORY.get(rule.rule_id)
        if category:
            categories_present.setdefault(category, []).append(rule.rule_id)

    independent_categories = sorted(categories_present.keys())
    fired = len(independent_categories) >= _MIN_INDEPENDENT_CATEGORIES

    if not fired:
        return CorrelationResult(
            fired=False,
            independent_categories=independent_categories,
            contributing_rule_ids=[],
            score_contribution=0,
            severity_contribution="none",
            evidence=[],
            false_positive_note="",
        )

    contributing_rule_ids = sorted(
        rid for ids in categories_present.values() for rid in ids
    )

    # Correlation bonus scales with how many independent categories agree,
    # not with the raw rule count — 2 categories is a moderate bump, 3+ is
    # a strong bump. threat_intel co-occurring with anything else earns an
    # extra bump since it's external corroboration, not just local heuristics.
    category_count = len(independent_categories)
    bonus = 10 if category_count == 2 else 20
    if "threat_intel" in categories_present and category_count >= 2:
        bonus += 15

    severity = "high" if category_count >= 3 or "threat_intel" in categories_present else "medium"

    evidence = [
        f"Independent evidence categories present: {', '.join(independent_categories)}",
        f"Contributing rules: {', '.join(contributing_rule_ids)}",
    ]

    return CorrelationResult(
        fired=True,
        independent_categories=independent_categories,
        contributing_rule_ids=contributing_rule_ids,
        score_contribution=bonus,
        severity_contribution=severity,
        evidence=evidence,
        false_positive_note=(
            "Correlation across independent categories reduces (but does not eliminate) "
            "the chance of a single misconfiguration explaining all evidence. Still verify "
            "each contributing rule's own false-positive notes before escalating."
        ),
    )
