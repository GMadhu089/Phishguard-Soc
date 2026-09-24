"""
mapper.py (src/mitre)

Aggregates MITRE ATT&CK technique mappings from fired detection rules into
a deduplicated summary. Only techniques actually carried by a fired rule
are included — this module does not invent or guess mappings.

If any child technique (T1566.001 or T1566.002) is present, the parent
T1566 (Phishing) is also included, since a child technique implies its
parent tactic occurred. T1566 is never included on its own without at
least one child technique justifying it.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.detection.rules import FiredRule

_TECHNIQUE_INFO = {
    "T1566": {
        "name": "Phishing",
        "description": "Adversaries send phishing messages to gain access to victim systems.",
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "description": "A phishing variant using a malicious attachment to gain access.",
    },
    "T1566.002": {
        "name": "Spearphishing Link",
        "description": "A phishing variant using a malicious link to gain access.",
    },
}


@dataclass
class MitreMapping:
    technique_id: str
    technique_name: str
    reason: str
    evidence: list[str]
    detection: str  # which rule(s) justified this mapping


def map_techniques(fired_rules: list[FiredRule]) -> list[MitreMapping]:
    technique_to_rules: dict[str, list[FiredRule]] = {}

    for rule in fired_rules:
        if rule.mitre_technique:
            technique_to_rules.setdefault(rule.mitre_technique, []).append(rule)

    mappings: list[MitreMapping] = []

    for technique_id in sorted(technique_to_rules.keys()):
        rules_for_technique = technique_to_rules[technique_id]
        info = _TECHNIQUE_INFO.get(technique_id, {"name": "Unknown", "description": ""})
        evidence = [ev for r in rules_for_technique for ev in r.evidence]
        detection = ", ".join(r.rule_id for r in rules_for_technique)
        mappings.append(
            MitreMapping(
                technique_id=technique_id,
                technique_name=info["name"],
                reason=info["description"],
                evidence=evidence,
                detection=detection,
            )
        )

    # Add parent T1566 if any child technique justified it, and only then.
    child_techniques = [t for t in technique_to_rules if t.startswith("T1566.")]
    if child_techniques and "T1566" not in technique_to_rules:
        contributing_rules = [
            r for t in child_techniques for r in technique_to_rules[t]
        ]
        mappings.insert(
            0,
            MitreMapping(
                technique_id="T1566",
                technique_name=_TECHNIQUE_INFO["T1566"]["name"],
                reason=(
                    "Parent technique implied by observed child technique(s): "
                    + ", ".join(sorted(child_techniques))
                ),
                evidence=[],
                detection=", ".join(sorted({r.rule_id for r in contributing_rules})),
            ),
        )

    return mappings
