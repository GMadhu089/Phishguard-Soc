"""
Tests for src/mitre/mapper.py
"""

from src.detection.rules import FiredRule
from src.mitre.mapper import map_techniques


def _rule(rule_id: str, technique: str | None) -> FiredRule:
    return FiredRule(
        rule_id=rule_id, name=rule_id, description="", evidence=[f"evidence for {rule_id}"],
        score_contribution=10, severity_contribution="low",
        mitre_technique=technique, false_positive_note="",
    )


def test_no_rules_gives_no_mitre_mappings():
    """
    WHAT: No fired rules.
    WHY: Must never invent a mapping without justification.
    EXPECTED: Empty list.
    """
    assert map_techniques([]) == []


def test_rules_without_mitre_mapping_are_ignored():
    """
    WHAT: A fired rule with mitre_technique=None (e.g. RULE-001, RULE-002).
    WHY: Not every rule justifies a MITRE mapping; only mapped ones should appear.
    EXPECTED: Empty list.
    """
    assert map_techniques([_rule("RULE-001", None), _rule("RULE-002", None)]) == []


def test_child_technique_present_adds_parent_automatically():
    """
    WHAT: A rule justifying T1566.002 (Spearphishing Link).
    WHY: Per project design, the parent T1566 (Phishing) is implied when
         a child technique is justified, and should be included so the
         report shows the full technique hierarchy.
    EXPECTED: Both T1566 and T1566.002 appear; T1566 comes first.
    """
    mappings = map_techniques([_rule("RULE-006", "T1566.002")])
    ids = [m.technique_id for m in mappings]
    assert ids == ["T1566", "T1566.002"]


def test_parent_not_added_without_any_child_justification():
    """
    WHAT: No fired rule maps to any T1566.* child technique.
    WHY: T1566 must never appear on its own without a justifying child —
         "map only justified techniques" per project design.
    EXPECTED: T1566 does not appear (list is empty here since no mappings exist).
    """
    mappings = map_techniques([_rule("RULE-001", None)])
    assert "T1566" not in [m.technique_id for m in mappings]


def test_multiple_rules_same_technique_are_merged_not_duplicated():
    """
    WHAT: Two different fired rules (RULE-006 and RULE-009) both justify
         T1566.002.
    WHY: The report should show ONE T1566.002 entry citing both rules,
         not two duplicate entries.
    EXPECTED: Exactly one T1566.002 mapping; its 'detection' field cites
              both rule IDs.
    """
    mappings = map_techniques([_rule("RULE-006", "T1566.002"), _rule("RULE-009", "T1566.002")])
    t1566_002 = [m for m in mappings if m.technique_id == "T1566.002"]
    assert len(t1566_002) == 1
    assert "RULE-006" in t1566_002[0].detection
    assert "RULE-009" in t1566_002[0].detection


def test_attachment_technique_mapped_independently():
    """
    WHAT: A rule justifying T1566.001 (Spearphishing Attachment) only.
    WHY: Attachment-based and link-based phishing are distinct child
         techniques and must not be conflated.
    EXPECTED: T1566 and T1566.001 appear; T1566.002 does not.
    """
    mappings = map_techniques([_rule("RULE-007", "T1566.001")])
    ids = [m.technique_id for m in mappings]
    assert "T1566.001" in ids
    assert "T1566.002" not in ids


def test_evidence_is_carried_through_from_the_rule():
    """
    WHAT: A fired rule with specific evidence strings.
    WHY: The MITRE mapping should be traceable back to concrete evidence,
         not just an assertion.
    EXPECTED: The mapping's evidence list contains the rule's evidence.
    """
    mappings = map_techniques([_rule("RULE-006", "T1566.002")])
    t1566_002 = next(m for m in mappings if m.technique_id == "T1566.002")
    assert "evidence for RULE-006" in t1566_002.evidence
