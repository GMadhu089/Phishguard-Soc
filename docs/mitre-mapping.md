# MITRE ATT&CK Mapping

PhishGuard SOC maps to exactly three techniques, and only when a specific
fired rule justifies them. No technique is ever assigned speculatively.

| Technique | Name | Justified by |
|---|---|---|
| T1566 | Phishing | Automatically added only when a child technique below is present |
| T1566.001 | Spearphishing Attachment | RULE-007 (suspicious attachment type) |
| T1566.002 | Spearphishing Link | RULE-005 (suspicious URL), RULE-006 (visible/href mismatch), RULE-009 (lookalike domain) |

## Why T1566 is never assigned standalone

T1566 (Phishing) is the parent tactic-level technique. Asserting it
without a specific child technique firing would be a vague, unfalsifiable
claim. `src/mitre/mapper.py` only inserts T1566 when at least one of
T1566.001 or T1566.002 is already justified by a fired rule — and its
`reason` field explicitly states it was added because of that child
technique, not independently detected.

## What is NOT mapped, and why

This project does not map to any technique beyond initial-access phishing
— no credential access (T1078), no execution (T1204), no persistence, no
command-and-control. This tool performs static email analysis only; it
has no visibility into what happens after an email is delivered (did the
user click, did malware execute, did an attacker gain a foothold). Mapping
further down the kill chain would require EDR/endpoint telemetry this
tool does not have access to — see `docs/limitations.md` and the "scope
investigation questions" in every generated report.

## Example: how a mapping is built

For `samples/phishing/credential_harvest_example.eml`, RULE-006 fires
(visible/href mismatch) and RULE-009 fires (lookalike domain), both
carrying `T1566.002`. `map_techniques()` merges these into a single
`T1566.002` entry citing both rule IDs, then adds `T1566` as the parent.
The generated report's MITRE section shows exactly this — two entries,
each with its justifying evidence and detecting rule(s), never an
unattributed assertion.
