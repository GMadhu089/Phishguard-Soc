# Implementation Checklist (Completed Record)

This tracks what was actually built each day, against the original Day
0 plan, including where reality diverged from the plan and why.

## Day 1 — Foundations
- [x] Repository scaffold, `.gitignore`, `.env.example`, `LICENSE`, `requirements.txt`
- [x] `src/utils/logger.py`
- [x] `src/parser/email_parser.py` — multipart-safe parsing, never executes content
- [x] `src/parser/header_parser.py` — safe header extraction, Received-chain IP classification
- [x] `src/analysis/auth_analyzer.py` — SPF/DKIM/DMARC parsing from `Authentication-Results`
- [x] `src/main.py` (Day-1-scoped CLI)
- [x] 2 synthetic samples (benign, phishing)
- [x] 19 pytest test cases
- **Verified:** manually (no `pytest` install available in the build
  sandbox — no network access); all 19 checks re-implemented and passed
  outside pytest. **User must run `pytest` locally to confirm.**

## Day 2 — Analysis, IOCs, Threat Intel, Detection Rules
- [x] `src/analysis/header_analyzer.py` (added — was implicitly Day 1 scope, built Day 2)
- [x] `src/analysis/url_analyzer.py` — extraction, visible/href mismatch, heuristics
- [x] `src/analysis/domain_analyzer.py` — local heuristics + typosquat detection
- [x] `src/analysis/attachment_analyzer.py` — hashing, risky-extension flags
- [x] `src/analysis/ioc_extractor.py` — deduplicated, confidence-scored IOCs
- [x] `src/intelligence/virustotal.py` — optional, graceful degradation on every failure mode
- [x] `src/detection/rules.py` — RULE-001 through RULE-009
- [x] 2 more samples (attachment, lookalike-domain) + 53 more test cases
- **Bugs found and fixed during this phase:**
  - `str.lstrip("www.")` bug in URL hostname comparison — stripped
    characters, not the literal prefix, corrupting hosts like
    `wallet.com` → `allet.com`. Fixed with explicit prefix check;
    regression test added.
  - Naive substring brand-matching silently missed the character-
    substitution typosquat `paypa1-secure.test` (vs `paypal`). Fixed by
    adding Levenshtein-distance matching; regression test added.
- **Verified:** manually (still no pytest install); 72/72 cumulative
  checks passed.

## Day 3 — Correlation, Scoring, MITRE, Reporting
- [x] `src/detection/correlation.py` — RULE-010, category-based not count-based
- [x] `src/detection/scoring.py` — deterministic risk score, configurable thresholds
- [x] `src/mitre/mapper.py` — deduplicated, justified-only technique mapping
- [x] `src/reporting/report_generator.py` — Markdown + JSON reports
- [x] Full rewrite of `main.py` wiring the entire pipeline end-to-end
- [x] 27 more test cases (99 cumulative)
- **Design decisions revised during this phase:**
  - Original plan implied CRITICAL severity at the top score threshold
    alone; revised so CRITICAL requires either an extreme score (≥90)
    or explicit corroboration (confirmed malicious IOC), so it isn't a
    routine outcome for heavily-flagged-but-unconfirmed emails.
- **Bug found:** one of my own test assertions
  (`test_severity_bands_follow_configured_thresholds`) was wrong — it
  expected a sub-threshold score to map to `LOW` when the correct,
  intentional behavior is `NONE`. Fixed the test, not the code.
- **Verified:** manually; 99/99 cumulative checks passed. All 8 samples
  (added 4 more this phase to reach the spec's minimum) produce
  distinct, evidence-proportional verdicts: 3 benign → CLEAN/0, phishing
  samples → LOW(25)/LOW(45)/HIGH(75)/CRITICAL(100).

## Day 4 — Polish, Documentation, Interview Prep
- [x] 4 more samples to reach the spec's 8-sample minimum (2 benign, 2 phishing)
- [x] `docs/architecture.md`, `docs/detection-rules.md`, `docs/mitre-mapping.md`,
      `docs/investigation.md`, `docs/limitations.md`
- [x] `README.md` — every claim checked against actual code/test output
- [x] `screenshots/CHECKLIST.md`
- [x] `docs/interview-prep.md` — 41 Q&A (spec required 40+), all 15
      flagged priority questions included, plus the single most
      important question answered per the spec's required structure
- [x] `docs/portfolio-description.md`
- [x] This checklist

## What was NOT built (explicitly out of scope for this MVP)
- Phase 2 web interface (explicitly deferred per the original spec)
- Live Splunk/Wazuh integration (illustrative example queries only)
- Non-hardcoded/dynamic brand and typosquat reference data
- Cryptographic DKIM re-verification / live SPF/DMARC DNS lookups

## A note on testing throughout this project

**No `pytest` install was available in the sandbox this project was
built in** (no network access to `pip install pytest`). Every test file
in `tests/` is real, standard pytest code — fixtures, `monkeypatch`,
`unittest.mock.patch`, parametrization-free but otherwise idiomatic. To
verify without pytest during the build, the exact same assertions were
re-implemented and run as plain Python scripts outside the pytest
framework, and every discrepancy found that way was treated as a real
bug to fix (see the two bugs listed under Day 2, and the one under Day
3). **You should still run `pytest tests/ -v` yourself** before trusting
this checklist's "99 passed" claim — that is the appropriate level of
verification for someone who's about to put this on a resume.
