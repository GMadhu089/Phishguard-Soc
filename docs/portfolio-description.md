# Portfolio / Resume Description

Every feature named below is implemented and tested in this repository —
verify against `README.md`, `docs/detection-rules.md`, and `tests/`.

## Resume bullet (one line)

> Built an automated phishing email triage and investigation engine that
> analyzes email headers and authentication results, extracts URLs,
> domains, attachments and IOCs, enriches indicators using threat
> intelligence, applies correlated detection rules, maps phishing
> activity to MITRE ATT&CK, calculates explainable risk scores, and
> generates SOC investigation reports.

## GitHub "About" description (short)

> Automated first-level phishing email triage assistant — header/SPF/
> DKIM/DMARC analysis, URL & domain heuristics, IOC extraction, optional
> VirusTotal enrichment, correlated detection rules, MITRE ATT&CK
> mapping, and Markdown/JSON SOC reports. Python, 99 tests.

## Longer version (for a portfolio page / LinkedIn project section)

**PhishGuard SOC** is a CLI tool that automates the repetitive first-pass
triage work an L1 SOC analyst performs on every reported phishing email.
Given a `.eml` file, it parses headers and MIME structure; analyzes
SPF/DKIM/DMARC authentication results (parsed from `Authentication-
Results`, with explicit scope limitations documented); detects header
anomalies like Reply-To mismatches and brand-impersonating display
names; extracts and analyzes URLs, flagging visible-text-vs-actual-href
mismatches and structurally suspicious characteristics; runs local
domain heuristics including Levenshtein-distance typosquat detection;
performs static attachment analysis (SHA-256/1/MD5 hashing, risky-
extension flagging — never executes anything); extracts and deduplicates
IOCs; optionally enriches them via the VirusTotal API (with full
graceful degradation if unconfigured, rate-limited, or unreachable);
applies 10 independent, evidence-backed detection rules, each with a
documented false-positive scenario; correlates findings across
independent evidence categories rather than raw rule counts; calculates
a deterministic, transparent risk score (never framed as a probability);
maps only MITRE-ATT&CK-justified behavior; and generates analyst-ready
Markdown and JSON incident reports, including SOC scope-investigation
questions and example Splunk/Wazuh queries for follow-up.

Built solo over 4 days, with 99 pytest test cases covering every module
including fully-mocked VirusTotal failure-mode testing (no real network
calls in the test suite).

**Stack:** Python 3.11+, standard library (`email`, `hashlib`, `re`,
`ipaddress`, `pathlib`), `requests`, `python-dotenv`, `pytest`.

## What this project deliberately does NOT claim

- Does not replace Microsoft Defender, Proofpoint, Mimecast, or any SIEM
- Does not perform live DNS/cryptographic SPF/DKIM verification
- Does not sandbox or execute attachments
- Does not claim real-time detection, 100% accuracy, or zero false
  positives
- Does not claim to prove user interaction (clicks, credential entry) —
  that requires SIEM/EDR data outside this tool's scope

These boundaries are stated explicitly in `docs/limitations.md` and are
themselves evidence of understanding how this tool fits into a real SOC
workflow rather than overselling it.
