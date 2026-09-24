# PhishGuard SOC

**Automated first-level phishing email triage and investigation assistant.**

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-CLI%20MVP-yellow)

> This project does **not** replace Microsoft Defender for Office 365,
> Proofpoint, Mimecast, Google Workspace security, Secure Email Gateways,
> VirusTotal, or your SIEM. It automates the repetitive first-pass work an
> L1 SOC analyst does on every reported phishing email, so the analyst can
> spend their time on judgment calls instead of manual data collection.

## Overview

PhishGuard SOC takes a suspicious `.eml` file and automatically:

- Parses headers, authentication results (SPF/DKIM/DMARC), URLs, domains,
  and attachments
- Extracts and deduplicates IOCs
- Optionally enriches IOCs via VirusTotal (degrades gracefully without it)
- Applies 10 correlated, transparent detection rules
- Calculates an explainable, deterministic risk score (never framed as a
  probability)
- Maps only justified behavior to MITRE ATT&CK
- Generates a Markdown + JSON SOC investigation report, including scope
  questions and example SIEM queries for follow-up investigation

## The Problem / SOC Use Case

L1 SOC analysts repeat the same manual steps on every reported phishing
email: read headers, check SPF/DKIM/DMARC, compare visible link text to
actual destinations, hash attachments, and write up findings. This is
repetitive, error-prone under alert fatigue, and slows down triage-to-
escalation time. PhishGuard SOC automates that repeatable first pass.

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full data-flow
diagram and design rationale. Summary:

```
.eml -> parse -> header/auth/URL/domain/attachment analysis -> IOC extraction
     -> optional VirusTotal enrichment -> detection rules -> correlation
     -> risk scoring -> MITRE mapping -> Markdown + JSON report
```

## Features

- **Email parsing** — multipart-safe, never executes attachment or HTML
  content, degrades gracefully on malformed/empty input
- **Header & authentication analysis** — From/Reply-To mismatch,
  display-name brand spoofing, SPF/DKIM/DMARC parsing with alignment notes
- **URL analysis** — extraction from text and HTML, visible-vs-actual-href
  mismatch detection, IP-based/shortener/punycode/encoded-character flags
- **Domain heuristics** — brand-token and Levenshtein-distance typosquat
  detection, explicitly labeled as local heuristics (never confused with
  threat intelligence)
- **Attachment analysis** — SHA-256/SHA-1/MD5 hashing, risky-extension
  flagging, static-only (never executes)
- **IOC extraction** — deduplicated, typed, confidence-scored
- **Threat intelligence (optional)** — VirusTotal domain/IP/URL/hash
  lookups; the tool runs fully without an API key
- **Detection engine** — 10 rules, each with evidence and a documented
  false-positive explanation (see [`docs/detection-rules.md`](docs/detection-rules.md))
- **Correlation engine** — fires only when independent evidence
  *categories* agree, not just a raw rule count
- **Risk scoring** — deterministic, transparent, capped at 100
- **MITRE ATT&CK mapping** — see [`docs/mitre-mapping.md`](docs/mitre-mapping.md)
- **Reporting** — Markdown + JSON, with SOC scope questions and example
  Splunk/Wazuh queries — see [`docs/investigation.md`](docs/investigation.md)

## Sample Output

```
$ python -m src.main analyze samples/phishing/credential_harvest_example.eml

============================================
PHISHGUARD SOC
PHISHING EMAIL ANALYZER
============================================

Verdict: SUSPICIOUS
Severity: CRITICAL
Risk Score: 100/100

Sender:
Microsoft Account Team <account-security@example.com>

Reply-To:
security-support@example.test

SPF:
FAIL

DKIM:
FAIL

DMARC:
FAIL

URLs:
1

Suspicious URLs:
1

Attachments:
0

Suspicious Attachments:
0

IOCs:
7

Threat Intelligence:
VT_API_KEY not set — VirusTotal enrichment skipped.

MITRE:
T1566, T1566.002

Report:
reports/INC-20260921-045700-credential_harvest_example.md

============================================
```

This is real output from a synthetic sample included in this repo —
not a fabricated example.

## Installation

```bash
git clone <your-repo-url>
cd phishguard-soc
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration

Copy `.env.example` to `.env` and fill in what you want to use:

```bash
cp .env.example .env
```

```
VT_API_KEY=                  # optional — leave blank to skip VirusTotal enrichment
RISK_THRESHOLD_LOW=25
RISK_THRESHOLD_MEDIUM=50
RISK_THRESHOLD_HIGH=75
```

Never commit a real `.env` file — it's already in `.gitignore`.

## Usage

```bash
python -m src.main analyze samples/phishing/credential_harvest_example.eml

# Full per-stage diagnostic detail
python -m src.main analyze samples/phishing/credential_harvest_example.eml --verbose

# Custom report output directory
python -m src.main analyze samples/phishing/example.eml --output-dir /tmp/reports
```

Eight synthetic sample emails are included under `samples/` (3 benign, 5
phishing), all using safe placeholder domains (`example.com/.test/.org`)
— no real malicious infrastructure.

## Testing

```bash
pytest tests/ -v
```

99 test cases across every module: parsing, header/auth analysis, URL/
domain/attachment analysis, IOC extraction, VirusTotal (fully mocked —
no real network calls), detection rules, correlation, scoring, MITRE
mapping, and report generation.

## Screenshots

See [`screenshots/CHECKLIST.md`](screenshots/CHECKLIST.md) for
the list of screenshots to capture after running this project yourself.

## Limitations

See [`docs/limitations.md`](docs/limitations.md) for a full, honest
accounting — including that SPF/DKIM results are parsed from
`Authentication-Results` rather than independently re-verified, domain
analysis is local-heuristic-only, and this tool cannot determine whether
a user actually interacted with a malicious email (that requires
SIEM/EDR data outside this tool's scope).

## Future Improvements

- Phase 2: a simple web interface wrapping the same core pipeline
- Expanded, non-hardcoded brand/typosquat detection (e.g. a larger
  reference list or a public-suffix-list-aware comparison)
- Additional threat-intel sources beyond VirusTotal
- Direct Splunk/Wazuh query execution (currently: illustrative example
  queries only, not a live integration)

## Security Considerations

- Never executes email content, attachments, or extracted URLs
- Static analysis only, end to end
- API keys are read from environment variables via `.env` (gitignored),
  never hardcoded, never logged
- All sample data uses placeholder domains — no real malicious
  infrastructure is referenced anywhere in this repository

## Additional Documentation

- [`docs/implementation-checklist.md`](docs/implementation-checklist.md) — what was built each day, including real bugs found and fixed
- [`docs/interview-prep.md`](docs/interview-prep.md) — 41 Q&A covering every topic area, grounded in the actual code
- [`docs/portfolio-description.md`](docs/portfolio-description.md) — resume/LinkedIn descriptions, with an explicit "what this does NOT claim" section

## License

MIT — see [`LICENSE`](LICENSE).
