# Architecture

## Overview

PhishGuard SOC is a modular Python CLI pipeline. Each stage reads the
output of the stage before it and produces one clearly-typed output. No
stage reaches backward into another stage's internals — this keeps each
module independently testable (see `tests/`) and means a future web UI
(Phase 2, not built) could call the same pipeline functions without any
rewrite of the analysis logic.

## Data Flow

```
.EML FILE
   |
   v
INPUT HANDLER (src/parser/email_parser.py)
   - loads the file, parses MIME structure, splits text/HTML bodies
     and attachments, never executes anything
   |
   v
HEADER PARSER (src/parser/header_parser.py)
   - extracts From/To/Reply-To/Return-Path/Subject/Date/Message-ID/
     Received/Authentication-Results/etc., safely defaulting missing
     fields to None rather than raising
   |
   +--------------------+--------------------+
   |                    |                    |
   v                    v                    v
HEADER/AUTH ANALYSIS   URL ANALYSIS      ATTACHMENT ANALYSIS
(header_analyzer.py,   (url_analyzer.py)  (attachment_analyzer.py)
 auth_analyzer.py)      - extraction,      - SHA-256/1/MD5 hashing
 - From/Reply-To          visible/href      - risky-extension flags
   mismatch                mismatch
 - display-name           - suspicious      DOMAIN ANALYSIS
   brand spoofing           characteristics  (domain_analyzer.py)
 - SPF/DKIM/DMARC                            - local heuristics only
   parsing from                              - typosquat detection
   Authentication-Results                      (Levenshtein distance)
   |                    |                    |
   +--------------------+--------------------+
                        |
                        v
              IOC EXTRACTION (analysis/ioc_extractor.py)
                 - structured, deduplicated IOC objects
                        |
                        v
        THREAT INTELLIGENCE / OPTIONAL (intelligence/virustotal.py)
                 - domain/IP/URL/hash lookups
                 - degrades gracefully if VT_API_KEY is unset,
                   the API times out, rate-limits, or is unreachable
                        |
                        v
              DETECTION ENGINE (detection/rules.py)
                 - RULE-001 through RULE-009, each independent,
                   each with evidence + false-positive guidance
                        |
                        v
              CORRELATION ENGINE (detection/correlation.py)
                 - RULE-010: fires only when independent evidence
                   CATEGORIES co-occur, not just a raw rule count
                        |
                        v
                RISK SCORING (detection/scoring.py)
                 - deterministic, transparent, capped at 100
                 - CRITICAL requires corroboration, not just a
                   numeric threshold
                        |
                        v
             MITRE ATT&CK MAPPING (mitre/mapper.py)
                 - deduplicated, only justified techniques,
                   parent technique added only when a child
                   technique is present
                        |
                        v
               SOC TRIAGE RESULT
              +---------+---------+
              |                   |
              v                   v
         CLI SUMMARY      REPORT GENERATOR (reporting/report_generator.py)
        (src/main.py)          - Markdown + JSON, written to reports/
```

## Why This Structure

**Independent analyzers, one detection engine.** Each analyzer
(`header_analyzer`, `url_analyzer`, `domain_analyzer`,
`attachment_analyzer`) only produces facts — it never decides whether an
email is malicious. All verdict logic lives in `detection/rules.py` and
`detection/correlation.py`. This separation is what makes false-positive
documentation possible: each analyzer's output is inspectable
independently of the scoring that follows it.

**Correlation is category-based, not count-based.** SPF, DKIM, and DMARC
often fail together from one root cause (a misconfigured sender). Counting
"3 rules fired" as strong evidence would double/triple-count one signal.
`correlation.py` groups rules into five independent evidence categories
and only escalates confidence when categories — not just rule IDs — agree.

**Threat intelligence is bolted on, not load-bearing.** `virustotal.py` is
called from `main.py` only if `VT_API_KEY` is set, and every failure mode
(missing key, invalid key, timeout, rate limit, malformed response) returns
a typed `VTLookupResult(available=False, error=...)` rather than raising.
`RULE-008` only fires on `available=True` results — the absence of
threat-intel data is never treated as a signal.

## Known Structural Deviation

The original design named "IOC EXTRACTION" as a pipeline stage but didn't
assign it a file in the repository tree. It lives at
`src/analysis/ioc_extractor.py`, alongside the analyzers it consumes
output from, rather than inventing a new top-level package for one file.
