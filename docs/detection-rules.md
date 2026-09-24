# Detection Rules

Every rule below is implemented in `src/detection/rules.py`
(RULE-001–009) or `src/detection/correlation.py` (RULE-010). No rule
alone produces a verdict — verdicts come from the aggregate risk score
(`src/detection/scoring.py`).

| Rule | Name | Points | Severity | MITRE |
|---|---|---|---|---|
| RULE-001 | Reply-To mismatch | +10 | low | — |
| RULE-002 | SPF failure | +15 | low | — |
| RULE-003 | DKIM failure | +15 | low | — |
| RULE-004 | DMARC failure | +15 | medium | — |
| RULE-005 | Suspicious URL characteristics | +20 | medium | T1566.002 |
| RULE-006 | Visible URL / actual href mismatch | +25 | high | T1566.002 |
| RULE-007 | Suspicious attachment type | +20 | medium | T1566.001 |
| RULE-008 | Known malicious IOC (VirusTotal) | +35 | critical | — |
| RULE-009 | Lookalike / brand-impersonation domain | +20 | medium | T1566.002 |
| RULE-010 | Multiple correlated phishing indicators | +10 to +35 | medium/high | — |

Points are additive and capped at 100 total (see `scoring.py`).

---

### RULE-001 — Reply-To mismatch
**Condition:** From domain differs from Reply-To domain.
**Why it matters:** A common credential-harvesting pattern — the attacker
wants replies (or, more often, this is irrelevant and the real payload is
the URL/attachment) routed to infrastructure they control.
**False positives:** Legitimate mailing lists, support ticketing systems
(Zendesk, Freshdesk), and marketing platforms sending on a company's
behalf routinely set a different Reply-To. **Analyst check:** is the
Reply-To domain a known, sanctioned third-party vendor?

### RULE-002 / 003 / 004 — SPF / DKIM / DMARC failure
**Condition:** The receiving mail system recorded a `fail` result in
`Authentication-Results`.
**Why it matters:** Authentication failures are consistent with sender
spoofing.
**False positives:** All three commonly fail for legitimate reasons:
SPF fail when a third-party sender isn't listed in the domain's SPF
record; DKIM fail when a mailing list or relay modifies the message body
after signing; DMARC fail from simple misconfiguration at a legitimate
domain that hasn't fully deployed DMARC. **Analyst check:** cross-
reference with DMARC alignment (`dmarc_alignment_note` in the report) and
whether the sending domain has a history of legitimate mail.
**Explicit scope limitation:** these results are parsed from the
receiving server's `Authentication-Results` header, not independently
re-verified via DNS or cryptographic signature checking — see
`docs/limitations.md`.

### RULE-005 — Suspicious URL characteristics
**Condition:** A URL has one or more of: IP-based host, excessive
subdomains, `@`-symbol userinfo trick, URL-encoded characters, a known
shortener domain, or a punycode host — and does NOT also have a
visible/href mismatch (that's RULE-006, to avoid double-counting).
**False positives:** Known shorteners and multi-subdomain SaaS platforms
are used legitimately all the time. **Analyst check:** which specific
flag fired matters — an IP-based URL is far more concerning than a
`bit.ly` link from a known marketing tool.

### RULE-006 — Visible URL / actual href mismatch
**Condition:** HTML anchor's visible text is itself a URL/domain that
differs from the actual `href` destination.
**Why it matters:** This is the strongest single indicator this tool
produces — deliberately disguising a link's destination behind unrelated
visible text is rare in legitimate mail.
**False positives:** Marketing/tracking redirectors are the main
legitimate cause. **Analyst check:** is the actual destination domain a
known internal redirector or tracking service?

### RULE-007 — Suspicious attachment type
**Condition:** Attachment extension is in a known-risky set (`.exe`,
`.scr`, `.js`, `.vbs`, `.bat`, `.cmd`, `.ps1`, `.hta`, `.docm`, `.xlsm`,
`.jar`, `.msi`, `.lnk`).
**False positives:** Macro-enabled Office files and scripts have many
legitimate business uses (invoicing templates, internal automation).
File extension alone is never sufficient for a verdict.

### RULE-008 — Known malicious IOC (VirusTotal)
**Condition:** A VirusTotal lookup for an extracted IOC returned
`available=True` with `malicious_votes > 0`. Only fires on confirmed data
— never on the absence of data (no key, timeout, rate limit, etc.).
**False positives:** Vendor detections can include false positives,
especially for newly-registered or repurposed infrastructure. A small
number of malicious votes among many vendors still warrants manual
review rather than automatic, unquestioned escalation.

### RULE-009 — Lookalike / brand-impersonation domain
**Condition:** A domain either contains a watched brand token as a
literal substring (`microsoft-login-example.test`) or is within edit
distance 2 of a brand token on a hyphen-split label (`paypa1-secure.test`
vs `paypal`, catching character-substitution typosquats a literal
substring check misses).
**False positives:** Legitimate third-party services sometimes include a
partner brand name in a subdomain with permission. This is a local
heuristic, not a trademark database — verify manually.

### RULE-010 — Multiple correlated phishing indicators
**Condition:** Fired rules span two or more independent evidence
categories (`authentication`, `sender_identity`, `url`, `attachment`,
`threat_intel`) — see `docs/architecture.md` for why categories, not raw
counts, are used. Bonus: +10 for 2 categories, +20 for 3+, plus an
additional +15 if `threat_intel` co-occurs with anything else.
**False positives:** Correlation reduces but does not eliminate the
chance that one misconfiguration explains everything — still check each
contributing rule's own false-positive note.
