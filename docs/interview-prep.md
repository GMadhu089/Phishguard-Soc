# Interview Preparation — PhishGuard SOC

Every answer here is grounded in what is actually implemented in this
repository. If you get asked something and your honest answer is "I
didn't implement that," say that — it's a better answer than pretending.

---

## THE Most Important Question

### "Why did you build this when existing security tools already perform phishing detection?"

**My answer:**

"I'm not trying to replace Defender, Proofpoint, or any SEG — those do
things I couldn't replicate as a fresher project: real-time mail-flow
interception, sandboxed detonation, vendor threat-intel feeds at scale.
What I noticed is that even with those tools in place, an L1 SOC analyst
still manually repeats the same first-pass triage on every alert that
reaches their queue: read the headers, check SPF/DKIM/DMARC, compare the
visible link text to where it actually goes, hash the attachment, write
up notes. I automated exactly that repeatable first pass. The tool
extracts IOCs, correlates multiple independent signals instead of
trusting any single one, enriches indicators against VirusTotal when
available, maps justified behavior to MITRE ATT&CK, and generates an
analyst-ready report — all as a static, local, pre-triage step before a
human (or the real security stack) makes the actual call."

This answer works because it explicitly: (1) shows you understand what
the existing products do, (2) doesn't claim to replace them, (3) names
the specific repetitive task you automated, (4) lists the concrete
technical things you built (correlation, IOC extraction, enrichment,
MITRE mapping, reporting) as evidence you understand SOC work, not just
Python.

---

## The 15 Most Important Questions

(All 15 are also included in the full list below, marked with ⭐.)

1. Why did you build this when Microsoft Defender already detects phishing? *(see above)*
2. Why not simply use VirusTotal?
3. What does SPF actually do?
4. Does SPF failure mean the email is malicious?
5. What does DKIM do?
6. What does DMARC do?
7. Can DMARC pass and the email still be malicious?
8. How do you determine the sender IP?
9. Can you trust Received headers?
10. How do you detect a fake Microsoft login link?
11. How does your risk score work?
12. How do you handle false positives?
13. What happens if VirusTotal is unavailable?
14. What happens after the user clicks the phishing link?
15. What are the limitations of your project?

---

## Full Q&A

### Project Overview

**Q: What does this project do, in one sentence?**
**My answer:** It's an automated first-level triage tool that takes a
suspicious `.eml` file and produces a scored, evidence-backed SOC
investigation report — headers, authentication, URLs, attachments, IOCs,
detection rules, MITRE mapping, all in one pass.
**Technical explanation:** A Python CLI pipeline: parse → analyze
(header/auth/URL/domain/attachment) → extract IOCs → optionally enrich
via VirusTotal → run 10 detection rules → correlate → score → map MITRE
→ generate Markdown/JSON report.
**Follow-up:** What would you build next if you had more time?
**Follow-up answer:** A simple web UI (Phase 2, explicitly scoped out of
this MVP) and a larger, non-hardcoded brand/typosquat reference list.

**Q: ⭐ Why not simply use VirusTotal?**
**My answer:** VirusTotal only tells you about infrastructure it already
has reputation data on — brand-new phishing domains registered an hour
ago won't be flagged yet. My tool's local heuristics (typosquat
detection, visible/href mismatch, auth failures) catch structural
red flags regardless of whether VT has seen the infrastructure before.
VT is genuinely useful as corroboration — that's exactly why RULE-008
exists — but it's an enrichment layer, not the core detection engine,
by design.
**Technical explanation:** `virustotal.py` is called optionally from
`main.py`, and every failure mode (missing key, timeout, rate limit,
404) returns a typed `available=False` result. RULE-008 only fires on
`available=True` with `malicious_votes > 0` — absence of VT data is
never itself a signal.
**Follow-up:** What if VirusTotal flags something my local heuristics miss?
**Follow-up answer:** That's exactly the intended synergy — RULE-008 can
fire independently of every other rule, and if it's the only thing that
fires, correlation (RULE-010) won't kick in but the score (+35, severity
"critical") still reflects that confirmed external corroboration matters
more than an unconfirmed local heuristic.

---

### Architecture

**Q: Walk me through your architecture.**
**My answer:** Parsing is fully separated from analysis, which is fully
separated from verdict logic. `email_parser.py` and `header_parser.py`
only extract facts. `header_analyzer.py`, `url_analyzer.py`,
`domain_analyzer.py`, `attachment_analyzer.py` only produce structured
indicators — none of them decide anything is malicious. All verdict
logic lives in `detection/rules.py` and `detection/correlation.py`.
**Technical explanation:** This separation means each analyzer is unit-
testable in isolation (see `tests/test_url_analyzer.py`, etc.) without
needing to construct a full email, and it's why false-positive
documentation is possible — each analyzer's output is inspectable
independently of the scoring that follows it.
**Follow-up:** Why is IOC extraction in `analysis/` and not its own
top-level package?
**Follow-up answer:** The original spec named "IOC extraction" as a
pipeline stage but didn't assign it a file in the repo tree. Rather than
invent a new top-level package for one file, I put it alongside the
analyzers it directly consumes output from. I documented this decision
explicitly rather than silently deviating.

**Q: Why is threat intelligence "bolted on" rather than core?**
**My answer:** Because the tool has to work with zero external
dependencies configured — that was an explicit requirement. If
VirusTotal being down or unconfigured broke detection entirely, the tool
would be fragile in exactly the way a triage tool can't afford to be.
**Technical explanation:** `main.py` checks `os.getenv("VT_API_KEY")`
before calling any VT function at all; if absent, `vt_results` stays an
empty list and the rest of the pipeline runs unmodified.
**Follow-up:** How did you test that VT failures don't break the pipeline?
**Follow-up answer:** `tests/test_virustotal.py` mocks every failure mode
(401, 429, 404, timeout, connection error, malformed JSON) and asserts
each returns `available=False` without raising — no test in that file
makes a real network call.

---

### Python

**Q: Why dataclasses instead of dicts for your internal data structures?**
**My answer:** Type safety and self-documentation. A `FiredRule` or
`ExtractedURL` dataclass tells you exactly what fields exist without
needing to trace through where the dict was built.
**Technical explanation:** Every analyzer returns a `@dataclass` (e.g.
`ParsedHeaders`, `AuthAnalysis`, `ExtractedURL`), which also makes
`asdict()` (used in `report_generator.py`) trivial for JSON
serialization.
**Follow-up:** Where did you use `frozen=True`, and why?
**Follow-up answer:** `IOC` in `ioc_extractor.py` — frozen so it's
hashable and can go directly into a `set()` for deduplication, which is
the whole point of that module.

**Q: How do you avoid crashing on malformed input throughout this project?**
**My answer:** Every parsing function catches specific exceptions at the
narrowest point possible and returns a safe default (`None`, empty list,
or a warning) instead of letting the exception propagate.
**Technical explanation:** `email_parser.py`'s `load_eml_file` catches
`OSError` on file read and generic parse failures separately;
`header_parser.py` never raises on a missing header, it appends to
`missing_headers` instead. This is tested directly —
`test_email_parser.py::test_malformed_email_does_not_crash`.
**Follow-up:** What's one bug you found during development related to this?
**Follow-up answer:** Not directly a crash bug, but a silent-failure bug:
my first `url_analyzer.py` used `str.lstrip("www.")` to normalize
hostnames for mismatch comparison. `lstrip` strips *characters*, not a
literal prefix — it turned `wallet.com` into `allet.com`. I caught it by
testing against a domain starting with 'w' that wasn't a www-prefixed
host, and fixed it with an explicit prefix check. There's a regression
test for this exact case in `test_url_analyzer.py`.

---

### Email / SMTP / MIME

**Q: What's the difference between an email's envelope and its headers?**
**My answer:** The envelope (MAIL FROM / RCPT TO in SMTP) is what mail
servers actually route on; the From/To headers are just displayed
content and can say anything the sender wants. Return-Path reflects the
envelope sender as recorded by the receiving server.
**Technical explanation:** This is exactly why SPF checks the envelope
sender (`smtp.mailfrom=`) while DMARC checks the visible From header
domain — a mismatch between them is meaningful and is exactly what
`dmarc_alignment_note` in `auth_analyzer.py` computes.
**Follow-up:** Where in your code do you use Return-Path?
**Follow-up answer:** It's extracted in `header_parser.py` and included
in reports, but I don't currently build a dedicated detection rule on
Return-Path/From mismatch specifically — that's a reasonable extension I
didn't implement (see limitations).

**Q: How does your tool handle multipart MIME emails?**
**My answer:** It walks the full MIME tree and separates text/plain,
text/html, and attachment parts based on Content-Type and
Content-Disposition.
**Technical explanation:** `email_parser.py`'s `_extract_bodies_and_attachments`
calls `msg.walk()` for multipart messages, classifying each leaf part;
container `multipart/*` parts themselves are skipped since they carry no
content. Tested directly in
`test_email_parser.py::test_multipart_email_extracts_text_and_html`.
**Follow-up:** What MIME types does it NOT specially handle?
**Follow-up answer:** Anything besides text/plain, text/html, and
attachments — e.g. `text/calendar` invites are currently ignored rather
than parsed, a documented limitation, not silently misclassified.

---

### Headers

**Q: ⭐ Can you trust Received headers?**
**My answer:** Only partially. Received headers are added by each
relaying server on the path, listed newest-first, and any hop can be
forged by an attacker-controlled server earlier in the chain. My tool
extracts and classifies every candidate IP but never assumes the first
or last one is the attacker.
**Technical explanation:** `header_parser.py`'s `_extract_candidate_ips`
preserves hop order via `source_header_index` and classifies each IP as
private/public/reserved/invalid using Python's `ipaddress` module, but
draws no conclusion about attribution — that's explicitly documented as
a limitation in both the module docstring and `docs/limitations.md`.
**Follow-up:** How would you actually attribute the true origin IP in practice?
**Follow-up answer:** You'd need to know which of your own mail
infrastructure hops are trusted (internal relays) and only trust the
first *untrusted* hop past your own infrastructure — that's
organization-specific configuration this tool doesn't have.

**Q: ⭐ How do you determine the sender IP?**
**My answer:** I don't determine *the* sender IP with certainty — I
extract every IPv4 address found across all Received headers and
classify each as private, public, or reserved, then leave interpretation
to the analyst.
**Technical explanation:** Same as above — see `CandidateIP` in
`header_parser.py`. This was a deliberate design choice per the spec's
explicit instruction not to assume "first IP = attacker."
**Follow-up:** Why not just always take the first public IP?
**Follow-up answer:** Because a compromised or attacker-controlled relay
could sit anywhere in the chain, and without knowing your own trusted
infrastructure boundary, "first public IP" is a guess, not a fact.

---

### SPF / DKIM / DMARC

**Q: ⭐ What does SPF actually do?**
**My answer:** SPF (Sender Policy Framework) lets a domain publish, via
DNS TXT record, which mail servers are authorized to send email on its
behalf. The receiving server checks whether the connecting server's IP
is in that authorized list.
**Technical explanation:** My tool doesn't perform this DNS check itself
— it parses the `spf=` result the receiving mail system already computed
and recorded in `Authentication-Results`. This is explicitly stated in
`auth_analyzer.py`'s `data_source_note`.
**Follow-up:** Why didn't you implement live SPF checking?
**Follow-up answer:** Time constraints for a 3-4 day project, and the
receiving server has already done this check more reliably than I could
reproduce (it has access to the actual connecting IP at SMTP time, which
a static `.eml` file doesn't preserve in a directly re-checkable way).

**Q: ⭐ Does SPF failure mean the email is malicious?**
**My answer:** No. SPF fail is common for entirely legitimate reasons —
a third-party sending service (like a CRM or marketing platform) that
isn't listed in the domain's SPF record, or plain misconfiguration.
**Technical explanation:** RULE-002 fires on SPF fail but only
contributes 15 points at "low" severity, and its `false_positive_note`
explicitly states this. No single rule in this project produces a
verdict on its own — see `docs/detection-rules.md`.
**Follow-up:** How much more confidence does SPF fail + DKIM fail + DMARC
fail together give you?
**Follow-up answer:** Less than you'd think, actually — all three often
fail together from ONE root cause (misconfiguration), so my correlation
engine (RULE-010) deliberately groups them into a single "authentication"
category rather than counting them as three independent signals.

**Q: ⭐ What does DKIM do?**
**My answer:** DKIM (DomainKeys Identified Mail) lets the sending domain
cryptographically sign parts of the email; the receiving server verifies
that signature against a public key published in the sender's DNS.
**Technical explanation:** My tool parses the `dkim=` result and `d=`/`s=`
values from `Authentication-Results` — it does not perform the actual
cryptographic signature verification itself. This is explicitly stated
in the module docstring and `dkim_data_source_note`-equivalent field.
**Follow-up:** What would break DKIM validation for a legitimate email?
**Follow-up answer:** Any modification to the signed content after
signing — e.g. a mailing list appending a footer, or a relay rewriting
headers — which is exactly why RULE-003's false-positive note calls this
out.

**Q: ⭐ What does DMARC do?**
**My answer:** DMARC ties SPF and DKIM together with a policy — it
requires that at least one of them "aligns" with the visible From
domain, and tells receiving servers what to do (none/quarantine/reject)
if alignment fails.
**Technical explanation:** `auth_analyzer.py`'s `_build_dmarc_note`
computes alignment by comparing the DMARC `header.from=` domain against
the visible From address domain, and reports "aligned"/"misaligned"/
"unknown" explicitly.
**Follow-up:** What's the difference between DMARC "alignment" and DMARC "pass"?
**Follow-up answer:** DMARC "pass"/"fail" as reported in
`Authentication-Results` already accounts for alignment — I'm not
computing DMARC's pass/fail decision myself, only re-deriving the
alignment detail for the analyst's benefit alongside the already-computed
result.

**Q: ⭐ Can DMARC pass and the email still be malicious?**
**My answer:** Yes. DMARC only proves the visible From domain wasn't
spoofed and the sender controls that domain's SPF/DKIM — it says nothing
about the sender's intent. An attacker who registers
`paypa1-secure.test` and properly configures SPF/DKIM/DMARC for *that*
domain will pass DMARC cleanly while still being a lookalike-domain
phishing attempt.
**Technical explanation:** This is exactly why RULE-009 (lookalike domain)
is a completely independent check from RULE-002/003/004 (auth) — my
`lookalike_domain_example.eml` sample actually has SPF/DKIM/DMARC all
*failing* in my sample, but I could just as easily have configured that
sample's synthetic domain to pass DMARC and RULE-009 would still fire
on its own, since domain heuristics don't depend on auth results at all.
**Follow-up:** So what's DMARC actually protecting against, if not this?
**Follow-up answer:** Domain spoofing — someone sending mail claiming to
be `paypal.com` itself without controlling `paypal.com`'s DNS. It does
nothing about lookalike domains the attacker actually owns and
legitimately configures.

---

### URLs

**Q: ⭐ How do you detect a fake Microsoft login link?**
**My answer:** Two independent mechanisms: RULE-006 catches when the
visible link text (e.g. `https://www.microsoft.com`) doesn't match the
actual `href` destination, and RULE-009 catches when the destination
domain itself contains "microsoft" as a substring or is a close
character-substitution typo of it, without being microsoft's real domain.
**Technical explanation:** `url_analyzer.py`'s `_check_visible_href_mismatch`
does the first; `domain_analyzer.py`'s `_find_brand_impersonation` and
`_find_typosquat` (Levenshtein distance ≤2 on hyphen-split tokens) do
the second. They're independent — either can fire without the other.
**Follow-up:** What if the attacker uses a completely unrelated domain
with no brand name and no mismatch — just a generic phishing page?
**Follow-up answer:** Then neither RULE-006 nor RULE-009 fires on domain/
URL grounds alone, but RULE-005 (suspicious URL characteristics — IP-based
host, excessive subdomains, encoding, etc.) or the authentication rules
might still catch it. This is exactly why correlation across independent
categories matters more than any single rule.

**Q: What's a mismatch a legitimate email could also trigger?**
**My answer:** Marketing/tracking redirectors — e.g. a link whose visible
text says the destination but whose actual href goes through a tracking
domain first.
**Technical explanation:** RULE-006's `false_positive_note` calls this out
explicitly. The mitigation is manual: check whether the actual
destination domain is a known internal redirector.
**Follow-up:** Could you programmatically whitelist known redirectors?
**Follow-up answer:** Yes, that's a reasonable extension — a small
allowlist of known corporate tracking domains checked before flagging
RULE-006. I didn't implement it because I don't have a real
organization's redirector list to build it against honestly.

---

### Domains

**Q: How does your typosquat detection work?**
**My answer:** I compute Levenshtein (edit) distance between each
hyphen-split token of the domain's first label and a small list of
watched brand names, and flag anything within edit distance 2.
**Technical explanation:** This exists specifically because a naive
substring check (`"paypal" in domain`) misses character-substitution
typosquats like `paypa1-secure.test`. I found this gap during testing —
my first synthetic sample for this exact scenario silently produced zero
flags until I added edit-distance matching.
**Follow-up:** Why edit distance 2 specifically, not 1 or 3?
**Follow-up answer:** Distance 1 misses two-character typos (e.g. a
transposition plus a substitution); distance 3+ starts producing false
positives on legitimately similar but unrelated short domain names. 2
was a judgment call, not derived from a dataset — a real deployment
would want to tune this against actual traffic.

---

### IOCs

**Q: What counts as an IOC in your tool, and how do you avoid duplicates?**
**My answer:** Email addresses, IPv4s from Received headers, domains,
URLs, and file hashes (SHA-256/1/MD5) and filenames from attachments.
Deduplication happens by putting everything into a Python `set` of
frozen dataclasses.
**Technical explanation:** `IOC` in `ioc_extractor.py` is
`@dataclass(frozen=True)`, which makes it hashable; the same domain
appearing in both the plain-text and HTML body of an email collapses to
one IOC entry. Tested in
`test_ioc_extractor.py::test_duplicate_iocs_are_deduplicated`.
**Follow-up:** How do you decide an IOC's confidence level?
**Follow-up answer:** Simple, deterministic rules — not ML: an IOC tied
to a flagged/suspicious source (e.g. a URL with visible/href mismatch,
or a risky-extension attachment's hash) gets "high"; a normal extracted
URL/domain gets "medium"; header metadata alone (like the From address)
gets "low."

---

### VirusTotal

**Q: ⭐ What happens if VirusTotal is unavailable?**
**My answer:** The tool keeps working normally. Every failure mode —
missing API key, invalid key, rate limiting, timeout, network failure,
malformed response — is caught and returns a typed "unavailable" result
with a human-readable reason. RULE-008 simply doesn't fire, and nothing
else in the pipeline depends on VT succeeding.
**Technical explanation:** `virustotal.py`'s `_safe_get` wraps every
`requests.get` call in specific exception handling
(`Timeout`, `ConnectionError`, generic `RequestException`) and checks
HTTP status codes explicitly (401/429/404/other non-200) before ever
attempting to parse a response body. All 8 failure paths are tested with
mocks in `test_virustotal.py` — no test makes a real network call.
**Follow-up:** Why didn't you build in retry logic for rate limits?
**Follow-up answer:** For a triage tool, failing fast and clearly
labeling "unavailable" is more honest than silently retrying and
potentially hanging the CLI — the analyst can see the reason and decide
whether to re-run later.

---

### Detection Engineering

**Q: Walk me through how one detection rule is structured.**
**My answer:** Every rule is a small pure function taking a shared
`RuleContext` and returning either `None` (didn't fire) or a `FiredRule`
carrying evidence, a point value, a severity contribution, an optional
MITRE technique, and a mandatory false-positive explanation.
**Technical explanation:** See any function in `detection/rules.py`,
e.g. `_rule_006_visible_href_mismatch`. The false-positive note isn't
optional — `test_rules.py::test_every_fired_rule_has_a_false_positive_note`
enforces every fired rule has a non-empty one.
**Follow-up:** Why not use a rules engine library (e.g. a YAML-based DSL)?
**Follow-up answer:** For 10 rules at this scale, plain Python functions
are more debuggable and testable than a DSL would be, and every rule
needs custom evidence-formatting logic that a generic engine would fight
against. I'd reconsider for 50+ rules.

**Q: How do RULE-005 and RULE-006 avoid double-counting the same URL?**
**My answer:** RULE-005 explicitly excludes any URL that already has a
`visible_href_mismatch` flag, so a URL with ONLY that flag triggers
RULE-006 and not RULE-005.
**Technical explanation:** `_rule_005_suspicious_url`'s filter is
`u.suspicious_flags and not u.visible_href_mismatch`. Tested directly in
`test_rules.py::test_visible_href_mismatch_fires_rule_006_not_rule_005`.
**Follow-up:** What if a URL has BOTH a mismatch AND, say, an IP-based host?
**Follow-up answer:** Then it still only avoids RULE-005 because of the
`not visible_href_mismatch` filter — meaning in that specific edge case,
the IP-based flag wouldn't get its own RULE-005 credit. That's an actual
minor gap I noticed while writing this doc — a reasonable improvement
would be checking "any suspicious flag OTHER than mismatch" rather than
excluding the whole URL.

---

### Correlation

**Q: How does your correlation engine avoid inflating confidence from one root cause?**
**My answer:** By grouping rules into independent evidence *categories*
rather than counting raw rule IDs. SPF+DKIM+DMARC failing together is 3
rule IDs but 1 category ("authentication"), so it alone never triggers
correlation.
**Technical explanation:** `correlation.py`'s `_RULE_TO_CATEGORY` maps
each rule to one of 5 categories; RULE-010 only fires when 2+ categories
are represented among fired rules. Tested directly in
`test_correlation.py::test_single_category_does_not_fire_correlation`.
**Follow-up:** Why does threat_intel get an extra bonus when it co-occurs?
**Follow-up answer:** Because it's external, confirmed corroboration
rather than another local heuristic agreeing with itself — qualitatively
stronger evidence, so it's weighted more (+15 on top of the base bonus).

---

### Risk Scoring

**Q: ⭐ How does your risk score work?**
**My answer:** It's a deterministic sum of every fired rule's point value
plus any correlation bonus, capped at 100. I call it a "Risk Score," not
a probability, because it's not statistically derived — it's a
transparent count of how much rule-based evidence exists.
**Technical explanation:** `scoring.py`'s `calculate_risk` sums
`ContributingFactor.points` across all fired rules and the correlation
result, capping via `min(raw_score, 100)`. Every contributing factor is
shown by name in the generated report — nothing is a black box.
**Follow-up:** Why does CRITICAL require more than just crossing the top
score threshold?
**Follow-up answer:** Because accumulating enough small heuristic points
(several low-severity rules) could mathematically reach 75+ without any
single strong signal — I didn't want that to look identical to a
confirmed-malicious-IOC case. CRITICAL requires either an extreme score
(≥90) or explicit corroboration like a fired RULE-008. I actually
designed this after noticing my first version would've made CRITICAL a
routine outcome for any heavily-flagged-but-still-heuristic-only email.

**Q: Are your point values (10, 15, 20, 25, 35...) derived from data?**
**My answer:** No — they're my own judgment calls based on how strong
each signal is in isolation (e.g. a visible/href mismatch at +25 is
weighted higher than a lone Reply-To mismatch at +10), not from any
labeled dataset.
**Technical explanation:** This is worth being upfront about — a
production system would tune these against real historical alert data
and analyst feedback, which I don't have access to for a portfolio
project.
**Follow-up:** How would you validate these weights if you had real data?
**Follow-up answer:** Compare rule-firing patterns against a labeled set
of confirmed-phishing vs. confirmed-benign historical alerts, and adjust
weights to minimize false positive/negative rates at each severity band.

---

### False Positives

**Q: ⭐ How do you handle false positives?**
**My answer:** Every single rule ships with a mandatory,
specific false-positive explanation telling the analyst exactly what
legitimate scenario could trigger it and what to check before
escalating — not a generic disclaimer.
**Technical explanation:** `FiredRule.false_positive_note` is a required
field, and it's enforced by test — see
`test_rules.py::test_every_fired_rule_has_a_false_positive_note`. See
`docs/detection-rules.md` for the full list.
**Follow-up:** Give me a specific example.
**Follow-up answer:** RULE-002 (SPF fail): commonly false-positives when
a legitimate third-party sending service isn't listed in the domain's
SPF record — the note tells the analyst to cross-reference DMARC
alignment and the sending domain's history before treating it as
meaningful.

---

### MITRE

**Q: Why do you only map to T1566 and its two children?**
**My answer:** Because this tool only has visibility into the email
itself — it can't observe what happens after delivery (execution,
credential entry, lateral movement), so mapping further down the kill
chain would be an unjustified guess.
**Technical explanation:** `mitre/mapper.py` only includes a technique
when a specific fired rule explicitly carries that `mitre_technique`
value — nothing is inferred or assumed.
**Follow-up:** Why is T1566 (the parent) only added conditionally?
**Follow-up answer:** Asserting the parent technique standalone, without
a child technique justifying it, would be a vague, unfalsifiable claim.
It's only inserted when T1566.001 or T1566.002 is already present, and
its `reason` field says explicitly why it was added.

---

### Incident Response

**Q: ⭐ What happens after the user clicks the phishing link?**
**My answer:** Honestly — I don't know, and my tool can't tell me. That's
outside its scope entirely. Static email analysis can tell you a link
was suspicious; it has zero visibility into what happened in the
browser or on the endpoint afterward.
**Technical explanation:** This is exactly why every report's
`alert_vs_incident_note` and `known_vs_unknown` fields exist — to make
that boundary explicit rather than implying the tool knows more than it
does. Finding out requires proxy logs (did the connection happen), DNS
logs (did the endpoint resolve the domain), and potentially EDR
telemetry (did anything execute) — all listed as scope questions in
every generated report.
**Follow-up:** So what's the actual value of flagging the link at all,
if you can't know the outcome?
**Follow-up answer:** Prevention and speed — flagging it before/as soon
as delivered lets the SOC block the domain at the proxy and warn the
user before they click, and gives Tier 2 a head start on exactly which
questions to check first, rather than starting a scope investigation
from zero.

**Q: What's the difference between an alert and an incident in your tool's language?**
**My answer:** This tool produces ALERTS — evidence a phishing email was
delivered. It becomes an INCIDENT only with corroborating evidence found
elsewhere (endpoint execution, confirmed credential entry) — this tool
alone can't prove that.
**Technical explanation:** Every generated report includes an explicit
`alert_vs_incident_note` field stating this, plus a `known_vs_unknown`
section separating what the tool actually knows from what requires
SIEM/EDR data.
**Follow-up:** What would you need to see to escalate an alert to a
confirmed incident?
**Follow-up answer:** Proxy/DNS logs showing the user's endpoint actually
reached the malicious domain, or EDR/Sysmon telemetry showing process
execution tied to an attachment hash — exactly the scope questions listed
in every generated report.

---

### Splunk / Wazuh

**Q: How does this integrate with Splunk or Wazuh?**
**My answer:** It doesn't, live — it generates illustrative example
queries built from the extracted IOCs (domain/IP/hash) that an analyst
can adapt to their own index and sourcetype naming.
**Technical explanation:** `report_generator.py`'s `_build_example_queries`
builds these strings but never executes them — no Splunk/Wazuh
connector exists in this project.
**Follow-up:** Why didn't you build a live integration?
**Follow-up answer:** It would require credentials and a live SIEM
instance I don't have for a portfolio project, and it would tie the
tool's core value (static triage) to infrastructure most reviewers of
this project won't have running either. The illustrative queries still
demonstrate I know how to bridge IOCs into SIEM investigation, without
overclaiming a live integration I didn't build.

---

### Automation

**Q: What parts of this project are actually automated end-to-end?**
**My answer:** Everything from `.eml` file in to Markdown/JSON report
out — one CLI command, no manual steps in between.
**Technical explanation:** `python -m src.main analyze <file>` runs the
entire pipeline shown in `docs/architecture.md` synchronously.
**Follow-up:** What isn't automated?
**Follow-up answer:** Report generation writes files, but nothing
automatically emails, tickets, or escalates the result anywhere — that
integration (e.g. into a ticketing system) is out of scope for this MVP.

---

### Limitations

**Q: ⭐ What are the limitations of your project?**
**My answer:** The honest list: SPF/DKIM results are parsed from
`Authentication-Results`, not independently re-verified; domain analysis
is local-heuristic-only with a small hardcoded brand list; attachment
analysis is static/hash-only, never sandboxed; risk score weights are my
own judgment, not data-derived; and critically, this tool can never prove
a user actually interacted with a malicious email — that requires
SIEM/EDR data it doesn't have.
**Technical explanation:** All of this is written down, not just spoken
— see `docs/limitations.md`, which I treated as a required deliverable,
not an afterthought.
**Follow-up:** Which limitation concerns you most for real-world use?
**Follow-up answer:** Trusting `Authentication-Results` at face value —
if that header itself were forged by a malicious or compromised
upstream relay, my SPF/DKIM/DMARC analysis would be built on bad data.
A production deployment would want the analysis running at the actual
receiving MTA, not on an exported `.eml` file after the fact.

---

### Additional Questions Across Categories

**Q: Which part of the codebase would you refactor first if you kept working on this?**
**My answer:** `main.py` — it's grown into one long function doing parsing, analysis orchestration, and CLI printing all together. I'd split it into a `pipeline.py` returning a structured result object, with `main.py` reduced to argument parsing and printing.
**Technical explanation:** Right now `run_analyze()` in `main.py` both runs the full pipeline AND formats CLI output — a web UI (Phase 2) would need that pipeline logic extracted and reused without the print statements.
**Follow-up:** Why didn't you do that from the start?
**Follow-up answer:** For a 3-4 day MVP, I prioritized working functionality over ideal structure everywhere except the modules that clearly needed independent testability (the analyzers) — `main.py`'s orchestration role was lower risk to leave coupled for now.

---

### SMTP / MIME (additional)

**Q: What's the difference between Content-Type and Content-Disposition, and why do you check both?**
**My answer:** Content-Type says what KIND of data a MIME part is (text/plain, application/pdf); Content-Disposition says how it should be presented (inline vs. attachment). I check both because a part can be a legitimate attachment without Content-Disposition explicitly saying "attachment" — some mail clients omit it.
**Technical explanation:** `email_parser.py`'s `_handle_part` treats a part as an attachment if EITHER `Content-Disposition` says "attachment" OR the part has a filename and isn't text/plain or text/html — covering mail clients that skip the disposition header.
**Follow-up:** Could this misclassify something as an attachment that shouldn't be?
**Follow-up answer:** Potentially an inline image referenced by a `cid:` in HTML — it would be extracted as an attachment even though it's meant to render inline. I don't currently special-case that; it's a minor known gap.

---

### Headers (additional)

**Q: How do you detect a spoofed display name like "Microsoft Account Team"?**
**My answer:** I parse the display name out of the From header, check it against a small list of watched brand tokens, and flag it if the brand is mentioned but the actual sending domain doesn't contain that brand — unless it's the brand's own legitimate domain.
**Technical explanation:** `header_analyzer.py`'s `_display_name_claims_brand` does a simple lowercase substring check; `analyze_headers` cross-references the actual From domain before flagging, so `Microsoft Account Team <no-reply@microsoft.com>` is correctly NOT flagged.
**Follow-up:** What's a legitimate scenario that would still false-positive here?
**Follow-up answer:** A legitimate partner or reseller whose display name mentions a brand they're authorized to represent but sends from their own domain — the false-positive note explicitly calls this out.

---

### Domains (additional)

**Q: Why do you separate "local heuristic" results from "threat intelligence" results so explicitly in your data model?**
**My answer:** Because they carry very different weight and reliability — a heuristic is a pattern match I wrote; threat intelligence is external, aggregated vendor data. Conflating them in a report would mislead an analyst about how much to trust the finding.
**Technical explanation:** `DomainHeuristicResult` has an explicit `label_source: str = "local_heuristic"` field that's always populated, and the report renders it inline next to every domain flag (e.g. "(local_heuristic)") so it's never ambiguous.
**Follow-up:** Could you have used a type system to enforce this separation instead of a string field?
**Follow-up answer:** Yes — a more rigorous approach would be a shared `Finding` base class with a `source_type` enum rather than a free-text field. I used a simple string for MVP speed; an enum would catch typos at development time.

---

### IOCs (additional)

**Q: Why does a private/internal IP still get extracted as an IOC, just at lower confidence, instead of being dropped entirely?**
**My answer:** Because even a private IP in a Received header can matter for internal correlation — e.g. matching it against your own internal relay's known IP range confirms or denies whether that hop is trusted infrastructure.
**Technical explanation:** `ioc_extractor.py`'s `_extract_header_iocs` still adds private/reserved IPs as `ipv4` IOCs but at `confidence="low"` rather than `"medium"`, so the analyst sees them but isn't misled into treating them as external threat indicators.
**Follow-up:** Would you ever want to filter private IPs out entirely?
**Follow-up answer:** For a purely external threat-intel workflow (e.g. auto-submitting IOCs to VirusTotal), yes — you'd filter to public IPs only, which is exactly what `main.py`'s VT enrichment loop does implicitly by only looking up domains, not raw candidate IPs, in the current implementation.

---

### Detection Engineering (additional)

**Q: How would you add an eleventh detection rule to this codebase?**
**My answer:** Write a new `_rule_011_whatever(ctx: RuleContext) -> Optional[FiredRule]` function following the same pattern as the existing nine, add it to the tuple of rule functions in `evaluate_rules`, and write a test asserting it fires/doesn't fire on the right inputs plus has a false-positive note.
**Technical explanation:** The modular function-per-rule design in `rules.py` makes this a pure addition — no existing rule's code needs to change, which is exactly the point of keeping rules independent.
**Follow-up:** What's a rule you'd add next, given more time?
**Follow-up answer:** A Return-Path/From mismatch rule, distinct from Reply-To mismatch — Return-Path reflects the actual envelope sender and a mismatch there is arguably a stronger signal than Reply-To, which I extract but don't currently build a dedicated rule around.

---

### MITRE (additional)

**Q: If this tool detected credential harvesting specifically, would you map to T1589 (Gather Victim Identity Information) or similar?**
**My answer:** No — I deliberately didn't add speculative mappings beyond what's directly justified. Detecting a credential-harvesting-*shaped* URL doesn't prove credential harvesting occurred; it's still just T1566.002 (the delivery mechanism), not a later-stage technique I have no evidence for.
**Technical explanation:** `mitre/mapper.py`'s technique table only contains T1566/T1566.001/T1566.002 — adding more would require either new detection logic that actually justifies them or would violate the "map only justified techniques" principle this project was built under.
**Follow-up:** What evidence would justify a credential-access mapping?
**Follow-up answer:** Confirmation the user actually submitted credentials to the page — which requires proxy/DNS logs or user interview, outside this tool's static-analysis scope entirely.

---

### Splunk / Wazuh (additional)

**Q: Why Splunk and Wazuh specifically in your example queries, and not something else?**
**My answer:** Because those are the platforms I have hands-on experience with, so the example queries reflect syntax I actually understand and can defend, rather than copying syntax for a tool I've never used.
**Technical explanation:** `_build_example_queries` in `report_generator.py` hardcodes Splunk SPL-style and Wazuh rule-group-style syntax; adapting it to, say, Microsoft Sentinel's KQL would be straightforward but I didn't do it since I can't personally validate that syntax against a real instance.
**Follow-up:** How would you validate these example queries actually work?
**Follow-up answer:** Run them against a real Splunk/Wazuh instance with test data and confirm the field names match your actual index schema — I explicitly labeled them "illustrative — adapt to your environment" rather than claiming they're drop-in ready, since field names vary by deployment.

---

### Automation / Limitations (additional)

**Q: If you had to demo this live in an interview right now, what would you show?**
**My answer:** I'd run the credential-harvest sample, show the CLI summary hitting CRITICAL/100, then open the generated Markdown report and walk through the Detection Rules and Correlation sections specifically — that's where the design decisions (category-based correlation, mandatory false-positive notes) are most visible.
**Technical explanation:** That exact walkthrough is reproducible with `python -m src.main analyze samples/phishing/credential_harvest_example.eml` — no setup beyond `pip install -r requirements.txt`, no API key required.
**Follow-up:** What would you show if asked to prove it doesn't just always say "CRITICAL"?
**Follow-up answer:** Run all 8 samples back to back — 3 benign score exactly 0/CLEAN, and the 5 phishing samples span LOW (25, 45) through HIGH (75) to CRITICAL (100), showing the score genuinely reflects evidence strength rather than being hardcoded or binary.
