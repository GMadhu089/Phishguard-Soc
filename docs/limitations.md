# Limitations

Honest accounting of what this tool does not do, matching the "AI-
generated project safety" requirement this project was built under: no
feature is claimed that isn't actually implemented.

## Authentication (SPF/DKIM/DMARC)

- **No live DNS lookups.** SPF and DMARC results are parsed entirely from
  the receiving mail system's `Authentication-Results` header, not
  independently verified against the sending domain's DNS records at
  analysis time.
- **No cryptographic DKIM verification.** The DKIM result is likewise
  read from `Authentication-Results`, not verified against the actual
  DKIM public key and signature. If the `Authentication-Results` header
  itself is missing, forged, or from an untrusted intermediate relay,
  these results cannot be trusted at face value — this is a known,
  general limitation of any tool that trusts upstream `Authentication-
  Results` rather than re-verifying independently.

## Received Headers / IP Attribution

- Received headers can be forged by any relay earlier in the chain. This
  tool extracts and classifies (private/public/reserved) every candidate
  IP found, but never assumes the first or last IP in the chain is the
  attacker's true origin. Attribution requires broader correlation the
  tool does not attempt.

## Domain Analysis

- All domain heuristics (`domain_analyzer.py`) are **local and offline**.
  This tool does **not** determine domain registration age, WHOIS data,
  or hosting reputation — that would require an external data source this
  project does not integrate (VirusTotal covers reputation, not
  registration metadata).
- The brand-impersonation and typosquat checks use a small, hardcoded
  list of watched brand tokens. This is not a comprehensive trademark or
  brand-protection database and will miss impersonation of any brand not
  on that list.

## URL Analysis

- URL extraction and the visible/href mismatch check are regex/string-
  based. Deliberately obfuscated HTML (e.g. broken up across many nested
  tags, JavaScript-rendered links) may not be fully caught, since this
  tool never executes or renders HTML/JavaScript — by design, for safety.

## Attachments

- **Static analysis only.** File extension and cryptographic hash are
  computed; the tool never opens, executes, or sandboxes an attachment.
  A risky extension is an indicator, not proof — and a non-risky
  extension does not mean an attachment is safe (this tool cannot detect,
  for example, malicious macros inside a `.docx` that hasn't been renamed
  `.docm`, or exploits embedded in a well-formed PDF).

## Threat Intelligence

- VirusTotal enrichment is entirely optional and only as good as VT's own
  data — brand-new malicious infrastructure won't yet have a reputation
  history there. The tool never treats "not found on VT" as evidence of
  safety.

## Risk Scoring

- The risk score is a **deterministic, weighted sum**, not a statistical
  or machine-learned probability. It should be read as "how much rule-
  based evidence exists," not "the likelihood this email is malicious."

## General

- This tool does not claim real-time detection, production-grade
  deployment readiness, 100% accuracy, or zero false positives — none of
  that is true of any phishing detection approach, rule-based or
  otherwise.
- This tool does not replace Microsoft Defender for Office 365,
  Proofpoint, Mimecast, Google Workspace security, any Secure Email
  Gateway, VirusTotal itself, or a SIEM platform. It is a first-level
  triage aid intended to reduce repetitive analyst work, not a
  replacement for any of the above.
- This tool cannot determine whether a user interacted with a malicious
  email (clicked a link, entered credentials, opened an attachment) — see
  `docs/investigation.md` for the scope questions that require SIEM/EDR
  data this tool does not have access to.
