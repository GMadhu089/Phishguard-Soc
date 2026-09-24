"""
rules.py

Modular detection rules. Each rule inspects a RuleContext (bundled analysis
output from parsing/analysis/intelligence modules) and, if its condition is
met, fires with: evidence, a score contribution, a severity contribution,
an optional MITRE ATT&CK mapping, and a false-positive explanation for the
analyst.

RULE-010 ("multiple correlated phishing indicators") is NOT implemented
here — it depends on the output of every other rule and is evaluated by
src/detection/correlation.py (built Day 3), which consumes this module's
output rather than duplicating logic.

No single rule here ever claims certainty. Score/severity contributions are
deliberately modest per-rule; conviction should come from correlation
across multiple rules, not any one signal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from src.analysis.attachment_analyzer import AttachmentAnalysis
from src.analysis.auth_analyzer import AuthAnalysis
from src.analysis.domain_analyzer import DomainHeuristicResult
from src.analysis.header_analyzer import HeaderAnomalies
from src.analysis.url_analyzer import ExtractedURL
from src.intelligence.virustotal import VTLookupResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class RuleContext:
    header_anomalies: HeaderAnomalies
    auth: AuthAnalysis
    urls: list[ExtractedURL] = field(default_factory=list)
    domain_results: list[DomainHeuristicResult] = field(default_factory=list)
    attachments: list[AttachmentAnalysis] = field(default_factory=list)
    vt_results: list[VTLookupResult] = field(default_factory=list)
    subject: str = ""
    body: str = ""


@dataclass
class FiredRule:
    rule_id: str
    name: str
    description: str
    evidence: list[str]
    score_contribution: int
    severity_contribution: str  # "low" | "medium" | "high" | "critical"
    mitre_technique: Optional[str]  # e.g. "T1566.002", or None if not justified
    false_positive_note: str


def evaluate_rules(context: RuleContext) -> list[FiredRule]:
    fired: list[FiredRule] = []

    for rule_fn in (
        _rule_001_reply_to_mismatch,
        _rule_002_spf_failure,
        _rule_003_dkim_failure,
        _rule_004_dmarc_failure,
        _rule_005_suspicious_url,
        _rule_006_visible_href_mismatch,
        _rule_007_suspicious_attachment,
        _rule_008_known_malicious_ioc,
        _rule_009_lookalike_domain,
        _rule_011_suspicious_display_name,
        _rule_012_credential_link_language,
        _rule_013_http_url,
        # _rule_014_ip_url,
        
    ):
        result = rule_fn(context)
        if result is not None:
            fired.append(result)

    logger.info("Detection rules fired: %d", len(fired))
    return fired


def _rule_001_reply_to_mismatch(ctx: RuleContext) -> Optional[FiredRule]:
    if not ctx.header_anomalies.from_reply_to_mismatch:
        return None
    return FiredRule(
        rule_id="RULE-001",
        name="Reply-To mismatch",
        description="The Reply-To domain differs from the From domain.",
        evidence=[
            f"From domain: {ctx.header_anomalies.from_domain}",
            f"Reply-To domain: {ctx.header_anomalies.reply_to_domain}",
        ],
        score_contribution=10,
        severity_contribution="low",
        mitre_technique=None,
        false_positive_note=(
            "Common for legitimate mailing lists, ticketing systems, and third-party "
            "senders acting on a company's behalf. Validate by checking whether the "
            "Reply-To domain is a known, sanctioned business relationship before escalating."
        ),
    )


def _rule_002_spf_failure(ctx: RuleContext) -> Optional[FiredRule]:
    if ctx.auth.spf.result != "fail":
        return None
    return FiredRule(
        rule_id="RULE-002",
        name="SPF failure",
        description="The receiving mail system recorded an SPF fail result.",
        evidence=[f"SPF result: {ctx.auth.spf.result}", f"Raw: {ctx.auth.spf.raw}"],
        score_contribution=15,
        severity_contribution="low",
        mitre_technique=None,
        false_positive_note=(
            "SPF fail can result from legitimate sender misconfiguration (e.g. a "
            "third-party mail service not listed in the domain's SPF record), not just "
            "spoofing. Correlate with DKIM/DMARC and other indicators before concluding "
            "malicious intent."
        ),
    )


def _rule_003_dkim_failure(ctx: RuleContext) -> Optional[FiredRule]:
    if ctx.auth.dkim.result != "fail":
        return None
    return FiredRule(
        rule_id="RULE-003",
        name="DKIM failure",
        description="The receiving mail system recorded a DKIM fail result.",
        evidence=[f"DKIM result: {ctx.auth.dkim.result}", f"d=: {ctx.auth.dkim.domain}"],
        score_contribution=15,
        severity_contribution="low",
        mitre_technique=None,
        false_positive_note=(
            "DKIM fail can occur when an email is legitimately modified in transit "
            "(e.g. a mailing list footer appended by an internal relay), breaking the "
            "signature without malicious intent."
        ),
    )


def _rule_004_dmarc_failure(ctx: RuleContext) -> Optional[FiredRule]:
    if ctx.auth.dmarc.result != "fail":
        return None
    return FiredRule(
        rule_id="RULE-004",
        name="DMARC failure",
        description="The receiving mail system recorded a DMARC fail result.",
        evidence=[
            f"DMARC result: {ctx.auth.dmarc.result}",
            f"Policy (p=): {ctx.auth.dmarc.policy}",
            ctx.auth.dmarc_alignment_note,
        ],
        score_contribution=15,
        severity_contribution="medium",
        mitre_technique=None,
        false_positive_note=(
            "DMARC misconfiguration at a legitimate sending domain is a common cause. "
            "A DMARC fail combined with a strict policy (p=reject) and From/DMARC "
            "misalignment is a stronger signal than DMARC fail alone."
        ),
    )


def _rule_005_suspicious_url(ctx: RuleContext) -> Optional[FiredRule]:
    flagged = [u for u in ctx.urls if u.suspicious_flags and not u.visible_href_mismatch]
    if not flagged:
        return None
    evidence = [f"{u.url} -> flags: {', '.join(u.suspicious_flags)}" for u in flagged[:5]]
    return FiredRule(
        rule_id="RULE-005",
        name="Suspicious URL characteristics",
        description="One or more URLs exhibit suspicious structural characteristics.",
        evidence=evidence,
        score_contribution=20,
        severity_contribution="medium",
        mitre_technique="T1566.002",
        false_positive_note=(
            "Legitimate URL shorteners, IP-based internal tools, and multi-subdomain "
            "SaaS platforms can trigger these heuristics. Review the specific flag(s) — "
            "an IP-based URL in a phishing email is far more concerning than a known "
            "shortener used by a legitimate marketing platform."
        ),
    )


def _rule_006_visible_href_mismatch(ctx: RuleContext) -> Optional[FiredRule]:
    mismatched = [u for u in ctx.urls if u.visible_href_mismatch]
    if not mismatched:
        return None
    evidence = [
        f"Visible: {u.visible_text!r} -> Actual href: {u.url}" for u in mismatched[:5]
    ]
    return FiredRule(
        rule_id="RULE-006",
        name="Visible URL / actual href mismatch",
        description="The link text shown to the user does not match the actual destination URL.",
        evidence=evidence,
        score_contribution=25,
        severity_contribution="high",
        mitre_technique="T1566.002",
        false_positive_note=(
            "Rare in legitimate mail (most legitimate senders don't disguise a link's "
            "true destination behind unrelated visible text). Marketing/tracking "
            "redirectors are a possible legitimate cause — verify the actual destination "
            "domain is not a known internal redirector before treating as high confidence."
        ),
    )


def _rule_007_suspicious_attachment(ctx: RuleContext) -> Optional[FiredRule]:
    risky = [a for a in ctx.attachments if a.is_risky_extension]
    if not risky:
        return None
    evidence = [f"{a.filename} ({a.extension}, sha256={a.sha256})" for a in risky]
    return FiredRule(
        rule_id="RULE-007",
        name="Suspicious attachment type",
        description="One or more attachments have file extensions commonly abused for malware delivery.",
        evidence=evidence,
        score_contribution=20,
        severity_contribution="medium",
        mitre_technique="T1566.001",
        false_positive_note=(
            "Macro-enabled Office files (.docm/.xlsm) and scripts (.ps1/.vbs/.js) have "
            "many legitimate business uses (invoicing templates, internal automation). "
            "File extension alone should never be the sole basis for a verdict."
        ),
    )


def _rule_008_known_malicious_ioc(ctx: RuleContext) -> Optional[FiredRule]:
    malicious = [v for v in ctx.vt_results if v.available and (v.malicious_votes or 0) > 0]
    if not malicious:
        return None
    evidence = [
        f"{v.ioc_type}:{v.ioc_value} — {v.malicious_votes} malicious vote(s) on VirusTotal"
        for v in malicious
    ]
    return FiredRule(
        rule_id="RULE-008",
        name="Known malicious IOC (threat intelligence)",
        description="An extracted IOC has malicious detections on VirusTotal.",
        evidence=evidence,
        score_contribution=35,
        severity_contribution="critical",
        mitre_technique=None,  # let URL/attachment rules carry the technique; this is corroboration
        false_positive_note=(
            "VirusTotal vendor detections can include false positives, especially for "
            "newly-registered or repurposed infrastructure. A small number of malicious "
            "votes among many vendors warrants review, not automatic escalation, though "
            "this is generally strong corroborating evidence."
        ),
    )


def _rule_009_lookalike_domain(ctx: RuleContext) -> Optional[FiredRule]:
    flagged = [d for d in ctx.domain_results if d.brand_token_found]
    if not flagged:
        return None
    evidence = [f"{d.domain} — flags: {', '.join(d.heuristic_flags)}" for d in flagged]
    return FiredRule(
        rule_id="RULE-009",
        name="Lookalike / brand-impersonation domain",
        description="A domain contains a recognizable brand token but is not that brand's official domain.",
        evidence=evidence,
        score_contribution=20,
        severity_contribution="medium",
        mitre_technique="T1566.002",
        false_positive_note=(
            "Legitimate third-party services sometimes include a partner brand name in "
            "a subdomain or marketing domain with permission. This is a local heuristic, "
            "not a trademark or brand-protection database result — verify manually."
        ),
    )

def _rule_011_suspicious_display_name(ctx: RuleContext) -> Optional[FiredRule]:
    if not ctx.header_anomalies.suspicious_display_name:
        return None

    brand = ctx.header_anomalies.display_name_claimed_brand or "unknown"
    domain = ctx.header_anomalies.display_name_actual_domain or "unknown"

    return FiredRule(
        rule_id="RULE-011",
        name="Suspicious brand display name",
        description="The sender display name claims a known brand, but the actual sending domain does not match that brand.",
        evidence=[
            f"Claimed brand: {brand}",
            f"Actual sender domain: {domain}",
        ],
        score_contribution=15,
        severity_contribution="medium",
        mitre_technique=None,
        false_positive_note=(
            "Legitimate third-party services may send messages on behalf of a brand. "
            "Verify SPF/DKIM/DMARC alignment and the sender relationship before escalating."
        ),
    )

def _rule_012_credential_link_language(ctx: RuleContext) -> Optional[FiredRule]:
    text = f"{ctx.subject} {ctx.body}".lower()

    credential_terms = (
        "verify your account",
        "verify your identity",
        "account will be suspended",
        "password",
        "login",
        "sign in",
        "credential",
        "confirm your account",
    )

    matched_terms = [term for term in credential_terms if term in text]

    if not ctx.urls or not matched_terms:
        return None

    return FiredRule(
        rule_id="RULE-012",
        name="Account-verification language with URL",
        description="The email contains account-verification or suspension language together with a URL.",
        evidence=[
            f"Matched language: {', '.join(matched_terms[:5])}",
            f"URL count: {len(ctx.urls)}",
        ],
        score_contribution=20,
        severity_contribution="medium",
        mitre_technique="T1566.002",
        false_positive_note=(
            "Legitimate account notifications may contain similar language and URLs. "
            "Verify the sender, destination domain, and authentication results."
        ),
    )


def _rule_013_http_url(ctx: RuleContext) -> Optional[FiredRule]:
    text = f"{ctx.subject} {ctx.body}".lower()

    suspicious_language = (
        "verify your account",
        "verify your identity",
        "account will be suspended",
        "confirm your account",
        "sign in",
        "login",
    )

    has_suspicious_language = any(
        term in text for term in suspicious_language
    )

    if not has_suspicious_language:
        return None
    http_urls = [
        u.url
        for u in ctx.urls
        if u.url.lower().startswith("http://")
    ]

    if not http_urls:
        return None

    return FiredRule(
        rule_id="RULE-013",
        name="URL uses unencrypted HTTP",
        description="The email contains a URL using HTTP instead of HTTPS.",
        evidence=[
            f"HTTP URL: {url}"
            for url in http_urls[:5]
        ],
        score_contribution=10,
        severity_contribution="low",
        mitre_technique=None,
        false_positive_note=(
            "Some legitimate websites still use HTTP or redirect HTTP to HTTPS. "
            "Verify the destination domain before treating this as malicious."
        ),
    )

# import re
# def _rule_014_ip_url(ctx: RuleContext) -> Optional[FiredRule]:
#     ip_urls = [
#     u.url
#     for u in ctx.urls
#     if re.search(
#         r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)",
#         u.url,
#         re.IGNORECASE,
#     )
# ]
#     if not ip_urls:
#         return None

#     return FiredRule(
#         rule_id="RULE-014",
#         name="URL uses an IP address",
#         description="The email contains a URL whose host is an IP address instead of a domain name.",
#         evidence=[
#             f"IP-based URL: {url}"
#             for url in ip_urls[:5]
#         ],
#         score_contribution=15,
#         severity_contribution="medium",
#         mitre_technique=None,
#         false_positive_note=(
#             "Internal applications and legitimate services may use IP-based URLs. "
#             "Verify whether the destination IP is expected in your environment."
#         ),
#     )