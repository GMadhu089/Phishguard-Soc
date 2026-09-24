"""
auth_analyzer.py

Parses SPF, DKIM, and DMARC results out of the email's Authentication-Results
header(s), as recorded by the RECEIVING mail system.

IMPORTANT AND DELIBERATE SCOPE LIMITATION:

This module parses SPF, DKIM, and DMARC verdicts from Authentication-Results.
Independent SPF DNS verification and DKIM cryptographic verification are
performed separately by the intelligence modules when sufficient data is
available. This module does NOT perform independent DMARC DNS/policy
verification.

None of SPF fail / DKIM fail / DMARC fail are treated as automatic proof of
malicious intent anywhere in this module. They are returned as structured
facts; the detection engine (src/detection/rules.py, built Day 2) is what
turns them into weighted, correlated evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)

_VALID_SPF_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}
_VALID_DKIM_RESULTS = {"pass", "fail", "none", "neutral", "temperror", "permerror", "policy"}
_VALID_DMARC_RESULTS = {"pass", "fail", "none", "temperror", "permerror"}


@dataclass
class SPFResult:
    result: Optional[str] = None  # one of _VALID_SPF_RESULTS, or None if not found
    raw: Optional[str] = None


@dataclass
class DKIMResult:
    result: Optional[str] = None
    domain: Optional[str] = None  # d= value
    selector: Optional[str] = None  # s= value
    raw: Optional[str] = None


@dataclass
class DMARCResult:
    result: Optional[str] = None
    policy: Optional[str] = None  # p= value, when present
    header_from_domain: Optional[str] = None
    raw: Optional[str] = None


@dataclass
class AuthAnalysis:
    spf: SPFResult
    dkim: DKIMResult
    dmarc: DMARCResult
    spf_dkim_alignment_note: str
    dmarc_alignment_note: str
    data_source_note: str = (
        "Authentication-Results SPF/DKIM/DMARC values are extracted from the "
        "Authentication-Results header written by the receiving mail system. "
        "Independent SPF DNS verification is performed when a sender domain "
        "and candidate public IP are available. DKIM cryptographic verification "
        "is performed when a DKIM signature is present. Independent DMARC "
        "DNS/policy verification is performed when a sender domain is available; "
        "this checks the published DMARC record and policy but does not "
        "independently determine message-level DMARC alignment/pass/fail."
    )


def analyze_authentication(
    authentication_results_headers: list[str],
    from_header: Optional[str] = None,
) -> AuthAnalysis:
    """
    authentication_results_headers: list of raw Authentication-Results header
        values (there can legitimately be more than one, e.g. added by
        different relays — we scan all of them and take the first match
        found for each mechanism).
    from_header: the raw From header value, used only to report the visible
        From domain alongside DMARC's header.from domain for an alignment
        note — this is informational, not a verdict.
    """
    combined = "\n".join(authentication_results_headers)

    spf = _parse_spf(combined)
    dkim = _parse_dkim(combined)
    dmarc = _parse_dmarc(combined)

    spf_dkim_note = _build_spf_dkim_note(spf, dkim)
    dmarc_note = _build_dmarc_note(dmarc, from_header)

    if not authentication_results_headers:
        logger.warning("No Authentication-Results header present; SPF/DKIM/DMARC unknown.")

    return AuthAnalysis(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        spf_dkim_alignment_note=spf_dkim_note,
        dmarc_alignment_note=dmarc_note,
    )


def _parse_spf(text: str) -> SPFResult:
    match = re.search(r"spf=(\w+)", text, re.IGNORECASE)
    if not match:
        return SPFResult(result=None, raw=None)

    result = match.group(1).lower()
    if result not in _VALID_SPF_RESULTS:
        logger.warning("Unrecognized SPF result value: %s", result)
        result = None

    return SPFResult(result=result, raw=match.group(0))


def _parse_dkim(text: str) -> DKIMResult:
    result_match = re.search(r"dkim=(\w+)", text, re.IGNORECASE)
    if not result_match:
        return DKIMResult(result=None)

    result = result_match.group(1).lower()
    if result not in _VALID_DKIM_RESULTS:
        logger.warning("Unrecognized DKIM result value: %s", result)
        result = None

    # d= and s= appear near the dkim= token, typically inside a parenthetical
    # comment e.g. dkim=pass (signature was verified) header.d=example.com
    domain_match = re.search(r"header\.d=([a-zA-Z0-9.\-]+)", text) or re.search(
        r"\bd=([a-zA-Z0-9.\-]+)", text
    )
    selector_match = re.search(r"header\.s=([a-zA-Z0-9.\-_]+)", text) or re.search(
        r"\bs=([a-zA-Z0-9.\-_]+)", text
    )

    return DKIMResult(
        result=result,
        domain=domain_match.group(1) if domain_match else None,
        selector=selector_match.group(1) if selector_match else None,
        raw=result_match.group(0),
    )


def _parse_dmarc(text: str) -> DMARCResult:
    result_match = re.search(r"dmarc=(\w+)", text, re.IGNORECASE)
    if not result_match:
        return DMARCResult(result=None)

    result = result_match.group(1).lower()
    if result not in _VALID_DMARC_RESULTS:
        logger.warning("Unrecognized DMARC result value: %s", result)
        result = None

    policy_match = re.search(r"\bp=(\w+)", text, re.IGNORECASE)
    header_from_match = re.search(r"header\.from=([a-zA-Z0-9.\-]+)", text, re.IGNORECASE)

    return DMARCResult(
        result=result,
        policy=policy_match.group(1) if policy_match else None,
        header_from_domain=header_from_match.group(1) if header_from_match else None,
        raw=result_match.group(0),
    )


def _extract_domain_from_address(address: Optional[str]) -> Optional[str]:
    if not address:
        return None
    match = re.search(r"@([a-zA-Z0-9.\-]+)", address)
    return match.group(1).lower() if match else None


def _build_spf_dkim_note(spf: SPFResult, dkim: DKIMResult) -> str:
    if spf.result is None and dkim.result is None:
        return "Neither SPF nor DKIM results were found in Authentication-Results."
    return (
        f"SPF result: {spf.result or 'unknown'}; DKIM result: {dkim.result or 'unknown'}. "
        "Neither result alone determines maliciousness — see detection rules "
        "for how these are correlated with other indicators."
    )


def _build_dmarc_note(dmarc: DMARCResult, from_header: Optional[str]) -> str:
    visible_from_domain = _extract_domain_from_address(from_header)

    if dmarc.result is None:
        return "No DMARC result found in Authentication-Results."

    alignment = "unknown"
    if dmarc.header_from_domain and visible_from_domain:
        alignment = "aligned" if dmarc.header_from_domain.lower() == visible_from_domain else "misaligned"

    return (
        f"DMARC result: {dmarc.result}. Policy (p=): {dmarc.policy or 'unknown'}. "
        f"Visible From domain vs DMARC header.from domain: {alignment}. "
        "A DMARC pass does not guarantee the email is benign, and a DMARC "
        "fail can occur for legitimate misconfigured senders — see "
        "docs/detection-rules.md for false-positive guidance."
    )
