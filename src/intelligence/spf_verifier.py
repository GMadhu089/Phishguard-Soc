"""
Independent SPF verification.

Performs DNS-based SPF lookup and evaluates common SPF mechanisms,
including recursive include: records.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

import dns.resolver


@dataclass
class SPFVerificationResult:
    domain: str
    ip_address: str
    result: str
    spf_record: Optional[str] = None
    reason: Optional[str] = None


_QUALIFIER_RESULTS = {
    "+": "pass",
    "-": "fail",
    "~": "softfail",
    "?": "neutral",
}


def _lookup_spf_records(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "TXT")
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
    ):
        return []
    except (dns.resolver.Timeout, dns.resolver.NoNameservers):
        raise

    records = []

    for answer in answers:
        record = answer.to_text().strip('"')
        if record.lower().startswith("v=spf1"):
            records.append(record)

    return records


def _evaluate_spf(
    domain: str,
    ip_address: str,
    visited: set[str],
    depth: int = 0,
) -> tuple[str, str]:
    """
    Return (result, reason).

    This handles:
    - ip4
    - ip6
    - include
    - all

    A recursion limit prevents circular include chains.
    """

    if depth > 10:
        return "permerror", "SPF include recursion limit exceeded."

    domain = domain.lower()

    if domain in visited:
        return "permerror", "Circular SPF include detected."

    visited.add(domain)

    try:
        records = _lookup_spf_records(domain)
    except (dns.resolver.Timeout, dns.resolver.NoNameservers):
        return "temperror", "Temporary DNS failure while retrieving SPF."

    if not records:
        return "none", f"No SPF record found for {domain}."

    if len(records) > 1:
        return "permerror", f"Multiple SPF records found for {domain}."

    spf_record = records[0]
    tokens = spf_record.split()[1:]

    ip_obj = ipaddress.ip_address(ip_address)

    for mechanism in tokens:
        if mechanism == "":
            continue

        qualifier = "+"

        if mechanism[0] in "+-~?":
            qualifier = mechanism[0]
            mechanism = mechanism[1:]

        # all
        if mechanism == "all":
            return (
                _QUALIFIER_RESULTS[qualifier],
                f"Matched all mechanism in {domain}: {qualifier}all.",
            )

        # ip4
        if mechanism.startswith("ip4:"):
            try:
                network = ipaddress.ip_network(
                    mechanism[4:],
                    strict=False,
                )
            except ValueError:
                continue

            if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in network:
                return (
                    _QUALIFIER_RESULTS[qualifier],
                    f"Matched ip4:{network} in {domain}.",
                )

        # ip6
        elif mechanism.startswith("ip6:"):
            try:
                network = ipaddress.ip_network(
                    mechanism[4:],
                    strict=False,
                )
            except ValueError:
                continue

            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in network:
                return (
                    _QUALIFIER_RESULTS[qualifier],
                    f"Matched ip6:{network} in {domain}.",
                )

        # include
        elif mechanism.startswith("include:"):
            include_domain = mechanism[8:].lower()

            include_result, include_reason = _evaluate_spf(
                include_domain,
                ip_address,
                visited.copy(),
                depth + 1,
            )

            # SPF include matches only when the included SPF evaluates PASS.
            if include_result == "pass":
                return (
                    _QUALIFIER_RESULTS[qualifier],
                    f"Matched include:{include_domain}. {include_reason}",
                )

            # include returning permerror/temperror propagates the error.
            if include_result in {"permerror", "temperror"}:
                return include_result, include_reason

    return (
        "neutral",
        f"No supported SPF mechanism matched the IP for {domain}.",
    )


def verify_spf(domain: str, ip_address: str) -> SPFVerificationResult:
    """Perform independent DNS-based SPF verification."""

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return SPFVerificationResult(
            domain=domain,
            ip_address=ip_address,
            result="unavailable",
            reason="Invalid IP address.",
        )

    try:
        records = _lookup_spf_records(domain)
    except (dns.resolver.Timeout, dns.resolver.NoNameservers):
        return SPFVerificationResult(
            domain=domain,
            ip_address=ip_address,
            result="temperror",
            reason="Temporary DNS failure while retrieving SPF.",
        )

    if not records:
        return SPFVerificationResult(
            domain=domain,
            ip_address=ip_address,
            result="none",
            reason="No SPF record found.",
        )

    if len(records) > 1:
        return SPFVerificationResult(
            domain=domain,
            ip_address=ip_address,
            result="permerror",
            spf_record=" | ".join(records),
            reason="Multiple SPF records found.",
        )

    spf_record = records[0]

    result, reason = _evaluate_spf(
        domain,
        ip_address,
        visited=set(),
    )

    return SPFVerificationResult(
        domain=domain,
        ip_address=ip_address,
        result=result,
        spf_record=spf_record,
        reason=reason,
    )