"""
Independent DMARC DNS verification.

Retrieves and parses the DMARC policy published at:
_dmarc.<domain>

This module does not determine whether an email is malicious.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import dns.resolver


@dataclass
class DMARCVerificationResult:
    domain: str
    result: str
    policy: Optional[str] = None
    record: Optional[str] = None
    reason: Optional[str] = None


def _lookup_dmarc_record(domain: str) -> Optional[str]:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except (dns.resolver.Timeout, dns.resolver.NoNameservers):
        raise

    records = []

    for answer in answers:
        record = answer.to_text().strip('"')
        if record.lower().startswith("v=dmarc1"):
            records.append(record)

    if len(records) > 1:
        raise ValueError("Multiple DMARC records found.")

    return records[0] if records else None


def verify_dmarc(domain: str) -> DMARCVerificationResult:
    domain = domain.strip().lower()

    if not domain:
        return DMARCVerificationResult(
            domain=domain,
            result="none",
            reason="No domain supplied.",
        )

    try:
        record = _lookup_dmarc_record(domain)
    except (dns.resolver.Timeout, dns.resolver.NoNameservers):
        return DMARCVerificationResult(
            domain=domain,
            result="temperror",
            reason="Temporary DNS failure while retrieving DMARC.",
        )
    except ValueError as exc:
        return DMARCVerificationResult(
            domain=domain,
            result="permerror",
            reason=str(exc),
        )

    if not record:
        return DMARCVerificationResult(
            domain=domain,
            result="none",
            reason=f"No DMARC record found for {domain}.",
        )

    policy = None

    for part in record.split(";"):
        part = part.strip()

        if part.lower().startswith("p="):
            policy = part.split("=", 1)[1].strip().lower()
            break

    if policy not in {"none", "quarantine", "reject"}:
        return DMARCVerificationResult(
            domain=domain,
            result="permerror",
            record=record,
            reason="DMARC record does not contain a valid p= policy.",
        )

    return DMARCVerificationResult(
    domain=domain,
    result="record_found",
    policy=policy,
    record=record,
    reason=(
        "Valid DMARC record found. Message-level DMARC pass/fail "
        "cannot be determined from the DNS record alone."
    ),
)