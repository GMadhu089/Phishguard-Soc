"""
header_analyzer.py

Turns raw header fields (from header_parser.py) into named indicators:
- From / Reply-To address mismatch
- suspicious display name (display name claims a brand/domain that doesn't
  match the actual sending address)
- external sender (From domain differs from the recipient's own domain)

DESIGN PRINCIPLE (per project spec): these are INDICATORS, not verdicts.
A mismatch is common for legitimate mailing lists, ticketing systems,
and marketing platforms. This module never labels an email "malicious" —
it only produces structured facts that src/detection/rules.py weighs
alongside other evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)

_ADDRESS_PATTERN = re.compile(r"[\w.\-+]+@([\w.\-]+)")

# A small, deliberately limited set of well-known brand names used only to
# flag a display name that CLAIMS a brand but sends from an unrelated
# domain. This is a heuristic aid for an L1 analyst, not a trademark
# database and not proof of impersonation.
_WATCHED_BRAND_TERMS = [
    "microsoft", "office365", "outlook", "google", "gmail", "apple",
    "paypal", "amazon", "bank", "netflix", "docusign", "adobe",
]


@dataclass
class HeaderAnomalies:
    from_reply_to_mismatch: bool = False
    from_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    suspicious_display_name: bool = False
    display_name_claimed_brand: Optional[str] = None
    display_name_actual_domain: Optional[str] = None
    external_sender: Optional[bool] = None  # None = unknown (recipient domain not provided)
    notes: list[str] = field(default_factory=list)


def analyze_headers(
    from_header: Optional[str],
    reply_to_header: Optional[str],
    recipient_domain: Optional[str] = None,
) -> HeaderAnomalies:
    """
    from_header / reply_to_header: raw header strings, e.g.
        '"IT Support" <it-support@example.com>'
    recipient_domain: the recipient's own organization domain, if known
        (used only to flag "external sender" — optional, since the CLI
        tool does not always know this).
    """
    anomalies = HeaderAnomalies()

    from_domain = _extract_domain(from_header)
    reply_to_domain = _extract_domain(reply_to_header)
    anomalies.from_domain = from_domain
    anomalies.reply_to_domain = reply_to_domain

    if reply_to_domain and from_domain and reply_to_domain.lower() != from_domain.lower():
        anomalies.from_reply_to_mismatch = True
        anomalies.notes.append(
            f"From domain ({from_domain}) differs from Reply-To domain ({reply_to_domain}). "
            "This is common for legitimate mailing lists and support ticketing systems; "
            "treat as one signal among several, not a standalone verdict."
        )

    display_name = _extract_display_name(from_header)
    if display_name and from_domain:
        claimed_brand = _display_name_claims_brand(display_name)
        if claimed_brand and claimed_brand.lower() not in from_domain.lower():
            anomalies.suspicious_display_name = True
            anomalies.display_name_claimed_brand = claimed_brand
            anomalies.display_name_actual_domain = from_domain
            anomalies.notes.append(
                f"Display name references '{claimed_brand}' but the sending domain is "
                f"'{from_domain}', which does not contain that term. Legitimate third-party "
                "senders (e.g. marketing platforms sending on a brand's behalf) can also "
                "trigger this — verify via SPF/DKIM alignment before concluding impersonation."
            )

    if recipient_domain and from_domain:
        anomalies.external_sender = from_domain.lower() != recipient_domain.lower()

    return anomalies


def _extract_domain(header_value: Optional[str]) -> Optional[str]:
    if not header_value:
        return None
    match = _ADDRESS_PATTERN.search(header_value)
    return match.group(1).lower() if match else None


def _extract_display_name(from_header: Optional[str]) -> Optional[str]:
    """
    '"IT Support" <it-support@example.com>' -> 'IT Support'
    'Microsoft Account Team <account-security@example.com>' -> 'Microsoft Account Team'
    """
    if not from_header:
        return None

    # Quoted display name
    quoted = re.match(r'\s*"([^"]+)"', from_header)
    if quoted:
        return quoted.group(1).strip()

    # Unquoted display name before an angle-bracketed address
    unquoted = re.match(r"\s*([^<]+)<", from_header)
    if unquoted:
        name = unquoted.group(1).strip()
        return name if name else None

    return None


def _display_name_claims_brand(display_name: str) -> Optional[str]:
    lowered = display_name.lower()
    for brand in _WATCHED_BRAND_TERMS:
        if brand in lowered:
            return brand
    return None
