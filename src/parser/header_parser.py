"""
header_parser.py

Extracts headers from a parsed email in a structured, safe way.
Every field defaults to None/[] if absent — this module must NEVER raise
just because a header is missing, since that's the normal case for a lot
of real-world phishing samples (spoofed/incomplete headers are common).

Also extracts the Received header chain and pulls candidate IP addresses
out of it, classifying each as private / public / reserved.

IMPORTANT LIMITATION (documented per project spec, see docs/limitations.md):
Received headers represent hops added by each relaying mail server, and are
listed newest-first. Any hop can be forged by an attacker-controlled server
earlier in the chain. This module does NOT assume "first IP = attacker" or
"last IP = origin" — it only extracts and classifies candidate IPs and
leaves interpretation to the analyst/detection rules.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Matches IPv4 addresses embedded anywhere in free-text Received header content.
_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)


@dataclass
class CandidateIP:
    ip: str
    scope: str  # "private" | "public" | "reserved" | "invalid"
    source_header_index: int  # which Received header (0 = topmost/newest) it came from


@dataclass
class ParsedHeaders:
    from_: Optional[str] = None
    to: Optional[str] = None
    cc: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    received: list[str] = field(default_factory=list)
    authentication_results: list[str] = field(default_factory=list)
    dkim_signatures: list[str] = field(default_factory=list)
    mime_version: Optional[str] = None
    content_type: Optional[str] = None
    content_disposition: Optional[str] = None
    x_mailer: Optional[str] = None
    x_originating_ip: Optional[str] = None
    candidate_ips: list[CandidateIP] = field(default_factory=list)
    missing_headers: list[str] = field(default_factory=list)


def parse_headers(raw_message) -> ParsedHeaders:
    """
    Extract all target headers from an email.message.EmailMessage.
    raw_message is expected to come from email_parser.load_eml_file(...).raw_message.
    """
    headers = ParsedHeaders()

    single_value_map = {
        "from_": "From",
        "to": "To",
        "cc": "Cc",
        "reply_to": "Reply-To",
        "return_path": "Return-Path",
        "subject": "Subject",
        "date": "Date",
        "message_id": "Message-ID",
        "mime_version": "MIME-Version",
        "content_type": "Content-Type",
        "content_disposition": "Content-Disposition",
        "x_mailer": "X-Mailer",
        "x_originating_ip": "X-Originating-IP",
    }

    for attr, header_name in single_value_map.items():
        value = _safe_get_header(raw_message, header_name)
        setattr(headers, attr, value)
        if value is None:
            headers.missing_headers.append(header_name)

    # Multi-value headers: a message can legitimately have several Received
    # headers (one per hop) and, less commonly, multiple Authentication-Results.
    headers.received = _safe_get_all(raw_message, "Received")
    headers.authentication_results = _safe_get_all(raw_message, "Authentication-Results")
    headers.dkim_signatures = _safe_get_all(raw_message, "DKIM-Signature")

    if not headers.received:
        headers.missing_headers.append("Received")
    if not headers.authentication_results:
        headers.missing_headers.append("Authentication-Results")
    if not headers.dkim_signatures:
        headers.missing_headers.append("DKIM-Signature")

    headers.candidate_ips = _extract_candidate_ips(headers.received)

    return headers


def _safe_get_header(raw_message, header_name: str) -> Optional[str]:
    try:
        value = raw_message.get(header_name)
        if value is None:
            return None
        return str(value).strip()
    except Exception as exc:
        logger.warning("Failed to read header %s: %s", header_name, exc)
        return None


def _safe_get_all(raw_message, header_name: str) -> list[str]:
    try:
        values = raw_message.get_all(header_name) or []
        return [str(v).strip() for v in values]
    except Exception as exc:
        logger.warning("Failed to read repeated header %s: %s", header_name, exc)
        return []


def _extract_candidate_ips(received_headers: list[str]) -> list[CandidateIP]:
    """
    Pull every IPv4-looking token out of each Received header and classify it.
    Order preserved: index 0 = topmost Received header (most recently added
    hop, i.e. closest to the recipient — NOT necessarily the attacker).
    """
    candidates: list[CandidateIP] = []

    for index, header_value in enumerate(received_headers):
        matches = _IPV4_PATTERN.findall(header_value)
        for ip_str in matches:
            scope = _classify_ip(ip_str)
            candidates.append(
                CandidateIP(ip=ip_str, scope=scope, source_header_index=index)
            )

    return candidates


def _classify_ip(ip_str: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "invalid"

    if ip_obj.is_private:
        return "private"
    if ip_obj.is_reserved or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
        return "reserved"
    return "public"
