"""
ioc_extractor.py

STRUCTURAL NOTE: the original architecture names "IOC EXTRACTION" as a
pipeline stage but the repository tree didn't assign it its own file. It's
placed here in analysis/ alongside the other analyzers it consumes output
from (url_analyzer, domain_analyzer, attachment_analyzer, header_parser),
rather than inventing a new top-level package for one file.

Produces a deduplicated list of structured IOC objects, e.g.:
    {"type": "domain", "value": "example.test", "source": "url", "confidence": "medium"}

Confidence levels here are simple and deterministic (not ML-derived):
- "high": IOC came from a flagged/suspicious source (e.g. a URL with
  visible/href mismatch, or a risky-extension attachment hash)
- "medium": IOC came from a normal but non-trivial source (e.g. any
  extracted URL/domain)
- "low": IOC came from header metadata alone (e.g. sender email address)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from src.analysis.attachment_analyzer import AttachmentAnalysis
from src.analysis.url_analyzer import ExtractedURL
from src.parser.header_parser import ParsedHeaders
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class IOC:
    type: str  # "email" | "ipv4" | "domain" | "url" | "sha256" | "sha1" | "md5" | "filename"
    value: str
    source: str  # e.g. "header", "url", "attachment", "received"
    confidence: str  # "low" | "medium" | "high"


def extract_iocs(
    headers: ParsedHeaders,
    urls: list[ExtractedURL],
    attachments: list[AttachmentAnalysis],
) -> list[IOC]:
    iocs: set[IOC] = set()

    _extract_header_iocs(headers, iocs)
    _extract_url_iocs(urls, iocs)
    _extract_attachment_iocs(attachments, iocs)

    deduped = sorted(iocs, key=lambda i: (i.type, i.value))
    logger.info("Extracted %d unique IOC(s).", len(deduped))
    return deduped


def _extract_header_iocs(headers: ParsedHeaders, iocs: set) -> None:
    for addr_header in (headers.from_, headers.reply_to, headers.return_path):
        email_value = _extract_email_address(addr_header)
        if email_value:
            iocs.add(IOC(type="email", value=email_value, source="header", confidence="low"))

    for candidate in headers.candidate_ips:
        if candidate.scope == "public":
            iocs.add(IOC(type="ipv4", value=candidate.ip, source="received", confidence="medium"))
        elif candidate.scope in ("private", "reserved"):
            # Still recorded, but lower confidence — not internet-routable,
            # so less useful as a standalone external IOC.
            iocs.add(IOC(type="ipv4", value=candidate.ip, source="received", confidence="low"))


def _extract_url_iocs(urls: list[ExtractedURL], iocs: set) -> None:
    for extracted in urls:
        confidence = "high" if extracted.suspicious_flags else "medium"
        iocs.add(IOC(type="url", value=extracted.url, source="url", confidence=confidence))
        if extracted.hostname:
            iocs.add(IOC(type="domain", value=extracted.hostname.lower(), source="url", confidence=confidence))


def _extract_attachment_iocs(attachments: list[AttachmentAnalysis], iocs: set) -> None:
    for att in attachments:
        confidence = "high" if att.is_risky_extension else "medium"
        if att.sha256:
            iocs.add(IOC(type="sha256", value=att.sha256, source="attachment", confidence=confidence))
        if att.sha1:
            iocs.add(IOC(type="sha1", value=att.sha1, source="attachment", confidence=confidence))
        if att.md5:
            iocs.add(IOC(type="md5", value=att.md5, source="attachment", confidence=confidence))
        if att.filename:
            iocs.add(IOC(type="filename", value=att.filename, source="attachment", confidence=confidence))


def _extract_email_address(header_value: Optional[str]) -> Optional[str]:
    if not header_value:
        return None
    import re

    match = re.search(r"[\w.\-+]+@[\w.\-]+", header_value)
    return match.group(0).lower() if match else None
