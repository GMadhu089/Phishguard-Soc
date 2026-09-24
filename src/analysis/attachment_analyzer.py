"""
attachment_analyzer.py

STATIC analysis only. Never executes, opens, or renders attachment content.
Computes cryptographic hashes (used for IOC extraction and, later,
VirusTotal hash lookups) and flags file extensions that are commonly abused
for malware delivery.

IMPORTANT: a risky extension is an INDICATOR, not proof of malice.
.docm/.xlsm (macro-enabled Office documents), .js, .vbs, .ps1, .hta, .bat,
.cmd, .scr, and .exe are flagged, but each has legitimate uses (internal
automation scripts, macro-based business templates, etc.) — see
docs/detection-rules.md for the false-positive guidance L1 analysts need.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.parser.email_parser import AttachmentPart
from src.utils.logger import get_logger

logger = get_logger(__name__)

_RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta",
    ".docm", ".xlsm", ".jar", ".msi", ".lnk",
}


@dataclass
class AttachmentAnalysis:
    filename: Optional[str]
    content_type: str
    size_bytes: int
    extension: Optional[str]
    sha256: Optional[str]
    sha1: Optional[str]
    md5: Optional[str]
    is_risky_extension: bool = False
    notes: list[str] = field(default_factory=list)


def analyze_attachment(attachment: AttachmentPart) -> AttachmentAnalysis:
    extension = _get_extension(attachment.filename)

    sha256 = sha1 = md5 = None
    if attachment.payload:
        sha256 = hashlib.sha256(attachment.payload).hexdigest()
        sha1 = hashlib.sha1(attachment.payload).hexdigest()
        md5 = hashlib.md5(attachment.payload).hexdigest()
    else:
        logger.warning(
            "Attachment '%s' has no payload bytes to hash (possibly failed decode).",
            attachment.filename,
        )

    analysis = AttachmentAnalysis(
        filename=attachment.filename,
        content_type=attachment.content_type,
        size_bytes=attachment.size_bytes,
        extension=extension,
        sha256=sha256,
        sha1=sha1,
        md5=md5,
    )

    if extension and extension.lower() in _RISKY_EXTENSIONS:
        analysis.is_risky_extension = True
        analysis.notes.append(
            f"Extension '{extension}' is commonly abused for malware delivery, but is also "
            "used legitimately (e.g. internal automation scripts, macro-enabled business "
            "templates). File type alone is not proof of malicious intent — see "
            "docs/detection-rules.md."
        )

    if not attachment.payload:
        analysis.notes.append("Payload could not be decoded; hashes unavailable.")

    return analysis


def analyze_attachments(attachments: list[AttachmentPart]) -> list[AttachmentAnalysis]:
    return [analyze_attachment(att) for att in attachments]


def _get_extension(filename: Optional[str]) -> Optional[str]:
    if not filename:
        return None
    suffix = Path(filename).suffix
    return suffix if suffix else None
