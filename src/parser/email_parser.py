"""
email_parser.py

Responsible for turning a raw .eml file on disk into a structured,
in-memory representation: the underlying email.message.EmailMessage object,
plus separated plain-text body, HTML body, and a list of attachment
descriptors (metadata only — raw bytes are kept in memory for hashing later,
never written to disk and never executed).

SECURITY NOTE:
This module NEVER executes, opens, or renders anything inside the email.
HTML bodies are treated as text data for regex/string analysis only.
Attachments are treated as raw bytes for hashing/metadata only.

Handles:
- multipart/* emails (alternative, mixed, related)
- text/plain and text/html parts
- attachments (any content-disposition indicating attachment, or any
  non-text/non-multipart part with a filename)
- missing/malformed parts (never raises on a well-formed but incomplete email)

Does not handle (documented limitation, see docs/limitations.md):
- decrypting S/MIME or PGP encrypted content
- rendering HTML (so JS/CSS in HTML bodies is inert — we only regex it)
"""

from __future__ import annotations

import email
import email.policy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class AttachmentPart:
    filename: Optional[str]
    content_type: str
    size_bytes: int
    payload: bytes  # raw bytes, in-memory only, used for hashing (analysis/attachment_analyzer.py)


@dataclass
class ParsedEmail:
    raw_message: "email.message.EmailMessage"
    text_body: str = ""
    html_body: str = ""
    attachments: list[AttachmentPart] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)


class EmailParseError(Exception):
    """Raised only when the file cannot be read or is not parseable at all."""


def load_eml_file(file_path: str) -> ParsedEmail:
    """
    Load and parse a .eml file from disk.

    Raises EmailParseError if the file does not exist or cannot be read.
    Does NOT raise for malformed/incomplete email content — the Python
    email library is deliberately lenient, and we add our own warnings
    list rather than crashing, per the project's "never crash on a
    suspicious/malformed sample" requirement.
    """
    path = Path(file_path)

    if not path.exists():
        raise EmailParseError(f"File not found: {file_path}")

    if not path.is_file():
        raise EmailParseError(f"Not a file: {file_path}")

    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise EmailParseError(f"Could not read file: {exc}") from exc

    if len(raw_bytes) == 0:
        logger.warning("Email file is empty: %s", file_path)
        # Build an empty EmailMessage so downstream code has something safe to work with.
        msg = email.message_from_bytes(b"", policy=email.policy.default)
        parsed = ParsedEmail(raw_message=msg)
        parsed.parse_warnings.append("Email file was empty.")
        return parsed

    try:
        msg = email.message_from_bytes(raw_bytes,policy=email.policy.default)
    except Exception as exc:  # email lib is lenient but we guard anyway
        raise EmailParseError(f"Failed to parse email content: {exc}") from exc

    parsed = ParsedEmail(raw_message=msg)
    _extract_bodies_and_attachments(msg, parsed)
    return parsed


def _extract_bodies_and_attachments(msg, parsed: ParsedEmail) -> None:
    """
    Walk the MIME tree and split parts into text_body / html_body / attachments.
    Safe against: missing Content-Type, missing payload, non-multipart emails,
    deeply nested multiparts.
    """
    try:
        if msg.is_multipart():
            for part in msg.walk():
                _handle_part(part, parsed)
        else:
            _handle_part(msg, parsed)
    except Exception as exc:
        # Last-resort guard: a malformed sample should degrade gracefully,
        # not crash the whole analysis pipeline.
        logger.error("Error walking MIME tree: %s", exc)
        parsed.parse_warnings.append(f"Error while extracting body/attachments: {exc}")


def _handle_part(part, parsed: ParsedEmail) -> None:
    content_type = part.get_content_type() if hasattr(part, "get_content_type") else "unknown"

    # Skip container multiparts themselves; we only care about leaf parts.
    if content_type.startswith("multipart/"):
        return

    content_disposition = (part.get("Content-Disposition") or "").lower()
    filename = part.get_filename()

    is_attachment = (
        "attachment" in content_disposition
        or (filename is not None and content_type not in ("text/plain", "text/html"))
    )

    if is_attachment:
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception as exc:
            logger.warning("Could not decode attachment payload: %s", exc)
            payload = b""
        parsed.attachments.append(
            AttachmentPart(
                filename=filename,
                content_type=content_type,
                size_bytes=len(payload),
                payload=payload,
            )
        )
        return

    if content_type == "text/plain":
        parsed.text_body += _safe_get_text(part)
    elif content_type == "text/html":
        parsed.html_body += _safe_get_text(part)
    # Other content types (e.g. text/calendar) are ignored for MVP —
    # documented as a limitation, not silently misclassified as attachments.


def _safe_get_text(part) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else str(content)
    except Exception as exc:
        logger.warning("Could not decode text part: %s", exc)
        return ""
