"""
Tests for src/analysis/attachment_analyzer.py
"""

import hashlib

from src.analysis.attachment_analyzer import analyze_attachment
from src.parser.email_parser import AttachmentPart


def test_hashes_computed_correctly():
    """
    WHAT: An attachment with known payload bytes.
    WHY: Hashes feed IOC extraction and VirusTotal lookups directly —
         correctness here is critical, not cosmetic.
    EXPECTED: sha256/sha1/md5 exactly match hashlib's own computation.
    """
    payload = b"Hello world"
    att = AttachmentPart(filename="note.txt", content_type="text/plain",
                          size_bytes=len(payload), payload=payload)
    result = analyze_attachment(att)
    assert result.sha256 == hashlib.sha256(payload).hexdigest()
    assert result.sha1 == hashlib.sha1(payload).hexdigest()
    assert result.md5 == hashlib.md5(payload).hexdigest()


def test_risky_extension_flagged():
    """
    WHAT: An attachment with a .docm (macro-enabled) extension.
    WHY: RULE-007's core signal.
    EXPECTED: is_risky_extension is True with a false-positive note attached.
    """
    att = AttachmentPart(filename="invoice.docm", content_type="application/vnd.ms-word.document.macroEnabled.12",
                          size_bytes=100, payload=b"x" * 100)
    result = analyze_attachment(att)
    assert result.is_risky_extension is True
    assert result.notes  # false-positive explanation must be present


def test_benign_extension_not_flagged():
    """
    WHAT: A plain .pdf attachment.
    WHY: Must not false-positive on ordinary document types.
    EXPECTED: is_risky_extension is False.
    """
    att = AttachmentPart(filename="report.pdf", content_type="application/pdf",
                          size_bytes=100, payload=b"x" * 100)
    result = analyze_attachment(att)
    assert result.is_risky_extension is False


def test_no_payload_does_not_crash():
    """
    WHAT: An attachment whose payload failed to decode (empty bytes).
    WHY: Real-world malformed MIME parts can yield empty payloads; hashing
         must not raise, and the analyst must be told hashes are unavailable.
    EXPECTED: All hash fields are None; a note explains why.
    """
    att = AttachmentPart(filename="broken.bin", content_type="application/octet-stream",
                          size_bytes=0, payload=b"")
    result = analyze_attachment(att)
    assert result.sha256 is None
    assert any("unavailable" in n.lower() for n in result.notes)


def test_no_filename_extension_is_none():
    """
    WHAT: An attachment with no filename at all.
    WHY: Some malformed/unusual emails omit the filename; extension
         extraction must not crash.
    EXPECTED: extension is None; is_risky_extension is False.
    """
    att = AttachmentPart(filename=None, content_type="application/octet-stream",
                          size_bytes=10, payload=b"x" * 10)
    result = analyze_attachment(att)
    assert result.extension is None
    assert result.is_risky_extension is False
