"""
Tests for src/parser/email_parser.py

Each test states WHAT is tested, WHY it matters for a phishing-triage tool,
and the EXPECTED result.
"""

import pytest

from src.parser.email_parser import EmailParseError, load_eml_file


def test_normal_email_parses_without_error(tmp_path):
    """
    WHAT: A well-formed plain-text email.
    WHY: This is the baseline case — the parser must never fail on valid input.
    EXPECTED: No exception; text_body contains the message content.
    """
    eml = tmp_path / "normal.eml"
    eml.write_text(
        "From: a@example.com\r\nTo: b@example.com\r\nSubject: Hi\r\n"
        "Content-Type: text/plain\r\n\r\nHello there.\r\n"
    )
    parsed = load_eml_file(str(eml))
    assert "Hello there." in parsed.text_body
    assert parsed.attachments == []


def test_missing_file_raises_parse_error():
    """
    WHAT: A path that does not exist on disk.
    WHY: The CLI must give the analyst a clear error, not a stack trace.
    EXPECTED: EmailParseError is raised.
    """
    with pytest.raises(EmailParseError):
        load_eml_file("/nonexistent/path/does_not_exist.eml")


def test_empty_email_does_not_crash(tmp_path):
    """
    WHAT: A zero-byte .eml file (e.g. corrupted download, truncated sample).
    WHY: Analysts sometimes upload broken exports; the tool must degrade
         gracefully rather than crash the whole pipeline.
    EXPECTED: Returns a ParsedEmail with a warning, not an exception.
    """
    eml = tmp_path / "empty.eml"
    eml.write_bytes(b"")
    parsed = load_eml_file(str(eml))
    assert parsed.text_body == ""
    assert any("empty" in w.lower() for w in parsed.parse_warnings)


def test_malformed_email_does_not_crash(tmp_path):
    """
    WHAT: A file that is not valid RFC 5322 email content at all.
    WHY: Suspicious samples are sometimes intentionally malformed.
    EXPECTED: The Python email library's lenient parser still returns
              something usable, or we degrade gracefully — no exception
              escapes load_eml_file for this kind of malformed input.
    """
    eml = tmp_path / "malformed.eml"
    eml.write_bytes(b"This is not really an email header block at all\n\nJust some text.")
    parsed = load_eml_file(str(eml))
    # The email library treats unparseable header blocks as body content;
    # what matters is that we get a ParsedEmail back, not an exception.
    assert parsed is not None


def test_multipart_email_extracts_text_and_html(tmp_path):
    """
    WHAT: A multipart/alternative email with both text/plain and text/html parts.
    WHY: Most real phishing emails are multipart/alternative or multipart/mixed;
         the parser must correctly separate both bodies.
    EXPECTED: Both text_body and html_body are populated.
    """
    raw = (
        "From: a@example.com\r\n"
        "To: b@example.com\r\n"
        "Subject: Test\r\n"
        'Content-Type: multipart/alternative; boundary="BOUNDARY"\r\n\r\n'
        "--BOUNDARY\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Plain version\r\n"
        "--BOUNDARY\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<p>HTML version</p>\r\n"
        "--BOUNDARY--\r\n"
    )
    eml = tmp_path / "multipart.eml"
    eml.write_bytes(raw.encode())
    parsed = load_eml_file(str(eml))
    assert "Plain version" in parsed.text_body
    assert "HTML version" in parsed.html_body


def test_attachment_is_extracted_with_metadata(tmp_path):
    """
    WHAT: A multipart/mixed email with one attachment part.
    WHY: Attachment metadata (filename, content-type, size, and later hash)
         feeds directly into IOC extraction and detection rules.
    EXPECTED: attachments list has exactly one entry with correct filename
              and non-empty payload.
    """
    raw = (
        "From: a@example.com\r\n"
        "To: b@example.com\r\n"
        "Subject: Test attachment\r\n"
        'Content-Type: multipart/mixed; boundary="BOUNDARY"\r\n\r\n'
        "--BOUNDARY\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "See attached.\r\n"
        "--BOUNDARY\r\n"
        "Content-Type: application/octet-stream\r\n"
        'Content-Disposition: attachment; filename="invoice.exe"\r\n'
        "Content-Transfer-Encoding: base64\r\n\r\n"
        "SGVsbG8gd29ybGQ=\r\n"  # base64 for "Hello world"
        "--BOUNDARY--\r\n"
    )
    eml = tmp_path / "with_attachment.eml"
    eml.write_bytes(raw.encode())
    parsed = load_eml_file(str(eml))
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "invoice.exe"
    assert parsed.attachments[0].size_bytes > 0
