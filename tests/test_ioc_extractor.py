"""
Tests for src/analysis/ioc_extractor.py
"""

from src.analysis.attachment_analyzer import AttachmentAnalysis
from src.analysis.ioc_extractor import extract_iocs
from src.analysis.url_analyzer import ExtractedURL
from src.parser.header_parser import CandidateIP, ParsedHeaders


def _headers(**overrides) -> ParsedHeaders:
    h = ParsedHeaders()
    for key, value in overrides.items():
        setattr(h, key, value)
    return h


def test_email_iocs_extracted_from_headers():
    """
    WHAT: Headers with From/Reply-To/Return-Path addresses.
    WHY: Sender addresses are basic but useful IOCs for SIEM correlation.
    EXPECTED: Three distinct 'email' IOCs extracted.
    """
    headers = _headers(from_="a@example.com", reply_to="b@example.test", return_path="<c@example.net>")
    iocs = extract_iocs(headers, urls=[], attachments=[])
    emails = {i.value for i in iocs if i.type == "email"}
    assert emails == {"a@example.com", "b@example.test", "c@example.net"}


def test_duplicate_iocs_are_deduplicated():
    """
    WHAT: The same URL/domain appearing from two different ExtractedURL
         entries (e.g. found in both text and HTML body).
    WHY: A phishing email often repeats the same malicious link multiple
         times; the analyst wants a clean, deduplicated IOC list.
    EXPECTED: Only one 'url' IOC and one 'domain' IOC for the repeated value.
    """
    headers = _headers()
    urls = [
        ExtractedURL(url="https://evil.test/a", source="text", hostname="evil.test"),
        ExtractedURL(url="https://evil.test/a", source="html_visible", hostname="evil.test"),
    ]
    iocs = extract_iocs(headers, urls=urls, attachments=[])
    url_iocs = [i for i in iocs if i.type == "url" and i.value == "https://evil.test/a"]
    domain_iocs = [i for i in iocs if i.type == "domain" and i.value == "evil.test"]
    assert len(url_iocs) == 1
    assert len(domain_iocs) == 1


def test_public_ip_gets_medium_confidence_private_gets_low():
    """
    WHAT: Received-chain candidate IPs, one public, one private.
    WHY: A public IP is a more directly useful external IOC than a
         private/internal address.
    EXPECTED: Public IP has 'medium' confidence, private IP has 'low'.
    """
    headers = _headers(candidate_ips=[
        CandidateIP(ip="8.8.8.8", scope="public", source_header_index=0),
        CandidateIP(ip="10.0.0.1", scope="private", source_header_index=1),
    ])
    iocs = extract_iocs(headers, urls=[], attachments=[])
    conf = {i.value: i.confidence for i in iocs if i.type == "ipv4"}
    assert conf["8.8.8.8"] == "medium"
    assert conf["10.0.0.1"] == "low"


def test_attachment_hashes_and_filename_become_iocs():
    """
    WHAT: An attachment analysis result with all three hashes and a filename.
    WHY: Hashes are the primary IOC type used for VirusTotal/EDR lookups.
    EXPECTED: sha256, sha1, md5, and filename all appear as distinct IOCs.
    """
    att = AttachmentAnalysis(
        filename="bad.exe", content_type="application/octet-stream", size_bytes=10,
        extension=".exe", sha256="a" * 64, sha1="b" * 40, md5="c" * 32,
        is_risky_extension=True,
    )
    headers = _headers()
    iocs = extract_iocs(headers, urls=[], attachments=[att])
    types_values = {(i.type, i.value) for i in iocs}
    assert ("sha256", "a" * 64) in types_values
    assert ("sha1", "b" * 40) in types_values
    assert ("md5", "c" * 32) in types_values
    assert ("filename", "bad.exe") in types_values


def test_risky_attachment_iocs_get_high_confidence():
    """
    WHAT: An attachment IOC where is_risky_extension is True.
    WHY: Risky-extension attachments are higher-value IOCs to prioritize.
    EXPECTED: Confidence is 'high' for that attachment's IOCs.
    """
    att = AttachmentAnalysis(
        filename="bad.exe", content_type="application/octet-stream", size_bytes=10,
        extension=".exe", sha256="d" * 64, sha1=None, md5=None,
        is_risky_extension=True,
    )
    headers = _headers()
    iocs = extract_iocs(headers, urls=[], attachments=[att])
    sha_ioc = next(i for i in iocs if i.type == "sha256")
    assert sha_ioc.confidence == "high"


def test_empty_input_returns_empty_list():
    """
    WHAT: No headers content, no URLs, no attachments.
    WHY: A minimal/incomplete email must not crash IOC extraction.
    EXPECTED: An empty list is returned.
    """
    headers = _headers()
    assert extract_iocs(headers, urls=[], attachments=[]) == []
