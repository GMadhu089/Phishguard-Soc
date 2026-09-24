"""
Tests for src/parser/header_parser.py
"""

import email
import email.policy

from src.parser.header_parser import parse_headers


def _make_message(raw_text: str):
    return email.message_from_string(raw_text, policy=email.policy.default)


def test_all_present_headers_are_extracted():
    """
    WHAT: An email with every target header present.
    WHY: Baseline correctness check for header extraction.
    EXPECTED: Every field is populated with the correct value.
    """
    raw = (
        "From: a@example.com\r\n"
        "To: b@example.com\r\n"
        "Reply-To: c@example.com\r\n"
        "Return-Path: <d@example.com>\r\n"
        "Subject: Hello\r\n"
        "Message-ID: <123@example.com>\r\n"
        "Received: from x by y; Mon, 01 Jan 2026 00:00:00 +0000\r\n"
        "Authentication-Results: mx.example.com; spf=pass\r\n\r\n"
        "Body\r\n"
    )
    msg = _make_message(raw)
    headers = parse_headers(msg)
    assert headers.from_ == "a@example.com"
    assert headers.reply_to == "c@example.com"
    assert headers.subject == "Hello"
    assert len(headers.received) == 1
    assert len(headers.authentication_results) == 1


def test_missing_headers_are_reported_not_raised():
    """
    WHAT: An email missing Reply-To, Return-Path, and Authentication-Results.
    WHY: Real phishing samples very often lack these — the parser must
         record the absence instead of crashing or inventing a value.
    EXPECTED: Missing fields are None; missing_headers lists their names.
    """
    raw = "From: a@example.com\r\nTo: b@example.com\r\nSubject: Hi\r\n\r\nBody\r\n"
    msg = _make_message(raw)
    headers = parse_headers(msg)
    assert headers.reply_to is None
    assert headers.return_path is None
    assert "Reply-To" in headers.missing_headers
    assert "Authentication-Results" in headers.missing_headers


def test_multiple_received_headers_all_captured():
    """
    WHAT: An email with three Received headers (three hops).
    WHY: Received chains commonly have multiple hops; losing any of them
         would break IP-candidate extraction and hop-order reasoning.
    EXPECTED: All three are present, in original (newest-first) order.
    """
    raw = (
        "From: a@example.com\r\n"
        "Received: from hop3 (1.1.1.1); t3\r\n"
        "Received: from hop2 (2.2.2.2); t2\r\n"
        "Received: from hop1 (3.3.3.3); t1\r\n\r\n"
        "Body\r\n"
    )
    msg = _make_message(raw)
    headers = parse_headers(msg)
    assert len(headers.received) == 3
    assert "hop3" in headers.received[0]
    assert "hop1" in headers.received[2]


def test_candidate_ip_extraction_and_classification():
    """
    WHAT: Received headers containing a private (RFC1918) IP and a public IP.
    WHY: Detection/correlation logic downstream needs correctly scoped IPs,
         and must never blindly assume "first IP = attacker."
    EXPECTED: Both IPs extracted; private one classified 'private', public
              one classified 'public'; original hop order preserved via
              source_header_index.
    """
    raw = (
        "From: a@example.com\r\n"
        "Received: from mx (8.8.8.8) by relay; t2\r\n"
        "Received: from internal (10.0.0.5) by mx; t1\r\n\r\n"
        "Body\r\n"
    )
    msg = _make_message(raw)
    headers = parse_headers(msg)
    ip_map = {c.ip: c.scope for c in headers.candidate_ips}
    assert ip_map["8.8.8.8"] == "public"
    assert ip_map["10.0.0.5"] == "private"


def test_invalid_ip_like_token_is_marked_invalid():
    """
    WHAT: A Received header containing a numeric token that looks IP-shaped
          but is out of valid octet range.
    WHY: Regex-based extraction can match invalid-looking octets in edge
         cases; classification must not crash on them.
    EXPECTED: No exception; any out-of-range match is excluded or marked
              invalid rather than silently treated as a real address.
    """
    raw = "From: a@example.com\r\nReceived: from x (999.999.999.999) by y; t\r\n\r\nBody\r\n"
    msg = _make_message(raw)
    headers = parse_headers(msg)
    # Our regex only matches valid 0-255 octet ranges, so 999.999.999.999
    # should simply not be picked up as a candidate at all.
    assert all(c.ip != "999.999.999.999" for c in headers.candidate_ips)
