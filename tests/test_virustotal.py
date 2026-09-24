"""
Tests for src/intelligence/virustotal.py

All tests mock network calls — none of these tests make a real request to
VirusTotal. This module's core design requirement is graceful degradation,
so most tests focus on failure modes.
"""

from unittest.mock import MagicMock, patch

import requests

from src.intelligence import virustotal


def test_missing_api_key_returns_unavailable(monkeypatch):
    """
    WHAT: VT_API_KEY not set in the environment.
    WHY: The tool must run fully without any VirusTotal key configured —
         this is the default state for most users of this project.
    EXPECTED: available=False with a clear, non-crashing reason.
    """
    monkeypatch.delenv("VT_API_KEY", raising=False)
    result = virustotal.lookup_domain("example.test")
    assert result.available is False
    assert "VT_API_KEY" in result.error


@patch("src.intelligence.virustotal.requests.get")
def test_invalid_api_key_401_handled(mock_get, monkeypatch):
    """
    WHAT: VirusTotal responds with HTTP 401 (invalid API key).
    WHY: Users may have a typo'd or revoked key; must degrade, not crash.
    EXPECTED: available=False, error mentions invalid key, no exception raised.
    """
    monkeypatch.setenv("VT_API_KEY", "fake-invalid-key")
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_get.return_value = mock_response

    result = virustotal.lookup_domain("example.test")
    assert result.available is False
    assert "401" in result.error or "Invalid" in result.error


@patch("src.intelligence.virustotal.requests.get")
def test_rate_limit_429_handled(mock_get, monkeypatch):
    """
    WHAT: VirusTotal responds with HTTP 429 (rate limited).
    WHY: The free VT tier has strict rate limits; must degrade gracefully.
    EXPECTED: available=False, error mentions rate limiting.
    """
    monkeypatch.setenv("VT_API_KEY", "fake-key")
    mock_response = MagicMock()
    mock_response.status_code = 429
    mock_get.return_value = mock_response

    result = virustotal.lookup_ip("8.8.8.8")
    assert result.available is False
    assert "429" in result.error or "Rate limited" in result.error


@patch("src.intelligence.virustotal.requests.get")
def test_timeout_handled(mock_get, monkeypatch):
    """
    WHAT: The request to VirusTotal times out.
    WHY: Network issues must never hang or crash the whole analysis pipeline.
    EXPECTED: available=False, error mentions timeout, no exception escapes.
    """
    monkeypatch.setenv("VT_API_KEY", "fake-key")
    mock_get.side_effect = requests.exceptions.Timeout()

    result = virustotal.lookup_hash("a" * 64)
    assert result.available is False
    assert "timed out" in result.error.lower()


@patch("src.intelligence.virustotal.requests.get")
def test_connection_error_handled(mock_get, monkeypatch):
    """
    WHAT: No network connectivity / DNS failure reaching VirusTotal.
    WHY: The tool must be usable fully offline aside from this one enrichment call.
    EXPECTED: available=False, no exception escapes.
    """
    monkeypatch.setenv("VT_API_KEY", "fake-key")
    mock_get.side_effect = requests.exceptions.ConnectionError()

    result = virustotal.lookup_domain("example.test")
    assert result.available is False


@patch("src.intelligence.virustotal.requests.get")
def test_successful_lookup_parses_stats(mock_get, monkeypatch):
    """
    WHAT: A well-formed 200 response with analysis stats.
    WHY: Baseline correctness for the success path.
    EXPECTED: available=True with malicious/suspicious/harmless counts parsed.
    """
    monkeypatch.setenv("VT_API_KEY", "fake-key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 2, "harmless": 60}}}
    }
    mock_get.return_value = mock_response

    result = virustotal.lookup_domain("evil.test")
    assert result.available is True
    assert result.malicious_votes == 5
    assert result.suspicious_votes == 2
    assert result.harmless_votes == 60


@patch("src.intelligence.virustotal.requests.get")
def test_unknown_ioc_404_handled(mock_get, monkeypatch):
    """
    WHAT: VirusTotal has no record of the IOC (HTTP 404).
    WHY: Brand-new infrastructure won't yet be in VT's database — a very
         common case, not an error condition to crash on.
    EXPECTED: available=False, error mentions not found.
    """
    monkeypatch.setenv("VT_API_KEY", "fake-key")
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    result = virustotal.lookup_hash("f" * 64)
    assert result.available is False
    assert "not found" in result.error.lower() or "404" in result.error


@patch("src.intelligence.virustotal.requests.get")
def test_malformed_json_response_handled(mock_get, monkeypatch):
    """
    WHAT: A 200 response whose body is not valid JSON.
    WHY: Defensive coding against unexpected API changes/proxies.
    EXPECTED: available=False, no exception escapes.
    """
    monkeypatch.setenv("VT_API_KEY", "fake-key")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = ValueError("not JSON")
    mock_get.return_value = mock_response

    result = virustotal.lookup_domain("example.test")
    assert result.available is False
