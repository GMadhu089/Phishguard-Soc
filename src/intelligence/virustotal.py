"""
virustotal.py

Optional threat-intelligence enrichment layer using the VirusTotal public API.

CRITICAL DESIGN CONSTRAINT (per project spec): VirusTotal is an ENRICHMENT
layer, never the core detection engine. If the API key is missing, invalid,
rate-limited, times out, or the service is unreachable, this module must
return a clearly-labeled "unavailable" result and the rest of the pipeline
must continue working using local heuristics and detection rules alone.

Reads the key from the VT_API_KEY environment variable (loaded via
python-dotenv from a local .env file — never hardcoded, never logged).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import requests
# from dotenv import load_dotenv

from src.utils.logger import get_logger

logger = get_logger(__name__)

_VT_BASE_URL = "https://www.virustotal.com/api/v3"
_REQUEST_TIMEOUT_SECONDS = 8


@dataclass
class VTLookupResult:
    ioc_type: str  # "domain" | "ip" | "url" | "hash"
    ioc_value: str
    available: bool
    malicious_votes: Optional[int] = None
    suspicious_votes: Optional[int] = None
    harmless_votes: Optional[int] = None
    error: Optional[str] = None  # human-readable reason when available=False


def _get_api_key() -> Optional[str]:
    # load_dotenv()
    key = os.getenv("VT_API_KEY")
    return key.strip() if key and key.strip() else None


def _headers(api_key: str) -> dict:
    return {"x-apikey": api_key}


def _make_unavailable(ioc_type: str, ioc_value: str, reason: str) -> VTLookupResult:
    # Never include the API key or any part of it in the reason string.
    logger.warning("VirusTotal lookup unavailable for %s '%s': %s", ioc_type, ioc_value, reason)
    return VTLookupResult(ioc_type=ioc_type, ioc_value=ioc_value, available=False, error=reason)


def _parse_stats(response_json: dict, ioc_type: str, ioc_value: str) -> VTLookupResult:
    try:
        stats = response_json["data"]["attributes"]["last_analysis_stats"]
        return VTLookupResult(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            available=True,
            malicious_votes=stats.get("malicious", 0),
            suspicious_votes=stats.get("suspicious", 0),
            harmless_votes=stats.get("harmless", 0),
        )
    except (KeyError, TypeError) as exc:
        return _make_unavailable(ioc_type, ioc_value, f"Unexpected response shape: {exc}")


def _safe_get(url: str, api_key: str, ioc_type: str, ioc_value: str) -> VTLookupResult:
    try:
        response = requests.get(url, headers=_headers(api_key), timeout=_REQUEST_TIMEOUT_SECONDS)
    except requests.exceptions.Timeout:
        return _make_unavailable(ioc_type, ioc_value, "Request timed out.")
    except requests.exceptions.ConnectionError:
        return _make_unavailable(ioc_type, ioc_value, "Network/connection error.")
    except requests.exceptions.RequestException as exc:
        return _make_unavailable(ioc_type, ioc_value, f"Request failed: {exc}")

    if response.status_code == 401:
        return _make_unavailable(ioc_type, ioc_value, "Invalid API key (401).")
    if response.status_code == 429:
        return _make_unavailable(ioc_type, ioc_value, "Rate limited by VirusTotal (429).")
    if response.status_code == 404:
        return _make_unavailable(ioc_type, ioc_value, "IOC not found in VirusTotal (404).")
    if response.status_code != 200:
        return _make_unavailable(ioc_type, ioc_value, f"Unexpected HTTP status {response.status_code}.")

    try:
        return _parse_stats(response.json(), ioc_type, ioc_value)
    except ValueError:
        return _make_unavailable(ioc_type, ioc_value, "Response was not valid JSON.")


def lookup_domain(domain: str) -> VTLookupResult:
    api_key = _get_api_key()
    if not api_key:
        return _make_unavailable("domain", domain, "No VT_API_KEY configured; enrichment skipped.")
    return _safe_get(f"{_VT_BASE_URL}/domains/{domain}", api_key, "domain", domain)


def lookup_ip(ip_address: str) -> VTLookupResult:
    api_key = _get_api_key()
    if not api_key:
        return _make_unavailable("ip", ip_address, "No VT_API_KEY configured; enrichment skipped.")
    return _safe_get(f"{_VT_BASE_URL}/ip_addresses/{ip_address}", api_key, "ip", ip_address)


def lookup_url(url: str) -> VTLookupResult:
    """
    VT's URL endpoint requires a URL identifier (base64 of the URL, no
    padding) rather than the raw URL string.
    """
    api_key = _get_api_key()
    if not api_key:
        return _make_unavailable("url", url, "No VT_API_KEY configured; enrichment skipped.")

    import base64

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return _safe_get(f"{_VT_BASE_URL}/urls/{url_id}", api_key, "url", url)


def lookup_hash(file_hash: str) -> VTLookupResult:
    api_key = _get_api_key()
    if not api_key:
        return _make_unavailable("hash", file_hash, "No VT_API_KEY configured; enrichment skipped.")
    return _safe_get(f"{_VT_BASE_URL}/files/{file_hash}", api_key, "hash", file_hash)
