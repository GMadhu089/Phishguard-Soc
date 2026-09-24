"""
url_analyzer.py

Extracts URLs from plain-text and HTML email bodies, and — critically for
phishing detection — compares the VISIBLE link text against the ACTUAL
href destination in HTML anchor tags. A mismatch (e.g. visible text reads
"https://www.microsoft.com" but the real href points to
"https://microsoft-login-example.test/login") is one of the strongest
single indicators of credential-harvesting phishing, but per project
design it is still just evidence fed to the detection engine, not an
automatic verdict.

Also flags suspicious URL characteristics via local heuristics:
IP-based host, excessive subdomains, @ symbol, URL-encoded characters,
known shortener domains, punycode host.

We do NOT execute, fetch, or follow any extracted URL. This module only
does string/regex parsing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Broad URL matcher for plain text and inside HTML (also catches hrefs).
_URL_PATTERN = re.compile(r'https?://[^\s"\'<>\)]+', re.IGNORECASE)

# <a ... href="URL" ...>VISIBLE TEXT</a>  (non-greedy, tolerant of attribute order)
_ANCHOR_PATTERN = re.compile(
    r'<a\b[^>]*?href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)

_KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly",
}

_IPV4_HOST_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


@dataclass
class ExtractedURL:
    url: str
    source: str  # "text" | "html_visible" | "html_href"
    visible_text: Optional[str] = None  # populated only when source == "html_href"
    hostname: Optional[str] = None
    scheme: Optional[str] = None
    suspicious_flags: list[str] = field(default_factory=list)
    visible_href_mismatch: bool = False


def extract_urls_from_text(text_body: str) -> list[ExtractedURL]:
    """Extract bare URLs from a plain-text body."""
    if not text_body:
        return []

    urls = []
    for match in _URL_PATTERN.finditer(text_body):
        raw_url = _strip_trailing_punctuation(match.group(0))
        urls.append(_build_extracted_url(raw_url, source="text"))
    return urls


def extract_urls_from_html(html_body: str) -> list[ExtractedURL]:
    """
    Extract URLs from HTML: anchor hrefs (with visible-text mismatch check)
    plus any bare URLs that appear outside anchor tags.
    """
    if not html_body:
        return []

    urls: list[ExtractedURL] = []
    matched_spans: list[tuple[int, int]] = []

    for match in _ANCHOR_PATTERN.finditer(html_body):
        href_raw = match.group(1).strip()
        visible_raw = _strip_html_tags(match.group(2)).strip()
        matched_spans.append(match.span())

        href_extracted = _build_extracted_url(href_raw, source="html_href", visible_text=visible_raw or None)
        _check_visible_href_mismatch(href_extracted, visible_raw)
        urls.append(href_extracted)

    # Also catch bare URLs sitting outside any <a> tag (e.g. plain text
    # pasted into an HTML body, or tracking pixels with visible URLs).
    remainder = html_body
    for start, end in sorted(matched_spans, reverse=True):
        remainder = remainder[:start] + remainder[end:]

    for match in _URL_PATTERN.finditer(remainder):
        raw_url = _strip_trailing_punctuation(match.group(0))
        urls.append(_build_extracted_url(raw_url, source="html_visible"))

    return urls


def _build_extracted_url(raw_url: str, source: str, visible_text: Optional[str] = None) -> ExtractedURL:
    extracted = ExtractedURL(url=raw_url, source=source, visible_text=visible_text)

    try:
        parsed = urlparse(raw_url)
        extracted.hostname = parsed.hostname
        extracted.scheme = parsed.scheme
    except ValueError as exc:
        logger.warning("Could not parse URL '%s': %s", raw_url, exc)
        extracted.suspicious_flags.append("malformed_url")
        return extracted

    _apply_heuristics(extracted, raw_url, parsed)
    return extracted


def _apply_heuristics(extracted: ExtractedURL, raw_url: str, parsed) -> None:
    host = parsed.hostname or ""

    if _IPV4_HOST_PATTERN.match(host):
        extracted.suspicious_flags.append("ip_based_url")

    if host.count(".") >= 4:  # e.g. login.account.secure.example.test -> many subdomain labels
        extracted.suspicious_flags.append("excessive_subdomains")

    if "@" in raw_url.split("://", 1)[-1]:
        # userinfo@host trick: https://real-looking-text@attacker.test/
        extracted.suspicious_flags.append("at_symbol_in_url")

    if "%" in raw_url:
        extracted.suspicious_flags.append("url_encoded_characters")

    if host.lower() in _KNOWN_SHORTENERS:
        extracted.suspicious_flags.append("known_shortener")

    if host.startswith("xn--") or ".xn--" in host:
        extracted.suspicious_flags.append("punycode_host")

    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
        extracted.suspicious_flags.append("unusual_scheme")


def _check_visible_href_mismatch(extracted: ExtractedURL, visible_text: str) -> None:
    """
    Flags when the visible link text looks like a URL/domain itself but
    points somewhere else than the actual href. We only compare when the
    visible text plausibly IS a URL or bare domain — visible text that is
    ordinary prose ("Click here") is not a mismatch by this definition,
    it's just an opaque link (a separate, weaker signal handled by rules.py).
    """
    if not visible_text:
        return

    visible_url_match = _URL_PATTERN.search(visible_text)
    visible_host = None

    if visible_url_match:
        try:
            visible_host = urlparse(visible_url_match.group(0)).hostname
        except ValueError:
            visible_host = None
    else:
        # Bare-domain-looking visible text, e.g. "www.microsoft.com" with no scheme.
        bare_domain_match = re.match(r"^(?:www\.)?[\w\-]+(?:\.[\w\-]+)+$", visible_text.strip())
        if bare_domain_match:
            visible_host = visible_text.strip().lower()

    if visible_host and extracted.hostname:
        if _strip_www(visible_host) != _strip_www(extracted.hostname):
            extracted.visible_href_mismatch = True
            extracted.suspicious_flags.append("visible_href_mismatch")


def _strip_www(hostname: str) -> str:
    """Remove a literal leading 'www.' prefix (NOT str.lstrip, which strips
    characters rather than the literal substring and would corrupt hosts
    like 'wallet.com' -> 'allet.com')."""
    hostname = hostname.lower()
    return hostname[4:] if hostname.startswith("www.") else hostname


def _strip_html_tags(fragment: str) -> str:
    return re.sub(r"<[^>]+>", "", fragment)


def _strip_trailing_punctuation(url: str) -> str:
    return url.rstrip(".,;:!?)")
