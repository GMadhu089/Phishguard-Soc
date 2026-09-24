"""
DKIM signature extraction.

Extracts useful fields from the DKIM-Signature header.
This module does NOT perform cryptographic verification yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import re
import dkim


@dataclass
class DKIMSignature:
    domain: Optional[str] = None
    selector: Optional[str] = None
    algorithm: Optional[str] = None
    canonicalization: Optional[str] = None
    signed_headers: Optional[str] = None
    body_hash: Optional[str] = None
    raw: Optional[str] = None
    verified: Optional[bool] = None


def extract_dkim_signature(headers: list[str]) -> Optional[DKIMSignature]:
    """
    Extract the first DKIM-Signature header.

    Returns None when no DKIM-Signature header is present.
    """

    if not headers:
        return None

    for header in headers:
        if not header:
            continue

        unfolded = re.sub(r"\r?\n[ \t]+", " ", header).strip()

        if unfolded.lower().startswith("dkim-signature:"):
            value = unfolded.split(":", 1)[1].strip()
        else:
            value = unfolded

        fields = {}
        for part in value.split(";"):
            part = part.strip()

            if "=" not in part:
                continue

            key, val = part.split("=", 1)
            fields[key.strip().lower()] = val.strip()

        return DKIMSignature(
            domain=fields.get("d"),
            selector=fields.get("s"),
            algorithm=fields.get("a"),
            canonicalization=fields.get("c"),
            signed_headers=fields.get("h"),
            body_hash=fields.get("bh"),
            raw=unfolded,
        )

    return None

def verify_dkim(raw_message: bytes) -> bool:
    """
    Perform cryptographic DKIM verification using dkimpy.

    Returns:
        True if the DKIM signature is cryptographically valid.
        False otherwise.
    """
    try:
        return bool(dkim.verify(raw_message))
    except Exception:
        return False