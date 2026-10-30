"""Elite evidence redaction façade over proof.redact and evidence.mask."""

from __future__ import annotations

from attestra.evidence.mask import mask_bytes
from attestra.proof.pair import HttpPair
from attestra.proof.redact import redact_body, redact_headers, redact_url

# @lat: [[architecture#Elite automated security testing#Evidence integrity]]


def redact_http_pair(pair: HttpPair) -> HttpPair:
    """Return a sanitized copy suitable for reports; original caller keeps the raw pair."""
    return pair.redacted()


def redact_text(data: bytes, content_type: str = "text/plain") -> tuple[bytes, dict]:
    """Mask secrets/PANs in text evidence bytes."""
    return mask_bytes(data, content_type=content_type)


def redact_headers_only(headers: dict[str, str]) -> dict[str, str]:
    return redact_headers(headers)


def redact_url_only(url: str) -> str:
    return redact_url(url)


def redact_body_only(body: str, content_type: str = "") -> str:
    return redact_body(body, content_type)
