"""Pure helpers for safe reflection / canary detection (no network I/O)."""

from __future__ import annotations

import html
import re
import secrets
from typing import Any

CANARY_PREFIX = "ATTSTRA_CANARY_"

_HTML_HINT = re.compile(
    r"(?i)<(!doctype\s+html|html\b|head\b|body\b|div\b|span\b|p\b|script\b|form\b|title\b)"
)


def new_canary(*, tag: str = "") -> str:
    """Return a unique ``ATTSTRA_CANARY_*`` marker (alphanumeric + underscores)."""
    mid = f"{tag}_" if tag else ""
    return f"{CANARY_PREFIX}{mid}{secrets.token_hex(4).upper()}"


def xss_canary_payload(canary: str | None = None) -> str:
    """Benign reflected-XSS shape: quote-break + unique marker (no script execution)."""
    marker = canary or new_canary(tag="XSS")
    return f"'\"><{marker}>"


def injection_canary_payload(canary: str | None = None) -> str:
    """Benign injection-surface canary with a quote (no time-based or destructive payload)."""
    marker = canary or new_canary(tag="INJ")
    return f"{marker}'"


def is_html_body(body: str, content_type: str | None = None) -> bool:
    """True when Content-Type is HTML or the body looks like HTML markup."""
    if content_type and "html" in content_type.lower():
        return True
    sample = (body or "")[:4000]
    return bool(_HTML_HINT.search(sample))


def detect_unencoded_reflection(needle: str, body: str) -> bool:
    """True when ``needle`` appears literally in ``body`` (not HTML-entity-only)."""
    if not needle or not body:
        return False
    if needle in body:
        return True
    return False


def detect_encoded_only_reflection(needle: str, body: str) -> bool:
    """True when only an HTML-escaped form of ``needle`` appears (proper encoding)."""
    if not needle or not body or needle in body:
        return False
    escaped = html.escape(needle, quote=True)
    return escaped != needle and escaped in body


def reflection_in_headers(needle: str, headers: dict[str, Any] | None) -> list[str]:
    """Return header names whose values contain the literal needle."""
    if not needle or not headers:
        return []
    hit: list[str] = []
    for key, value in headers.items():
        if needle in str(value):
            hit.append(str(key))
    return hit


def reflected_unencoded_in_html(
    needle: str,
    body: str,
    *,
    content_type: str | None = None,
) -> bool:
    """Finding gate: literal reflection inside an HTML response context."""
    return detect_unencoded_reflection(needle, body) and is_html_body(body, content_type)
