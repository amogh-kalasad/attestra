"""Redact credentials from captured HTTP traffic before it is hashed and stored."""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-amz-security-token",
    }
)
_SENSITIVE_NAME = re.compile(r"(?i)(token|secret|passw|pwd|api[_-]?key|session|auth|signature|^sig$|jwt|bearer)")


def is_sensitive_name(name: str) -> bool:
    return bool(_SENSITIVE_NAME.search(name or ""))


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        low = k.lower()
        out[k] = REDACTED if low in SENSITIVE_HEADERS or is_sensitive_name(low) else v
    return out


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    if not parts.query:
        return url
    q = [(k, REDACTED if is_sensitive_name(k) else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit(parts._replace(query=urlencode(q, safe="[]")))


def _redact_json(obj):
    if isinstance(obj, dict):
        return {k: (REDACTED if is_sensitive_name(str(k)) and not isinstance(v, (dict, list)) else _redact_json(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_json(v) for v in obj]
    return obj


def redact_body(body: str, content_type: str = "") -> str:
    if not body:
        return body
    stripped = body.strip()
    if "json" in content_type.lower() or stripped[:1] in ("{", "["):
        try:
            return json.dumps(_redact_json(json.loads(stripped)))
        except ValueError:
            pass
    if "x-www-form-urlencoded" in content_type.lower():
        q = [(k, REDACTED if is_sensitive_name(k) else v) for k, v in parse_qsl(stripped, keep_blank_values=True)]
        return urlencode(q, safe="[]")
    # Fallback: key=value / "key": "value" occurrences in free text.
    body = re.sub(
        r'(?i)(["\']?(?:[a-z0-9_-]*(?:token|secret|password|passwd|api[_-]?key|session)[a-z0-9_-]*)["\']?\s*[:=]\s*["\']?)([^"\'&\s,;]+)',
        lambda m: m.group(1) + REDACTED,
        body,
    )
    return re.sub(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-+=/]{8,}", r"\1" + REDACTED, body)
