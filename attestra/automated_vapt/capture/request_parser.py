"""Normalize captured HTTP requests for Elite validation modules."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from attestra.proof.pair import HttpPair
from attestra.proof.redact import is_sensitive_name

# @lat: [[architecture#Elite automated security testing#HTTP capture]]


def parse_request(pair: HttpPair | dict[str, Any]) -> dict[str, Any]:
    """Extract query, JSON/form fields, path identifiers, and auth metadata.

    Keeps the original request separately under ``original``. Sensitive values
    in ``fields`` are replaced with ``[REDACTED]`` for ordinary use.
    """
    if isinstance(pair, HttpPair):
        method = pair.method
        url = pair.url
        headers = dict(pair.request_headers or {})
        body = pair.request_body or ""
    else:
        method = str(pair.get("method") or "GET").upper()
        url = str(pair.get("url") or "")
        headers = {str(k): str(v) for k, v in (pair.get("request_headers") or {}).items()}
        body = str(pair.get("request_body") or "")

    parts = urlsplit(url)
    query = {k: _maybe_redact(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)}
    path_ids = _path_identifiers(parts.path or "/")
    json_fields: dict[str, Any] = {}
    form_fields: dict[str, Any] = {}
    ct = _content_type(headers)
    if body.strip():
        if "json" in ct or body.strip()[:1] in ("{", "["):
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    json_fields = {k: _maybe_redact(k, v) for k, v in parsed.items()}
            except json.JSONDecodeError:
                json_fields = {}
        elif "form" in ct or "=" in body:
            form_fields = {
                k: _maybe_redact(k, v) for k, v in parse_qsl(body, keep_blank_values=True)
            }

    auth_meta = {
        "has_authorization": any(k.lower() == "authorization" for k in headers),
        "has_cookie": any(k.lower() == "cookie" for k in headers),
        "authorization_scheme": _auth_scheme(headers),
    }
    return {
        "method": method,
        "url": url,
        "path": parts.path or "/",
        "query": query,
        "json_fields": json_fields,
        "form_fields": form_fields,
        "path_identifiers": path_ids,
        "auth": auth_meta,
        "original": {
            "method": method,
            "url": url,
            "headers": headers,
            "body": body,
        },
    }


def _content_type(headers: dict[str, str]) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v.lower()
    return ""


def _auth_scheme(headers: dict[str, str]) -> str:
    for k, v in headers.items():
        if k.lower() == "authorization":
            return (v.split(None, 1)[0] if v else "")[:40]
    return ""


def _path_identifiers(path: str) -> list[str]:
    parts = [p for p in path.split("/") if p]
    out: list[str] = []
    for p in parts:
        if p.isdigit() or (len(p) >= 8 and any(c.isdigit() for c in p)):
            out.append(p)
        elif p.lower().startswith(("proj-", "user-", "org-", "tenant-")):
            out.append(p)
    return out


def _maybe_redact(name: str, value: Any) -> Any:
    if is_sensitive_name(str(name)) and not isinstance(value, (dict, list)):
        return "[REDACTED]"
    return value
