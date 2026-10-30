"""Normalize HTTP responses for Elite validation modules."""

from __future__ import annotations

import json
import re
from typing import Any

from attestra.proof.pair import HttpPair
from attestra.proof.redact import is_sensitive_name

# @lat: [[architecture#Elite automated security testing#HTTP capture]]

_ID_KEYS = frozenset(
    {
        "id",
        "userid",
        "user_id",
        "projectid",
        "project_id",
        "tenantid",
        "tenant_id",
        "organizationid",
        "organization_id",
        "role",
        "platform_role",
        "permissions",
    }
)
_SENSITIVE_MARKERS = (
    "SENSITIVE",
    "password",
    "api_token",
    "secret_note",
    "ssn",
    "credit card",
)


def parse_response(pair: HttpPair | dict[str, Any]) -> dict[str, Any]:
    """Extract status, JSON fields, identifiers, and sensitive-data indicators.

    Presence of a role or identifier alone does not imply a vulnerability.
    """
    if isinstance(pair, HttpPair):
        status = pair.status
        headers = dict(pair.response_headers or {})
        body = pair.response_body or ""
    else:
        status = pair.get("status")
        headers = {str(k): str(v) for k, v in (pair.get("response_headers") or {}).items()}
        body = str(pair.get("response_body") or "")

    json_fields: dict[str, Any] = {}
    if body.strip() and (body.strip()[:1] in ("{", "[") or "json" in _content_type(headers)):
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                json_fields = {k: _maybe_redact(k, v) for k, v in parsed.items()}
            elif isinstance(parsed, list):
                json_fields = {"_list_len": len(parsed)}
        except json.JSONDecodeError:
            json_fields = {}

    identifiers = {
        k: json_fields[k]
        for k in list(json_fields)
        if k.lower().replace("-", "_") in _ID_KEYS or k.lower() in _ID_KEYS
    }
    role_info = json_fields.get("role") or json_fields.get("platform_role")
    tenant_info = json_fields.get("tenant") or json_fields.get("tenantId") or json_fields.get("tenant_id")
    permission_fields = {
        k: json_fields[k]
        for k in json_fields
        if "permission" in k.lower() or k.lower() in ("permissions", "scopes")
    }
    sensitive_hits = [m for m in _SENSITIVE_MARKERS if re.search(re.escape(m), body, re.I)]
    # Also flag known leaky keys when present with non-empty values.
    for key in ("secret_note", "api_token", "password", "project_tokens"):
        if key in json_fields and json_fields[key] not in (None, "", "[REDACTED]"):
            if key not in sensitive_hits:
                sensitive_hits.append(key)

    return {
        "status": status,
        "json_fields": json_fields,
        "resource_identifiers": identifiers,
        "user_identifiers": {k: v for k, v in identifiers.items() if "user" in k.lower()},
        "role": role_info,
        "tenant": tenant_info,
        "permissions": permission_fields,
        "sensitive_indicators": sensitive_hits,
        "empty": not (body or "").strip(),
        "original_status": status,
    }


def _content_type(headers: dict[str, str]) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v.lower()
    return ""


def _maybe_redact(name: str, value: Any) -> Any:
    if is_sensitive_name(str(name)) and not isinstance(value, (dict, list)):
        return "[REDACTED]"
    return value
