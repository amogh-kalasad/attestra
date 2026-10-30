"""Tenant isolation probes using Account A vs Account B project tenants."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, login, request_pair

# @lat: [[architecture#Elite automated security testing#Authz test modules]]


def run(client, base_url: str, **_kwargs) -> dict[str, Any]:
    login(client, base_url, "account_a", "account-a-pass")
    pair = request_pair(client, "GET", absolute(base_url, "/api/projects/proj-b"))
    status = int(pair.status or 0)
    body: Any = None
    try:
        import json

        body = json.loads(pair.response_body) if pair.response_body else None
    except Exception:
        body = None
    cross_tenant = status == 200 and isinstance(body, dict) and body.get("tenant") == "tenant-b"
    evidence_pairs = [pair] if cross_tenant else []
    return {
        "test_id": "T06",
        "category": "authorization",
        "observations": {
            "cross_tenant_status": status,
            "cross_tenant_access": cross_tenant,
            "returned_tenant": (body or {}).get("tenant") if isinstance(body, dict) else None,
        },
        "finding_candidate": cross_tenant,
        "evidence_pairs": evidence_pairs,
        "evidence_hints": ["GET /api/projects/proj-b as account_a (tenant-a)"],
    }
