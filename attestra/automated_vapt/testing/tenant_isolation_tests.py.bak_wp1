"""Tenant isolation probes using Account A vs Account B project tenants."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, login, request_pair
from attestra.automated_vapt.testing._session import (
    SKIP_NO_AUTH_SESSION,
    SKIP_NO_SECOND_ROLE,
    is_substantive_json,
    parse_json,
    probe_urls,
    ready_auth,
    request_auth,
    resolve_mode,
    scrub_pair,
    skip_result,
)

# @lat: [[architecture#Elite automated security testing#Authz test modules]]

_TENANT_KEYS = ("tenant", "tenant_id", "tenantId", "org", "org_id", "orgId", "account_id", "accountId")


def _tenant_values(data: Any) -> list[str]:
    found: list[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            if k in _TENANT_KEYS and v is not None and str(v).strip():
                found.append(str(v))
            found.extend(_tenant_values(v))
    elif isinstance(data, list):
        for item in data[:30]:
            found.extend(_tenant_values(item))
    # unique
    out: list[str] = []
    for v in found:
        if v not in out:
            out.append(v)
    return out


def _run_with_session(client, base_url: str, auth: Any, **kwargs) -> dict[str, Any]:
    secondary = ready_auth(kwargs, "_secondary_session_auth")
    if secondary is None:
        return skip_result(
            "T06",
            "authorization",
            SKIP_NO_SECOND_ROLE,
            "cross-tenant T06 needs a second-role (or second-tenant) login profile",
        )
    urls = probe_urls(base_url, kwargs, api=True, limit=8)
    if not urls:
        urls = probe_urls(base_url, kwargs, api=False, limit=6)
    evidence: list[Any] = []
    rows: list[dict[str, Any]] = []
    cross = False
    last_status = None
    for url in urls:
        pair_a = request_auth(client, "GET", url, auth, base_url)
        pair_b = request_auth(client, "GET", url, secondary, base_url)
        a_sub = is_substantive_json(pair_a.status, pair_a.response_body)
        b_sub = is_substantive_json(pair_b.status, pair_b.response_body)
        ten_a = _tenant_values(parse_json(pair_a.response_body) if a_sub else None)
        ten_b = _tenant_values(parse_json(pair_b.response_body) if b_sub else None)
        last_status = int(pair_a.status or 0)
        # Cross-tenant: A sees a tenant id that is exclusive to B (or vice versa) in the same call.
        leaked = bool(ten_a and ten_b and set(ten_a) & set(ten_b) and set(ten_a) != set(ten_b))
        # Stronger: A body contains a tenant value that B claims and A also claims a different one
        # plus identical exclusive values mixed. Also flag when A and B get each other's
        # exclusive tenant sets on the same URL (A has B-only values).
        a_only = set(ten_a) - set(ten_b)
        b_only = set(ten_b) - set(ten_a)
        mixed = bool(ten_a and ten_b and (set(ten_a) & set(ten_b)) and (a_only or b_only))
        row_cross = mixed
        if row_cross:
            cross = True
            evidence.append(scrub_pair(pair_a, auth, secondary))
        rows.append(
            {
                "url": url,
                "primary_status": int(pair_a.status or 0),
                "secondary_status": int(pair_b.status or 0),
                "tenant_key_present": bool(ten_a or ten_b),
                "cross_tenant": row_cross,
            }
        )
    return {
        "test_id": "T06",
        "category": "authorization",
        "observations": {
            "mode": "engagement_session",
            "cross_tenant_status": last_status,
            "cross_tenant_access": cross,
            "probes": rows,
        },
        "finding_candidate": cross,
        "evidence_pairs": evidence,
        "evidence_hints": [f"GET {u} as primary vs secondary profile" for u in urls],
    }


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    mode, auth = resolve_mode(client, kwargs)
    if mode == "engagement":
        return _run_with_session(client, base_url, auth, **kwargs)
    if mode == "skip":
        return skip_result(
            "T06",
            "authorization",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped lab account_a tenant probes",
        )

    from attestra.automated_vapt.testing._http import clear_cookies, login_response

    clear_cookies(client)
    try:
        lr = login_response(client, base_url, "account_a", "account-a-pass")
        login_ok = int(getattr(lr, "status_code", 0) or 0) in (200, 302, 303)
    except Exception:
        login_ok = False
    if not login_ok:
        # No mock accounts (typical on real apps without lab fixtures): skip cleanly.
        return {
            "test_id": "T06",
            "category": "authorization",
            "status_hint": "SKIPPED",
            "skip_reason": "no_mock_accounts",
            "observations": {
                "detail": "account_a login failed; cross-tenant T06 needs lab mocks or two tenant profiles",
            },
            "finding_candidate": False,
            "evidence_hints": [],
        }

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
