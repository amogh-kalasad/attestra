"""Tenant isolation probes using Account A vs Account B project tenants.

D-04: on a live engagement, T06 compares the *same* URLs as the primary and the
secondary engagement profile (read-only GETs). Identity values (tenant / owner /
user keys) that only one profile sees elsewhere prove the two identities differ; the
other profile then seeing those values on the same object is cross-identity access.
Without distinguishable identities the case is INCONCLUSIVE, never PASSED; WAF /
challenge / rate-limit answers make it BLOCKED.
"""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.core.response_classifier import (
    ResponseClass,
    classify_pair,
    is_blocking,
    samples_to_json,
    skip_reason_for,
)
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
# Owner / user identity keys used for same-object comparison across identities (D-04).
_OWNER_KEYS = (
    "owner", "owner_id", "ownerId", "user_id", "userId", "created_by", "createdBy",
    "username", "user_name", "userName", "email", "member_id", "memberId",
)


def identity_values(data: Any, keys: tuple[str, ...] = _TENANT_KEYS + _OWNER_KEYS, *, depth: int = 0) -> list[str]:
    """Values of tenant/owner identity keys in a JSON body (kept in memory, never reported)."""
    found: list[str] = []
    if depth > 6:
        return found
    if isinstance(data, dict):
        for k, v in data.items():
            if k in keys and v is not None and not isinstance(v, (dict, list)) and str(v).strip():
                found.append(str(v))
            found.extend(identity_values(v, keys, depth=depth + 1))
    elif isinstance(data, list):
        for item in data[:30]:
            found.extend(identity_values(item, keys, depth=depth + 1))
    out: list[str] = []
    for v in found:
        if v not in out:
            out.append(v)
    return out


def compare_identities(rows: list[tuple[set[str], set[str]]]) -> dict[str, Any]:
    """Same-object comparison across two identities (pure).

    ``rows`` holds ``(primary_values, secondary_values)`` per URL (substantive bodies
    only). Values seen only by one identity somewhere prove the identities differ;
    the other identity seeing them on any URL is cross-identity access.
    """
    a_only: set[str] = set()
    b_only: set[str] = set()
    for a, b in rows:
        a_only |= a - b
        b_only |= b - a
    distinct = bool(a_only and b_only)
    cross_rows: list[int] = []
    for i, (a, b) in enumerate(rows):
        mixed = bool(a and b and (a & b) and (a ^ b))
        leak = distinct and bool((b & a_only) or (a & b_only))
        if mixed or leak:
            cross_rows.append(i)
    return {"distinct_identities": distinct, "cross_rows": cross_rows}


def _tenant_values(data: Any) -> list[str]:
    """Tenant-key values only (kept for callers of the pre-D-04 helper)."""
    return identity_values(data, _TENANT_KEYS)


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
    samples = []
    pairs: list[tuple[Any, Any]] = []
    value_rows: list[tuple[set[str], set[str]]] = []
    last_status = None
    for url in urls:
        pair_a = request_auth(client, "GET", url, auth, base_url)
        pair_b = request_auth(client, "GET", url, secondary, base_url)
        c_a = classify_pair(pair_a, authed=True)
        c_b = classify_pair(pair_b, authed=True)
        samples.extend([c_a, c_b])
        a_sub = c_a.cls is ResponseClass.APP_OK and is_substantive_json(pair_a.status, pair_a.response_body)
        b_sub = c_b.cls is ResponseClass.APP_OK and is_substantive_json(pair_b.status, pair_b.response_body)
        val_a = set(identity_values(parse_json(pair_a.response_body) if a_sub else None))
        val_b = set(identity_values(parse_json(pair_b.response_body) if b_sub else None))
        value_rows.append((val_a, val_b))
        pairs.append((pair_a, pair_b))
        last_status = int(pair_a.status or 0)
        rows.append(
            {
                "url": url,
                "primary_status": int(pair_a.status or 0),
                "secondary_status": int(pair_b.status or 0),
                "primary_class": c_a.cls.value,
                "secondary_class": c_b.cls.value,
                "tenant_key_present": bool(val_a or val_b),
                "cross_tenant": False,
            }
        )
    cmp = compare_identities(value_rows)
    for i in cmp["cross_rows"]:
        rows[i]["cross_tenant"] = True
        pair_a, pair_b = pairs[i]
        evidence.append(scrub_pair(pair_b, auth, secondary))
    cross = bool(cmp["cross_rows"])
    blocked = any(is_blocking(c) for c in samples)
    result: dict[str, Any] = {
        "test_id": "T06",
        "category": "authorization",
        "observations": {
            "mode": "engagement_session",
            "identities": [f"profile#{getattr(auth, 'profile_id', None)}", f"profile#{getattr(secondary, 'profile_id', None)}"],
            "distinct_identities": cmp["distinct_identities"],
            "cross_tenant_status": last_status,
            "cross_tenant_access": cross,
            "probes": rows,
        },
        "finding_candidate": cross,
        "evidence_pairs": evidence,
        "evidence_hints": [f"GET {u} as primary vs secondary profile" for u in urls],
        "validity_samples": samples_to_json(samples),
    }
    if not cross:
        if blocked:
            result["status_hint"] = "BLOCKED"
            result["skip_reason"] = skip_reason_for(samples)
        elif not cmp["distinct_identities"]:
            result["status_hint"] = "INCONCLUSIVE"
            result["skip_reason"] = "identities_not_distinguishable"
    return result


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
