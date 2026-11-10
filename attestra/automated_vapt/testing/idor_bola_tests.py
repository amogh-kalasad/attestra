"""Controlled two-account BOLA/IDOR checks for Elite automated security testing."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, login, request_json, request_pair
from attestra.automated_vapt.testing._session import (
    SKIP_NO_AUTH_SESSION,
    SKIP_NO_SECOND_ROLE,
    is_substantive_json,
    probe_urls,
    ready_auth,
    request_auth,
    resolve_mode,
    scrub_pair,
    secret_key_names,
    skip_result,
)

# @lat: [[architecture#Elite automated security testing#Authz test modules]]


def _run_with_session(client, base_url: str, auth: Any, **kwargs) -> dict[str, Any]:
    """Compare capture/API URLs as the primary vs secondary engagement profile."""
    from attestra.automated_vapt.testing._session import parse_json

    secondary = ready_auth(kwargs, "_secondary_session_auth")
    if secondary is None:
        return skip_result(
            "T04",
            "authorization",
            SKIP_NO_SECOND_ROLE,
            "IDOR/BOLA on an engagement target needs a second-role login profile",
        )
    urls = probe_urls(base_url, kwargs, api=True, limit=8)
    if not urls:
        urls = probe_urls(base_url, kwargs, api=False, limit=6)
    evidence: list[Any] = []
    rows: list[dict[str, Any]] = []
    exposed_keys: list[str] = []
    a_ok = False
    b_ok = False
    same_any = False
    for url in urls:
        pair_a = request_auth(client, "GET", url, auth, base_url)
        pair_b = request_auth(client, "GET", url, secondary, base_url)
        a_status = int(pair_a.status or 0)
        b_status = int(pair_b.status or 0)
        a_sub = is_substantive_json(a_status, pair_a.response_body)
        b_sub = is_substantive_json(b_status, pair_b.response_body)
        if a_status == 200:
            a_ok = True
        if b_status == 200:
            b_ok = True
        keys = secret_key_names(parse_json(pair_a.response_body) if a_sub else None)
        keys_b = secret_key_names(parse_json(pair_b.response_body) if b_sub else None)
        for name in keys + keys_b:
            if name not in exposed_keys:
                exposed_keys.append(name)
        same = (
            a_sub
            and b_sub
            and (pair_a.response_body or "").strip() == (pair_b.response_body or "").strip()
        )
        if same:
            same_any = True
        if (keys or keys_b or same):
            evidence.append(scrub_pair(pair_a, auth, secondary))
            evidence.append(scrub_pair(pair_b, auth, secondary))
        rows.append(
            {
                "url": url,
                "primary_status": a_status,
                "secondary_status": b_status,
                "same_body": same,
                "secret_key_names": keys or keys_b,
            }
        )
    has_secrets = bool(exposed_keys)
    finding_candidate = has_secrets or same_any
    first = rows[0] if rows else {}
    return {
        "test_id": "T04",
        "category": "authorization",
        "observations": {
            "mode": "engagement_session",
            "authorized_ok": a_ok and b_ok,
            "unauthorized_blocked": not same_any,
            "exposed_secrets": has_secrets,
            "secret_key_names": exposed_keys,
            "account_a_proj_a_status": first.get("primary_status"),
            "account_a_proj_b_status": first.get("secondary_status") if same_any else (401 if rows else None),
            "account_b_proj_b_status": first.get("secondary_status"),
            "probes": rows,
        },
        "finding_candidate": finding_candidate,
        "evidence_pairs": evidence,
        "evidence_hints": [f"GET {u} as primary vs secondary profile" for u in urls],
    }


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Account A owns proj-a; Account B owns proj-b. Cross-owner access must fail."""
    mode, auth = resolve_mode(client, kwargs)
    if mode == "engagement":
        return _run_with_session(client, base_url, auth, **kwargs)
    if mode == "skip":
        return skip_result(
            "T04",
            "authorization",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped lab account_a / proj-b probes",
        )

    login(client, base_url, "account_a", "account-a-pass")
    own_status, own_body, _ = request_json(client, "GET", absolute(base_url, "/api/projects/proj-a"))
    cross_url = absolute(base_url, "/api/projects/proj-b")
    cross_pair = request_pair(client, "GET", cross_url)
    cross_status = int(cross_pair.status or 0)
    cross_text = cross_pair.response_body
    cross_body: Any = None
    try:
        import json

        cross_body = json.loads(cross_text) if cross_text else None
    except Exception:
        cross_body = None

    login(client, base_url, "account_b", "account-b-pass")
    b_own_status, b_own_body, _ = request_json(client, "GET", absolute(base_url, "/api/projects/proj-b"))

    exposed_secrets = False
    if isinstance(cross_body, dict):
        note = str(cross_body.get("secret_note") or "")
        token = str(cross_body.get("api_token") or "")
        exposed_secrets = ("SENSITIVE" in note) or token.startswith("tok_")
    elif cross_status == 200 and ("SENSITIVE" in cross_text or "tok_" in cross_text):
        exposed_secrets = True

    authorized_ok = own_status == 200 and b_own_status == 200
    unauthorized_blocked = cross_status in (401, 403, 404)
    finding_candidate = cross_status == 200 and (exposed_secrets or isinstance(cross_body, dict))

    evidence_pairs = []
    if finding_candidate:
        evidence_pairs.append(cross_pair)

    return {
        "test_id": "T04",
        "category": "authorization",
        "observations": {
            "account_a_proj_a_status": own_status,
            "account_a_proj_b_status": cross_status,
            "account_b_proj_b_status": b_own_status,
            "authorized_ok": authorized_ok,
            "unauthorized_blocked": unauthorized_blocked,
            "exposed_secrets": exposed_secrets,
            "cross_body_keys": sorted(cross_body.keys()) if isinstance(cross_body, dict) else [],
        },
        "finding_candidate": finding_candidate,
        "evidence_pairs": evidence_pairs,
        "evidence_hints": [
            "GET /api/projects/proj-a as account_a",
            "GET /api/projects/proj-b as account_a",
            "GET /api/projects/proj-b as account_b",
        ],
    }
