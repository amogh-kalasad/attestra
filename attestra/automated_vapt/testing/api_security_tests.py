"""Configurable API security probes for Elite automated security testing."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, login, request_json
from attestra.automated_vapt.testing._session import (
    SKIP_AUTH_REQUESTS_FAILED,
    SKIP_NO_AUTH_SESSION,
    is_substantive_json,
    parse_json,
    probe_urls,
    request_auth,
    request_plain,
    resolve_mode,
    scrub_pair,
    secret_key_names,
    skip_result,
)

# @lat: [[architecture#Elite automated security testing#Authz test modules]]


def _run_with_session(client, base_url: str, auth: Any, **kwargs) -> dict[str, Any]:
    urls = probe_urls(base_url, kwargs, api=True, limit=8)
    if not urls:
        urls = probe_urls(base_url, kwargs, api=False, limit=6)
    evidence: list[Any] = []
    rows: list[dict[str, Any]] = []
    any_auth_ok = False
    any_unauth_blocked = False
    any_unauth_open = False
    excessive_keys: list[str] = []
    users_status = None
    unauth_status = None
    for url in urls:
        unauth = request_plain(client, "GET", url)
        authed = request_auth(client, "GET", url, auth, base_url)
        u_status = int(unauth.status or 0)
        a_status = int(authed.status or 0)
        if unauth_status is None:
            unauth_status = u_status
        if users_status is None:
            users_status = a_status
        auth_ok = a_status == 200
        if auth_ok:
            any_auth_ok = True
        if u_status in (401, 403):
            any_unauth_blocked = True
        open_unauth = u_status == 200 and (
            is_substantive_json(u_status, unauth.response_body)
            or (
                auth_ok
                and (unauth.response_body or "").strip() == (authed.response_body or "").strip()
                and len(unauth.response_body or "") >= 32
            )
        )
        if open_unauth:
            any_unauth_open = True
            evidence.append(scrub_pair(unauth, auth))
        keys = secret_key_names(parse_json(authed.response_body) if auth_ok else None)
        for name in keys:
            if name not in excessive_keys:
                excessive_keys.append(name)
        if keys:
            evidence.append(scrub_pair(authed, auth))
        rows.append(
            {
                "url": url,
                "unauth_status": u_status,
                "auth_status": a_status,
                "secret_key_names": keys,
            }
        )
    if not any_auth_ok:
        return skip_result(
            "T07",
            "disclosure",
            SKIP_AUTH_REQUESTS_FAILED,
            "authenticated GETs did not succeed with the engagement session; cannot assess API exposure",
        )
    # Auth enforcement counts only when unauth is blocked *and* the session is accepted.
    missing_auth_enforced = any_unauth_blocked and not any_unauth_open
    excessive = bool(excessive_keys)
    finding_candidate = (not missing_auth_enforced) or excessive
    return {
        "test_id": "T07",
        "category": "disclosure",
        "observations": {
            "mode": "engagement_session",
            "unauth_project_status": unauth_status,
            "missing_auth_enforced": missing_auth_enforced,
            "users_status": users_status,
            "excessive_data_exposure": excessive,
            "secret_key_names": excessive_keys,
            "probes": rows,
        },
        "finding_candidate": finding_candidate,
        "evidence_pairs": evidence,
        "evidence_hints": [f"GET {u} unauth vs session" for u in urls],
    }


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    mode, auth = resolve_mode(client, kwargs)
    if mode == "engagement":
        return _run_with_session(client, base_url, auth, **kwargs)
    if mode == "skip":
        return skip_result(
            "T07",
            "disclosure",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped lab /api/users probes",
        )

    # Missing authentication — clear session cookies first when supported.
    jar = getattr(client, "cookies", None)
    if jar is not None:
        try:
            jar.clear()
        except Exception:
            pass
    unauth_status, _, _ = request_json(client, "GET", absolute(base_url, "/api/projects/proj-a"))
    missing_auth_enforced = unauth_status in (401, 403)

    login(client, base_url, "account_a", "account-a-pass")
    users_status, users_body, _ = request_json(client, "GET", absolute(base_url, "/api/users"))
    excessive = False
    if isinstance(users_body, dict):
        rows = users_body.get("users") or []
        if any(isinstance(u, dict) and "password" in u for u in rows):
            excessive = True
        if "project_tokens" in users_body:
            excessive = True

    finding_candidate = (not missing_auth_enforced) or excessive
    return {
        "test_id": "T07",
        "category": "disclosure",
        "observations": {
            "unauth_project_status": unauth_status,
            "missing_auth_enforced": missing_auth_enforced,
            "users_status": users_status,
            "excessive_data_exposure": excessive,
        },
        "finding_candidate": finding_candidate,
        "evidence_hints": ["GET /api/projects/proj-a unauthenticated", "GET /api/users authenticated"],
    }
