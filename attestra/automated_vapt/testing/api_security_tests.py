"""Configurable API security probes for Elite automated security testing.

FND-04: ``missing_auth_enforced`` is True only when some URL answered the anonymous
request with an application denial/login redirect **and** the session request to the
same URL returned ``APP_OK``. A WAF 403 is not enforcement; blocked runs report
``BLOCKED``/``INCONCLUSIVE`` instead of PASSED or a false finding.
"""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.core.response_classifier import (
    ResponseClass,
    classify_pair,
    is_blocking,
    proves_enforcement,
    samples_to_json,
    skip_reason_for,
)
from attestra.automated_vapt.testing._http import absolute, login, request_pair
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
    samples = []
    any_auth_ok = False
    any_unauth_blocked = False
    any_infra_blocked = False
    any_unauth_open = False
    excessive_keys: list[str] = []
    users_status = None
    unauth_status = None
    for url in urls:
        unauth = request_plain(client, "GET", url)
        authed = request_auth(client, "GET", url, auth, base_url)
        u_status = int(unauth.status or 0)
        a_status = int(authed.status or 0)
        u_cls = classify_pair(unauth)
        a_cls = classify_pair(authed, authed=True)
        samples.extend([u_cls, a_cls])
        if unauth_status is None:
            unauth_status = u_status
        if users_status is None:
            users_status = a_status
        auth_ok = a_cls.cls is ResponseClass.APP_OK
        if auth_ok:
            any_auth_ok = True
        # FND-04: denial/redirect class AND authed APP_OK on the same URL.
        if proves_enforcement(u_cls, a_cls):
            any_unauth_blocked = True
        if is_blocking(u_cls) or is_blocking(a_cls):
            any_infra_blocked = True
        open_unauth = u_status == 200 and u_cls.cls is ResponseClass.APP_OK and (
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
                "unauth_class": u_cls.cls.value,
                "auth_class": a_cls.cls.value,
                "secret_key_names": keys,
            }
        )
    if not any_auth_ok:
        if any_infra_blocked or any(c.cls is ResponseClass.AUTH_EXPIRED for c in samples):
            return {
                "test_id": "T07",
                "category": "disclosure",
                "status_hint": "BLOCKED",
                "skip_reason": skip_reason_for(samples),
                "observations": {
                    "mode": "engagement_session",
                    "missing_auth_enforced": False,
                    "infrastructure_blocked": any_infra_blocked,
                    "probes": rows,
                    "detail": "session GETs answered by WAF/challenge/rate limit or the session expired",
                },
                "finding_candidate": False,
                "evidence_hints": [],
                "validity_samples": samples_to_json(samples),
            }
        out = skip_result(
            "T07",
            "disclosure",
            SKIP_AUTH_REQUESTS_FAILED,
            "authenticated GETs did not succeed with the engagement session; cannot assess API exposure",
        )
        out["validity_samples"] = samples_to_json(samples)
        return out
    # Auth enforcement counts only when unauth is denied *and* the session is accepted.
    missing_auth_enforced = any_unauth_blocked and not any_unauth_open
    excessive = bool(excessive_keys)
    finding_candidate = any_unauth_open or excessive
    result: dict[str, Any] = {
        "test_id": "T07",
        "category": "disclosure",
        "observations": {
            "mode": "engagement_session",
            "unauth_project_status": unauth_status,
            "missing_auth_enforced": missing_auth_enforced,
            "users_status": users_status,
            "excessive_data_exposure": excessive,
            "secret_key_names": excessive_keys,
            "infrastructure_blocked": any_infra_blocked,
            "probes": rows,
        },
        "finding_candidate": finding_candidate,
        "evidence_pairs": evidence,
        "evidence_hints": [f"GET {u} unauth vs session" for u in urls],
        "validity_samples": samples_to_json(samples),
    }
    if not finding_candidate and not missing_auth_enforced:
        # Nothing proved enforcement (WAF 403 / 404 / non-login redirects): never PASS.
        result["status_hint"] = "BLOCKED" if any_infra_blocked else "INCONCLUSIVE"
        result["skip_reason"] = skip_reason_for(samples) if any_infra_blocked else "enforcement_not_proven"
    return result


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
    project_url = absolute(base_url, "/api/projects/proj-a")
    unauth_pair = request_pair(client, "GET", project_url)
    unauth_status = int(unauth_pair.status or 0)
    u_cls = classify_pair(unauth_pair)

    login(client, base_url, "account_a", "account-a-pass")
    authed_pair = request_pair(client, "GET", project_url)
    a_cls = classify_pair(authed_pair, authed=True)
    users_pair = request_pair(client, "GET", absolute(base_url, "/api/users"))
    users_status = int(users_pair.status or 0)
    users_cls = classify_pair(users_pair, authed=True)
    samples = [u_cls, a_cls, users_cls]
    try:
        import json as _json

        users_body = _json.loads(users_pair.response_body) if users_pair.response_body else None
    except Exception:
        users_body = None
    # FND-04: denial/redirect AND authenticated APP_OK on the same URL.
    missing_auth_enforced = proves_enforcement(u_cls, a_cls)
    unauth_open = u_cls.cls is ResponseClass.APP_OK
    excessive = False
    if isinstance(users_body, dict):
        rows = users_body.get("users") or []
        if any(isinstance(u, dict) and "password" in u for u in rows):
            excessive = True
        if "project_tokens" in users_body:
            excessive = True

    infra_blocked = any(is_blocking(c) for c in samples)
    finding_candidate = unauth_open or excessive
    result: dict[str, Any] = {
        "test_id": "T07",
        "category": "disclosure",
        "observations": {
            "unauth_project_status": unauth_status,
            "unauth_class": u_cls.cls.value,
            "missing_auth_enforced": missing_auth_enforced,
            "users_status": users_status,
            "excessive_data_exposure": excessive,
            "infrastructure_blocked": infra_blocked,
        },
        "finding_candidate": finding_candidate,
        "evidence_hints": ["GET /api/projects/proj-a unauthenticated", "GET /api/users authenticated"],
        "validity_samples": samples_to_json(samples),
    }
    if not finding_candidate and not missing_auth_enforced:
        result["status_hint"] = "BLOCKED" if infra_blocked else "INCONCLUSIVE"
        result["skip_reason"] = skip_reason_for(samples) if infra_blocked else "enforcement_not_proven"
    return result
