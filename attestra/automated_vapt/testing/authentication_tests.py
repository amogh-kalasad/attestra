"""Authentication enforcement checks for Elite automated security testing.

FND-04: a 401/403 on its own never proves enforcement. "Auth enforced" needs an
application denial or same-site login redirect (``APP_AUTH_DENIED`` /
``AUTH_REDIRECT`` from [[attestra/automated_vapt/core/response_classifier.py]]) **and**
an authenticated ``APP_OK`` on the same URL. WAF blocks, challenges and rate limits
make the case ``BLOCKED`` (never PASSED, never a finding by themselves).
"""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.core.response_classifier import (
    ResponseClass,
    classify_httpx,
    classify_pair,
    is_blocking,
    is_security_control_evidence,
    proves_enforcement,
    samples_to_json,
    skip_reason_for,
)
from attestra.automated_vapt.testing._http import (
    absolute,
    clear_cookies,
    login,
    login_response,
)
from attestra.automated_vapt.testing._session import (
    SKIP_AUTH_REQUESTS_FAILED,
    SKIP_NO_AUTH_SESSION,
    is_substantive_json,
    probe_urls,
    request_auth,
    request_plain,
    resolve_mode,
    scrub_pair,
    skip_result,
)

# @lat: [[architecture#Elite automated security testing#Authz test modules]]


def _probe_account_enumeration(client, base_url: str) -> dict[str, Any]:
    """Differential login responses only — two probes, no spraying or resets.

    Compares unknown-username vs known-username with the same wrong password.
    A status or body-length/content difference is an enumeration signal.
    """
    unknown = login_response(client, base_url, "no_such_user_attestra", "wrong-password")
    known = login_response(client, base_url, "viewer", "wrong-password")
    clear_cookies(client)

    u_status = int(unknown.status_code)
    k_status = int(known.status_code)
    u_body = getattr(unknown, "text", "") or ""
    k_body = getattr(known, "text", "") or ""
    status_differs = u_status != k_status
    length_differs = abs(len(u_body) - len(k_body)) >= 32
    bodies_differ = u_body.strip() != k_body.strip()
    combined = (u_body + "\n" + k_body).lower()
    # Soft content-only diffs count only when the body names user/account existence.
    soft_user_hint = bodies_differ and (
        "unknown user" in combined
        or "user not found" in combined
        or "no such user" in combined
        or "does not exist" in combined
        or "invalid username" in combined
        or "account not found" in combined
    )
    signal = status_differs or length_differs or soft_user_hint
    return {
        "unknown_user_status": u_status,
        "known_user_wrong_pw_status": k_status,
        "unknown_body_len": len(u_body),
        "known_wrong_pw_body_len": len(k_body),
        "status_differs": status_differs,
        "length_differs": length_differs,
        "content_differs": bodies_differ,
        "enumeration_signal": bool(signal),
        "invalid_creds_rejected": k_status in (401, 403),
    }


def _probe_auth_state(client, base_url: str) -> dict[str, Any]:
    """Confirm protected routes reject access after session cookies are cleared."""
    good = login(client, base_url, "viewer", "viewer-pass")
    authed = client.get(absolute(base_url, "/app"), follow_redirects=False)
    authed_status = int(authed.status_code)
    clear_cookies(client)
    after = client.get(absolute(base_url, "/app"), follow_redirects=False)
    after_status = int(after.status_code)
    authed_cls = classify_httpx(authed)
    after_cls = classify_httpx(after)
    state_cleared = is_security_control_evidence(after_cls)
    return {
        "login_status": good,
        "authed_app_status": authed_status,
        "login_works": good in (303, 302, 200) and authed_cls.cls is ResponseClass.APP_OK,
        "post_clear_app_status": after_status,
        "auth_state_cleared": state_cleared,
        "_samples": [authed_cls, after_cls],
    }


def _run_with_session(client, base_url: str, auth: Any, **kwargs) -> dict[str, Any]:
    """Compare unauthenticated vs engagement-session GETs on capture/target URLs."""
    urls = probe_urls(base_url, kwargs, api=False, limit=6)
    evidence: list[Any] = []
    rows: list[dict[str, Any]] = []
    samples = []
    any_auth_ok = False
    any_unauth_open = False
    any_enforced = False
    any_blocked = False
    for url in urls:
        unauth = request_plain(client, "GET", url)
        authed = request_auth(client, "GET", url, auth, base_url)
        u_status = int(unauth.status or 0)
        a_status = int(authed.status or 0)
        u_cls = classify_pair(unauth)
        a_cls = classify_pair(authed, authed=True)
        samples.extend([u_cls, a_cls])
        auth_ok = a_cls.cls is ResponseClass.APP_OK
        enforced = proves_enforcement(u_cls, a_cls)
        blocked_row = is_blocking(u_cls) or is_blocking(a_cls)
        # Same authenticated content without a session is a bypass. A 200 login-page
        # HTML that differs from the authed body is not.
        same_body = (unauth.response_body or "") == (authed.response_body or "") and len(
            unauth.response_body or ""
        ) >= 32
        open_unauth = u_cls.cls is ResponseClass.APP_OK and u_status == 200 and (
            is_substantive_json(u_status, unauth.response_body)
            or (auth_ok and same_body)
        )
        if auth_ok:
            any_auth_ok = True
        if enforced:
            any_enforced = True
        if blocked_row:
            any_blocked = True
        if open_unauth:
            any_unauth_open = True
            evidence.append(scrub_pair(unauth, auth))
        rows.append(
            {
                "url": url,
                "unauth_status": u_status,
                "auth_status": a_status,
                "unauth_class": u_cls.cls.value,
                "auth_class": a_cls.cls.value,
                # Kept for report compatibility: True only for an application denial.
                "unauth_blocked": is_security_control_evidence(u_cls),
                "enforcement_proven": enforced,
                "unauth_open": open_unauth,
            }
        )
    finding = any_unauth_open
    auth_required_ok = (not any_unauth_open) and any_enforced
    base_obs = {
        "mode": "engagement_session",
        "unauth_app_status": rows[0]["unauth_status"] if rows else None,
        "auth_required_ok": auth_required_ok,
        "invalid_creds_rejected": True,
        "settings_unauth_status": next((r["unauth_status"] for r in rows if r["unauth_open"]), None),
        "settings_open_without_auth": any_unauth_open,
        "login_works": any_auth_ok,
        "authorized_ok": any_auth_ok,
        "unauthorized_blocked": any_enforced,
        "infrastructure_blocked": any_blocked,
        "account_enumeration": {
            "skipped": True,
            "reason": "engagement profile path does not probe /login differentials",
        },
        "probes": rows,
    }
    if not any_auth_ok and not finding:
        if any_blocked or any(s.cls is ResponseClass.AUTH_EXPIRED for s in samples):
            return {
                "test_id": "T03",
                "category": "authentication",
                "status_hint": "BLOCKED",
                "skip_reason": skip_reason_for(samples),
                "observations": {**base_obs, "detail": "authenticated GETs were answered by WAF/challenge/rate limit or the session expired"},
                "finding_candidate": False,
                "evidence_hints": [],
                "validity_samples": samples_to_json(samples),
            }
        out = skip_result(
            "T03",
            "authentication",
            SKIP_AUTH_REQUESTS_FAILED,
            "authenticated GETs did not succeed with the engagement session; cannot assess auth enforcement",
        )
        out["validity_samples"] = samples_to_json(samples)
        return out
    result: dict[str, Any] = {
        "test_id": "T03",
        "category": "authentication",
        "observations": base_obs,
        "finding_candidate": finding,
        "evidence_pairs": evidence,
        "evidence_hints": [f"GET {u} unauth vs session" for u in urls],
        "validity_samples": samples_to_json(samples),
    }
    if not finding and not auth_required_ok:
        # No URL proved enforcement (WAF 403s, 404s, non-login redirects): never PASS.
        result["status_hint"] = "BLOCKED" if any_blocked else "INCONCLUSIVE"
        result["skip_reason"] = skip_reason_for(samples) if any_blocked else "enforcement_not_proven"
    return result


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Probe auth gates, enumeration differentials, invalid creds, and auth state."""
    mode, auth = resolve_mode(client, kwargs)
    if mode == "engagement":
        return _run_with_session(client, base_url, auth, **kwargs)
    if mode == "skip":
        return skip_result(
            "T03",
            "authentication",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped lab /login probes",
        )

    clear_cookies(client)
    unauth = client.get(absolute(base_url, "/app"), follow_redirects=False)
    unauth_status = int(unauth.status_code)
    unauth_cls = classify_httpx(unauth)

    enum_obs = _probe_account_enumeration(client, base_url)
    invalid_creds_rejected = bool(enum_obs.get("invalid_creds_rejected"))

    settings = client.get(absolute(base_url, "/app/settings"), follow_redirects=False)
    settings_status = int(settings.status_code)
    settings_cls = classify_httpx(settings)
    # Finding candidate when settings are reachable without auth (application content).
    settings_open = settings_status == 200 and settings_cls.cls is ResponseClass.APP_OK

    state_obs = _probe_auth_state(client, base_url)
    state_samples = state_obs.pop("_samples", [])
    samples = [unauth_cls, settings_cls, *state_samples]
    # FND-04: denial/login-redirect AND authenticated APP_OK on the same /app URL.
    authed_app_ok = bool(state_obs.get("login_works"))
    auth_required_ok = is_security_control_evidence(unauth_cls) and authed_app_ok
    infra_blocked = any(is_blocking(c) for c in samples)

    if infra_blocked and not settings_open:
        return {
            "test_id": "T03",
            "category": "authentication",
            "status_hint": "BLOCKED",
            "skip_reason": skip_reason_for(samples),
            "observations": {
                "unauth_app_status": unauth_status,
                "unauth_class": unauth_cls.cls.value,
                "auth_required_ok": False,
                "infrastructure_blocked": True,
                "detail": "responses came from a WAF/challenge/rate limit; auth enforcement not assessed",
            },
            "finding_candidate": False,
            "evidence_hints": ["GET /app", "GET /app/settings"],
            "validity_samples": samples_to_json(samples),
        }

    finding_candidate = (
        (unauth_cls.cls is ResponseClass.APP_OK)
        or settings_open
        or (not invalid_creds_rejected)
        or bool(enum_obs.get("enumeration_signal"))
        or (authed_app_ok and not state_obs.get("auth_state_cleared"))
    )
    result = {
        "test_id": "T03",
        "category": "authentication",
        "observations": {
            "unauth_app_status": unauth_status,
            "unauth_class": unauth_cls.cls.value,
            "auth_required_ok": auth_required_ok,
            "invalid_creds_status": enum_obs.get("known_user_wrong_pw_status"),
            "invalid_creds_rejected": invalid_creds_rejected,
            "settings_unauth_status": settings_status,
            "settings_open_without_auth": settings_open,
            "login_works": state_obs.get("login_works"),
            "account_enumeration": enum_obs,
            "auth_state": state_obs,
        },
        "finding_candidate": finding_candidate,
        "evidence_hints": [
            "GET /app",
            "POST /login unknown vs known (wrong password)",
            "GET /app/settings",
            "GET /app after cookie clear",
        ],
        "validity_samples": samples_to_json(samples),
    }
    if not finding_candidate and not auth_required_ok:
        result["status_hint"] = "INCONCLUSIVE"
        result["skip_reason"] = "enforcement_not_proven"
    return result
