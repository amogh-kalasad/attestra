"""Authentication enforcement checks for Elite automated security testing."""

from __future__ import annotations

from typing import Any

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
    state_cleared = after_status in (302, 401, 403)
    return {
        "login_status": good,
        "authed_app_status": authed_status,
        "login_works": good in (303, 302, 200) and authed_status == 200,
        "post_clear_app_status": after_status,
        "auth_state_cleared": state_cleared,
    }


def _run_with_session(client, base_url: str, auth: Any, **kwargs) -> dict[str, Any]:
    """Compare unauthenticated vs engagement-session GETs on capture/target URLs."""
    urls = probe_urls(base_url, kwargs, api=False, limit=6)
    evidence: list[Any] = []
    rows: list[dict[str, Any]] = []
    any_auth_ok = False
    any_unauth_open = False
    any_unauth_blocked = False
    for url in urls:
        unauth = request_plain(client, "GET", url)
        authed = request_auth(client, "GET", url, auth, base_url)
        u_status = int(unauth.status or 0)
        a_status = int(authed.status or 0)
        blocked = u_status in (301, 302, 303, 307, 308, 401, 403)
        auth_ok = a_status == 200
        # Same authenticated content without a session is a bypass. A 200 login-page
        # HTML that differs from the authed body is not.
        same_body = (unauth.response_body or "") == (authed.response_body or "") and len(
            unauth.response_body or ""
        ) >= 32
        open_unauth = u_status == 200 and (
            is_substantive_json(u_status, unauth.response_body)
            or (auth_ok and same_body)
        )
        if auth_ok:
            any_auth_ok = True
        if blocked:
            any_unauth_blocked = True
        if open_unauth:
            any_unauth_open = True
            evidence.append(scrub_pair(unauth, auth))
        rows.append(
            {
                "url": url,
                "unauth_status": u_status,
                "auth_status": a_status,
                "unauth_blocked": blocked,
                "unauth_open": open_unauth,
            }
        )
    if not any_auth_ok:
        return skip_result(
            "T03",
            "authentication",
            SKIP_AUTH_REQUESTS_FAILED,
            "authenticated GETs did not succeed with the engagement session; cannot assess auth enforcement",
        )
    finding = any_unauth_open
    return {
        "test_id": "T03",
        "category": "authentication",
        "observations": {
            "mode": "engagement_session",
            "unauth_app_status": rows[0]["unauth_status"] if rows else None,
            "auth_required_ok": (not any_unauth_open) and any_unauth_blocked,
            "invalid_creds_rejected": True,
            "settings_unauth_status": next((r["unauth_status"] for r in rows if r["unauth_open"]), None),
            "settings_open_without_auth": any_unauth_open,
            "login_works": any_auth_ok,
            "authorized_ok": any_auth_ok,
            "unauthorized_blocked": any_unauth_blocked,
            "account_enumeration": {
                "skipped": True,
                "reason": "engagement profile path does not probe /login differentials",
            },
            "probes": rows,
        },
        "finding_candidate": finding,
        "evidence_pairs": evidence,
        "evidence_hints": [f"GET {u} unauth vs session" for u in urls],
    }


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
    auth_required_ok = unauth_status in (302, 401, 403)

    enum_obs = _probe_account_enumeration(client, base_url)
    invalid_creds_rejected = bool(enum_obs.get("invalid_creds_rejected"))

    settings = client.get(absolute(base_url, "/app/settings"), follow_redirects=False)
    settings_status = int(settings.status_code)
    # Finding candidate when settings are reachable without auth.
    settings_open = settings_status == 200

    state_obs = _probe_auth_state(client, base_url)

    finding_candidate = (
        (not auth_required_ok)
        or settings_open
        or (not invalid_creds_rejected)
        or bool(enum_obs.get("enumeration_signal"))
        or (not state_obs.get("auth_state_cleared"))
    )
    return {
        "test_id": "T03",
        "category": "authentication",
        "observations": {
            "unauth_app_status": unauth_status,
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
    }
