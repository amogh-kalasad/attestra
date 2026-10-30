"""Authentication enforcement checks for Elite automated security testing."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, login

# @lat: [[architecture#Elite automated security testing#Authz test modules]]


def run(client, base_url: str, **_kwargs) -> dict[str, Any]:
    """Probe auth requirements, invalid credentials, and settings gate."""
    unauth = client.get(absolute(base_url, "/app"), follow_redirects=False)
    unauth_status = int(unauth.status_code)
    auth_required_ok = unauth_status in (302, 401, 403)

    bad = login(client, base_url, "viewer", "wrong-password")
    invalid_creds_rejected = bad in (401, 403)

    settings = client.get(absolute(base_url, "/app/settings"), follow_redirects=False)
    settings_status = int(settings.status_code)
    # Finding candidate when settings are reachable without auth.
    settings_open = settings_status == 200

    good = login(client, base_url, "viewer", "viewer-pass")
    authed_app = client.get(absolute(base_url, "/app"), follow_redirects=False)
    login_works = good in (303, 302, 200) and int(authed_app.status_code) == 200

    finding_candidate = (not auth_required_ok) or settings_open or (not invalid_creds_rejected)
    return {
        "test_id": "T03",
        "category": "authentication",
        "observations": {
            "unauth_app_status": unauth_status,
            "auth_required_ok": auth_required_ok,
            "invalid_creds_status": bad,
            "invalid_creds_rejected": invalid_creds_rejected,
            "settings_unauth_status": settings_status,
            "settings_open_without_auth": settings_open,
            "login_works": login_works,
        },
        "finding_candidate": finding_candidate,
        "evidence_hints": ["GET /app", "POST /login invalid", "GET /app/settings"],
    }
