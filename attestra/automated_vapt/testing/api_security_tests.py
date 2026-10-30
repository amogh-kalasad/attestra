"""Configurable API security probes for Elite automated security testing."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, login, request_json

# @lat: [[architecture#Elite automated security testing#Authz test modules]]


def run(client, base_url: str, **_kwargs) -> dict[str, Any]:
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
