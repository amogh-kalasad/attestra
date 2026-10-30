"""Horizontal/vertical privilege checks for Elite automated security testing."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, login

# @lat: [[architecture#Elite automated security testing#Authz test modules]]


def run(client, base_url: str, **_kwargs) -> dict[str, Any]:
    login(client, base_url, "account_a", "account-a-pass")
    admin = client.get(absolute(base_url, "/admin"), follow_redirects=False)
    users = client.get(absolute(base_url, "/api/users"), follow_redirects=False)
    admin_status = int(admin.status_code)
    users_status = int(users.status_code)
    finding_candidate = admin_status == 200 or users_status == 200
    return {
        "test_id": "T05-PRIV",
        "category": "authorization",
        "observations": {
            "member_admin_status": admin_status,
            "member_users_status": users_status,
        },
        "finding_candidate": finding_candidate,
        "evidence_hints": ["GET /admin as member", "GET /api/users as member"],
    }
