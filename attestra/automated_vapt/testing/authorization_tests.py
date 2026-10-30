"""Role-enforcement checks for Elite automated security testing."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, login

# @lat: [[architecture#Elite automated security testing#Authz test modules]]


def run(client, base_url: str, **_kwargs) -> dict[str, Any]:
    login(client, base_url, "account_a", "account-a-pass")
    member_admin = client.get(absolute(base_url, "/admin"), follow_redirects=False)
    member_status = int(member_admin.status_code)

    login(client, base_url, "admin", "admin-pass")
    admin_admin = client.get(absolute(base_url, "/admin"), follow_redirects=False)
    admin_status = int(admin_admin.status_code)

    role_enforced = member_status in (403, 401) and admin_status == 200
    finding_candidate = member_status == 200
    return {
        "test_id": "T05",
        "category": "authorization",
        "observations": {
            "member_admin_status": member_status,
            "admin_admin_status": admin_status,
            "role_enforced": role_enforced,
        },
        "finding_candidate": finding_candidate,
        "evidence_hints": ["GET /admin as member", "GET /admin as admin"],
    }
