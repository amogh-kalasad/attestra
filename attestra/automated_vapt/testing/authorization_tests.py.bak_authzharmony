"""Role-enforcement checks for Elite automated security testing."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, login, request_pair
from attestra.automated_vapt.testing.privilege_escalation_tests import (
    probe_horizontal_privilege,
    probe_vertical_privilege,
)

# @lat: [[architecture#Elite automated security testing#Authz test modules]]

# Horizontal / vertical helpers live in privilege_escalation_tests; re-exported here
# so authorization callers can import from one module.
__all__ = ["probe_horizontal_privilege", "probe_vertical_privilege", "run"]


def run(client, base_url: str, **_kwargs) -> dict[str, Any]:
    """Server-side role check (member vs admin on /admin)."""
    login(client, base_url, "account_a", "account-a-pass")
    member_pair = request_pair(
        client, "GET", absolute(base_url, "/admin"), follow_redirects=False
    )
    member_status = int(member_pair.status or 0)

    login(client, base_url, "admin", "admin-pass")
    admin_pair = request_pair(
        client, "GET", absolute(base_url, "/admin"), follow_redirects=False
    )
    admin_status = int(admin_pair.status or 0)

    role_enforced = member_status in (403, 401) and admin_status == 200
    finding_candidate = member_status == 200
    evidence_pairs = [member_pair] if finding_candidate else []
    return {
        "test_id": "T05",
        "category": "authorization",
        "observations": {
            "member_admin_status": member_status,
            "admin_admin_status": admin_status,
            "role_enforced": role_enforced,
        },
        "finding_candidate": finding_candidate,
        "evidence_pairs": evidence_pairs,
        "evidence_hints": ["GET /admin as member", "GET /admin as admin"],
    }
