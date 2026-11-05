"""Horizontal/vertical privilege helpers for Elite automated security testing."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, clear_cookies, login, request_pair

# @lat: [[architecture#Elite automated security testing#Authz test modules]]


def probe_vertical_privilege(client, base_url: str) -> dict[str, Any]:
    """Member must not reach admin UI or admin-only user directory (vertical)."""
    clear_cookies(client)
    login(client, base_url, "account_a", "account-a-pass")
    admin = client.get(absolute(base_url, "/admin"), follow_redirects=False)
    users = client.get(absolute(base_url, "/api/users"), follow_redirects=False)
    admin_status = int(admin.status_code)
    users_status = int(users.status_code)
    finding_candidate = admin_status == 200 or users_status == 200
    return {
        "kind": "vertical",
        "member_admin_status": admin_status,
        "member_users_status": users_status,
        "finding_candidate": finding_candidate,
    }


def probe_horizontal_privilege(client, base_url: str) -> dict[str, Any]:
    """Account A must not read Account B's object (horizontal / object-level).

    Complements [[attestra/automated_vapt/testing/idor_bola_tests.py]]; lighter probe
    used when only a privilege signal is needed.
    """
    clear_cookies(client)
    login(client, base_url, "account_a", "account-a-pass")
    pair = request_pair(client, "GET", absolute(base_url, "/api/projects/proj-b"))
    status = int(pair.status or 0)
    body: Any = None
    try:
        import json

        body = json.loads(pair.response_body) if pair.response_body else None
    except Exception:
        body = None
    exposed = False
    if isinstance(body, dict):
        note = str(body.get("secret_note") or "")
        token = str(body.get("api_token") or "")
        exposed = ("SENSITIVE" in note) or token.startswith("tok_")
    finding_candidate = status == 200 and (exposed or isinstance(body, dict))
    return {
        "kind": "horizontal",
        "cross_object_status": status,
        "exposed_secrets": exposed,
        "finding_candidate": finding_candidate,
        "evidence_pairs": [pair] if finding_candidate else [],
    }


def run(client, base_url: str, **_kwargs) -> dict[str, Any]:
    """Run vertical then horizontal privilege probes; never marks checklist passed."""
    vertical = probe_vertical_privilege(client, base_url)
    horizontal = probe_horizontal_privilege(client, base_url)
    evidence_pairs = list(horizontal.get("evidence_pairs") or [])
    finding_candidate = bool(vertical.get("finding_candidate")) or bool(
        horizontal.get("finding_candidate")
    )
    return {
        "test_id": "T05-PRIV",
        "category": "authorization",
        "observations": {
            "vertical": {
                k: v for k, v in vertical.items() if k != "evidence_pairs"
            },
            "horizontal": {
                k: v for k, v in horizontal.items() if k != "evidence_pairs"
            },
            # Flat keys retained for orchestrator / callers that expect them.
            "member_admin_status": vertical.get("member_admin_status"),
            "member_users_status": vertical.get("member_users_status"),
            "cross_object_status": horizontal.get("cross_object_status"),
        },
        "finding_candidate": finding_candidate,
        "evidence_pairs": evidence_pairs,
        "evidence_hints": [
            "GET /admin as member",
            "GET /api/users as member",
            "GET /api/projects/proj-b as account_a",
        ],
    }


# Explicit exports for authorization coverage wiring.
__all__ = [
    "probe_horizontal_privilege",
    "probe_vertical_privilege",
    "run",
]
