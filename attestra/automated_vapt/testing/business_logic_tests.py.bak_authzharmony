"""Business-logic catalogue case (BIZ): owner access + safe order/replay sanity.

Read-only GETs only. Expands beyond a single owner GET to confirm the caller's
own object succeeds and a foreign object is denied (or flagged when exposed).
"""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, clear_cookies, login, request_json, request_pair

# @lat: [[architecture#Elite automated security testing#Authz test modules]]

SKIP_LOGIN_FAILED = "biz_login_failed"


def _login_ok(client, base_url: str, user: str, password: str) -> bool:
    clear_cookies(client)
    try:
        code = login(client, base_url, user, password)
    except Exception:
        return False
    return int(code or 0) in (200, 302, 303)


def run(client, base_url: str, **_kwargs) -> dict[str, Any]:
    if not _login_ok(client, base_url, "account_a", "account-a-pass"):
        return {
            "test_id": "BIZ",
            "category": "authorization",
            "status_hint": "SKIPPED",
            "skip_reason": SKIP_LOGIN_FAILED,
            "observations": {"detail": "mock account_a login failed; engagement profiles not used for BIZ yet"},
            "finding_candidate": False,
            "evidence_hints": [],
        }

    own_status, own_body, _ = request_json(client, "GET", absolute(base_url, "/api/projects/proj-a"))
    owner_ok = own_status == 200 and isinstance(own_body, dict) and (
        own_body.get("id") == "proj-a" or own_body.get("projectId") == "proj-a"
    )

    # Safe order/replay: foreign object GET must not return the other owner's record.
    foreign_pair = request_pair(client, "GET", absolute(base_url, "/api/projects/proj-b"))
    foreign_status = int(foreign_pair.status or 0)
    foreign_body: Any = None
    try:
        import json

        foreign_body = json.loads(foreign_pair.response_body) if foreign_pair.response_body else None
    except Exception:
        foreign_body = None
    foreign_exposed = foreign_status == 200 and isinstance(foreign_body, dict) and (
        foreign_body.get("id") == "proj-b"
        or foreign_body.get("projectId") == "proj-b"
        or foreign_body.get("owner") == "account_b"
    )

    evidence = [foreign_pair] if foreign_exposed else []
    finding = (not owner_ok) or foreign_exposed
    return {
        "test_id": "BIZ",
        "category": "authorization",
        "observations": {
            "owner_access_ok": owner_ok,
            "owner_status": own_status,
            "foreign_status": foreign_status,
            "foreign_exposed": foreign_exposed,
        },
        "finding_candidate": finding,
        "evidence_pairs": evidence,
        "evidence_hints": [
            "GET /api/projects/proj-a as owner",
            "GET /api/projects/proj-b as owner (must deny)",
        ],
    }
