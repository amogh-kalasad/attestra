"""Owner-access sanity check for Elite automated security testing."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, login, request_json

# @lat: [[architecture#Elite automated security testing#Authz test modules]]


def run(client, base_url: str, **_kwargs) -> dict[str, Any]:
    login(client, base_url, "account_a", "account-a-pass")
    status, body, _ = request_json(client, "GET", absolute(base_url, "/api/projects/proj-a"))
    ok = status == 200 and isinstance(body, dict) and body.get("id") == "proj-a"
    return {
        "test_id": "BIZ",
        "category": "authorization",
        "observations": {"owner_access_ok": ok, "status": status},
        "finding_candidate": not ok,
        "evidence_hints": ["GET /api/projects/proj-a as owner"],
    }
