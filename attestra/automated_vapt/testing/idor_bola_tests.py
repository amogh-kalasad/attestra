"""Controlled two-account BOLA/IDOR checks for Elite automated security testing."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, login, request_json, request_pair

# @lat: [[architecture#Elite automated security testing#Authz test modules]]


def run(client, base_url: str, **_kwargs) -> dict[str, Any]:
    """Account A owns proj-a; Account B owns proj-b. Cross-owner access must fail."""
    login(client, base_url, "account_a", "account-a-pass")
    own_status, own_body, _ = request_json(client, "GET", absolute(base_url, "/api/projects/proj-a"))
    cross_url = absolute(base_url, "/api/projects/proj-b")
    cross_pair = request_pair(client, "GET", cross_url)
    cross_status = int(cross_pair.status or 0)
    cross_text = cross_pair.response_body
    cross_body: Any = None
    try:
        import json

        cross_body = json.loads(cross_text) if cross_text else None
    except Exception:
        cross_body = None

    login(client, base_url, "account_b", "account-b-pass")
    b_own_status, b_own_body, _ = request_json(client, "GET", absolute(base_url, "/api/projects/proj-b"))

    exposed_secrets = False
    if isinstance(cross_body, dict):
        note = str(cross_body.get("secret_note") or "")
        token = str(cross_body.get("api_token") or "")
        exposed_secrets = ("SENSITIVE" in note) or token.startswith("tok_")
    elif cross_status == 200 and ("SENSITIVE" in cross_text or "tok_" in cross_text):
        exposed_secrets = True

    authorized_ok = own_status == 200 and b_own_status == 200
    unauthorized_blocked = cross_status in (401, 403, 404)
    finding_candidate = cross_status == 200 and (exposed_secrets or isinstance(cross_body, dict))

    evidence_pairs = []
    if finding_candidate:
        evidence_pairs.append(cross_pair)

    return {
        "test_id": "T04",
        "category": "authorization",
        "observations": {
            "account_a_proj_a_status": own_status,
            "account_a_proj_b_status": cross_status,
            "account_b_proj_b_status": b_own_status,
            "authorized_ok": authorized_ok,
            "unauthorized_blocked": unauthorized_blocked,
            "exposed_secrets": exposed_secrets,
            "cross_body_keys": sorted(cross_body.keys()) if isinstance(cross_body, dict) else [],
        },
        "finding_candidate": finding_candidate,
        "evidence_pairs": evidence_pairs,
        "evidence_hints": [
            "GET /api/projects/proj-a as account_a",
            "GET /api/projects/proj-b as account_a",
            "GET /api/projects/proj-b as account_b",
        ],
    }
