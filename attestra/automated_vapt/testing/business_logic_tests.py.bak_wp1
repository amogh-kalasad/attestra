"""Business-logic catalogue case (BIZ): owner access + safe order/replay sanity.

Read-only GETs only. Expands beyond a single owner GET to confirm the caller's
own object succeeds and a foreign object is denied (or flagged when exposed).
"""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, clear_cookies, login, request_json, request_pair
from attestra.automated_vapt.testing._session import (
    SKIP_NO_AUTH_SESSION,
    is_substantive_json,
    probe_urls,
    ready_auth,
    request_auth,
    resolve_mode,
    scrub_pair,
    skip_result,
)

# @lat: [[architecture#Elite automated security testing#Authz test modules]]

SKIP_LOGIN_FAILED = "biz_login_failed"


def _login_ok(client, base_url: str, user: str, password: str) -> bool:
    clear_cookies(client)
    try:
        code = login(client, base_url, user, password)
    except Exception:
        return False
    return int(code or 0) in (200, 302, 303)


def _run_with_session(client, base_url: str, auth: Any, **kwargs) -> dict[str, Any]:
    """Confirm the engagement session can read in-scope resources (read-only)."""
    urls = probe_urls(base_url, kwargs, api=True, limit=6)
    if not urls:
        urls = probe_urls(base_url, kwargs, api=False, limit=6)
    secondary = ready_auth(kwargs, "_secondary_session_auth")
    evidence: list[Any] = []
    rows: list[dict[str, Any]] = []
    owner_ok = False
    owner_status = None
    foreign_exposed = False
    foreign_status = None
    for url in urls:
        pair = request_auth(client, "GET", url, auth, base_url)
        status = int(pair.status or 0)
        if owner_status is None:
            owner_status = status
        if status == 200:
            owner_ok = True
        rows.append({"url": url, "primary_status": status})
        if secondary is not None:
            other = request_auth(client, "GET", url, secondary, base_url)
            ostatus = int(other.status or 0)
            foreign_status = ostatus if foreign_status is None else foreign_status
            same = (
                is_substantive_json(status, pair.response_body)
                and is_substantive_json(ostatus, other.response_body)
                and (pair.response_body or "").strip() == (other.response_body or "").strip()
            )
            rows[-1]["secondary_status"] = ostatus
            rows[-1]["same_body"] = same
            if same:
                foreign_exposed = True
                evidence.append(scrub_pair(other, auth, secondary))
    if not owner_ok:
        # Session was ready but no resource accepted it — report as not-ok, not a skip
        # (unlike T03 which cannot assess enforcement). BIZ is "owner access works".
        finding = True
    else:
        finding = foreign_exposed
    return {
        "test_id": "BIZ",
        "category": "authorization",
        "observations": {
            "mode": "engagement_session",
            "owner_access_ok": owner_ok,
            "owner_status": owner_status,
            "foreign_status": foreign_status,
            "foreign_exposed": foreign_exposed,
            "probes": rows,
        },
        "finding_candidate": finding,
        "evidence_pairs": evidence,
        "evidence_hints": [f"GET {u} with engagement session" for u in urls],
    }


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    mode, auth = resolve_mode(client, kwargs)
    if mode == "engagement":
        return _run_with_session(client, base_url, auth, **kwargs)
    if mode == "skip":
        return skip_result(
            "BIZ",
            "authorization",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped lab account_a business-logic probes",
        )

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
