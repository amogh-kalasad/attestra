"""Role-enforcement checks for Elite automated security testing."""

from __future__ import annotations

from typing import Any

from attestra.automated_vapt.testing._http import absolute, login, request_pair
from attestra.automated_vapt.testing._session import (
    SKIP_NO_AUTH_SESSION,
    SKIP_NO_SECOND_ROLE,
    looks_privileged_url,
    probe_urls,
    ready_auth,
    request_auth,
    resolve_mode,
    scrub_pair,
    skip_result,
)
from attestra.automated_vapt.testing.privilege_escalation_tests import (
    probe_horizontal_privilege,
    probe_vertical_privilege,
)

# @lat: [[architecture#Elite automated security testing#Authz test modules]]

# Horizontal / vertical helpers live in privilege_escalation_tests; re-exported here
# so authorization callers can import from one module.
__all__ = ["probe_horizontal_privilege", "probe_vertical_privilege", "run"]


def _run_with_session(client, base_url: str, auth: Any, **kwargs) -> dict[str, Any]:
    """Compare capture URLs as primary vs secondary engagement profiles."""
    secondary = ready_auth(kwargs, "_secondary_session_auth")
    if secondary is None:
        return skip_result(
            "T05",
            "authorization",
            SKIP_NO_SECOND_ROLE,
            "role-enforcement on an engagement target needs a second-role login profile",
        )
    urls = probe_urls(base_url, kwargs, api=False, limit=8)
    evidence: list[Any] = []
    rows: list[dict[str, Any]] = []
    status_diff = False
    both_priv = False
    member_open = None
    admin_open = None
    for url in urls:
        pair_a = request_auth(client, "GET", url, auth, base_url)
        pair_b = request_auth(client, "GET", url, secondary, base_url)
        a_status = int(pair_a.status or 0)
        b_status = int(pair_b.status or 0)
        differs = a_status != b_status
        if differs:
            status_diff = True
        priv = looks_privileged_url(url)
        if priv and a_status == 200 and b_status == 200:
            both_priv = True
            evidence.append(scrub_pair(pair_a, auth, secondary))
            evidence.append(scrub_pair(pair_b, auth, secondary))
        if priv:
            member_open = member_open if member_open is not None else a_status
            admin_open = admin_open if admin_open is not None else b_status
        rows.append({"url": url, "primary_status": a_status, "secondary_status": b_status, "privileged": priv})
    # Finding only when a privileged-looking path is 200 for both roles (no split).
    finding_candidate = both_priv and not status_diff
    return {
        "test_id": "T05",
        "category": "authorization",
        "observations": {
            "mode": "engagement_session",
            "member_admin_status": member_open if both_priv else (403 if status_diff else member_open),
            "admin_admin_status": admin_open if admin_open is not None else (200 if status_diff else None),
            "role_enforced": status_diff,
            "probes": rows,
        },
        "finding_candidate": finding_candidate,
        "evidence_pairs": evidence,
        "evidence_hints": [f"GET {u} as primary vs secondary profile" for u in urls],
    }


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Server-side role check (member vs admin on /admin)."""
    mode, auth = resolve_mode(client, kwargs)
    if mode == "engagement":
        return _run_with_session(client, base_url, auth, **kwargs)
    if mode == "skip":
        return skip_result(
            "T05",
            "authorization",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped lab /admin role probes",
        )

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
