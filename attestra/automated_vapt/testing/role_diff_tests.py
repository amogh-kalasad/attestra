"""Catalogue ROLEDIFF: read-only two-role comparison for automated VAPT.

Uses mock Account A/B on lab apps when present; otherwise SKIPPED with an explicit
reason when a second profile/session is unavailable. Never sends state-changing
probes (intrusive=False).
"""

from __future__ import annotations

from typing import Any

from attestra.auth_web.roles import RoleSnapshot, compare_roles
from attestra.automated_vapt.testing._http import absolute, clear_cookies, login, request_pair
from attestra.automated_vapt.testing._session import (
    SKIP_NO_AUTH_SESSION,
    SKIP_NO_SECOND_ROLE,
    probe_urls,
    ready_auth,
    request_auth,
    resolve_mode,
    skip_result,
)

# @lat: [[architecture#Remaining gaps plan (auth depth)]]

SKIP_LOGIN_FAILED = "role_login_failed"


def _snapshot(client, base_url: str, role: str, path: str) -> RoleSnapshot:
    url = absolute(base_url, path)
    pair = request_pair(client, "GET", url)
    markers: list[str] = []
    body = pair.response_body or ""
    if "proj-a" in body:
        markers.append("proj-a")
    if "proj-b" in body:
        markers.append("proj-b")
    if '"items"' in body or '"id"' in body:
        markers.append("json_list")
    return RoleSnapshot(
        role_name=role,
        url=url,
        status_code=int(pair.status or 0),
        final_url=url,
        body_markers=markers,
        visible_controls=list(markers),
    )


def _snapshot_auth(client, url: str, role: str, auth: Any, root: str) -> RoleSnapshot:
    pair = request_auth(client, "GET", url, auth, root)
    markers: list[str] = []
    body = pair.response_body or ""
    if "proj-a" in body:
        markers.append("proj-a")
    if "proj-b" in body:
        markers.append("proj-b")
    if '"items"' in body or '"id"' in body:
        markers.append("json_list")
    if int(pair.status or 0) == 200:
        markers.append("http_200")
    elif int(pair.status or 0) in (401, 403):
        markers.append("denied")
    return RoleSnapshot(
        role_name=role,
        url=url,
        status_code=int(pair.status or 0),
        final_url=url,
        body_markers=markers,
        visible_controls=list(markers),
    )


def _try_login(client, base_url: str, username: str, password: str) -> bool:
    clear_cookies(client)
    try:
        code = login(client, base_url, username, password)
    except Exception:
        return False
    # Lab apps redirect 303 on success; some targets return 200.
    return int(code or 0) in (200, 302, 303)


def _run_with_session(client, base_url: str, auth: Any, **kwargs) -> dict[str, Any]:
    secondary = ready_auth(kwargs, "_secondary_session_auth")
    if secondary is None:
        return skip_result(
            "ROLEDIFF",
            "authorization",
            SKIP_NO_SECOND_ROLE,
            "second role (secondary login profile) unavailable",
        )
    urls = probe_urls(base_url, kwargs, api=False, limit=8)
    snaps_a = [_snapshot_auth(client, u, "primary", auth, base_url) for u in urls]
    snaps_b = [_snapshot_auth(client, u, "secondary", secondary, base_url) for u in urls]
    diffs = compare_roles(snaps_a, snaps_b, intrusive=False) if snaps_a and snaps_b else []
    meaningful = [
        d
        for d in diffs
        if d.status_differs or d.redirect_differs or d.controls_only_in_a or d.controls_only_in_b
    ]
    # Cross-role list smell (lab markers) plus identical 200 on every URL is noted,
    # but finding_candidate requires a visible marker leak or identical privileged access
    # that compare_roles already called out. Keep conservative: no finding unless
    # lab-style proj-a/proj-b markers cross, or every URL is 200 for both with no diffs
    # *and* a denied marker is missing — actually don't flag "same role" as a finding.
    a_sees_b = any("proj-b" in (s.body_markers or []) for s in snaps_a)
    b_sees_a = any("proj-a" in (s.body_markers or []) for s in snaps_b)
    cross_list = bool(a_sees_b or b_sees_a)
    finding = cross_list
    return {
        "test_id": "ROLEDIFF",
        "category": "authorization",
        "observations": {
            "mode": "engagement_session",
            "diff_count": len(meaningful),
            "cross_role_list": cross_list,
            "account_a_ok": True,
            "account_b_ok": True,
            "notes": [n for d in meaningful for n in d.notes][:20],
        },
        "finding_candidate": finding,
        "evidence_hints": [f"role compare on {u}" for u in urls],
    }


def run(client, base_url: str, **kwargs) -> dict[str, Any]:
    """Compare account_a vs account_b (or secondary session) on shared read paths."""
    mode, auth = resolve_mode(client, kwargs)
    if mode == "engagement":
        return _run_with_session(client, base_url, auth, **kwargs)
    if mode == "skip":
        return skip_result(
            "ROLEDIFF",
            "authorization",
            SKIP_NO_AUTH_SESSION,
            "engagement login profile not ready; skipped lab account_a/account_b role compare",
        )

    paths = ("/api/projects", "/api/projects/proj-a", "/api/projects/proj-b")
    ctx = kwargs.get("ctx")
    secondary = None
    if ctx is not None:
        secondary = (getattr(ctx, "extra", {}) or {}).get("_secondary_session_auth")

    # Prefer lab mock accounts; fall back to secondary session headers only for status compare.
    a_ok = _try_login(client, base_url, "account_a", "account-a-pass")
    if not a_ok and secondary is None:
        return {
            "test_id": "ROLEDIFF",
            "category": "authorization",
            "status_hint": "SKIPPED",
            "skip_reason": SKIP_LOGIN_FAILED,
            "observations": {"detail": "could not log in account_a for role comparison"},
            "finding_candidate": False,
            "evidence_hints": [],
        }

    snaps_a = [_snapshot(client, base_url, "account_a", p) for p in paths] if a_ok else []

    b_ok = _try_login(client, base_url, "account_b", "account-b-pass")
    if not b_ok and secondary is None:
        return {
            "test_id": "ROLEDIFF",
            "category": "authorization",
            "status_hint": "SKIPPED",
            "skip_reason": SKIP_NO_SECOND_ROLE,
            "observations": {
                "detail": "second role (account_b / secondary profile) unavailable",
                "account_a_ok": a_ok,
            },
            "finding_candidate": False,
            "evidence_hints": ["need two AuthCredentialProfile rows or lab account_b"],
        }

    snaps_b = [_snapshot(client, base_url, "account_b", p) for p in paths] if b_ok else []
    diffs = compare_roles(snaps_a, snaps_b, intrusive=False) if snaps_a and snaps_b else []
    meaningful = [
        d
        for d in diffs
        if d.status_differs or d.redirect_differs or d.controls_only_in_a or d.controls_only_in_b
    ]
    # On the vulnerable lab, both roles can list both projects — that is an authz smell.
    a_sees_b = any("proj-b" in (s.body_markers or []) for s in snaps_a)
    b_sees_a = any("proj-a" in (s.body_markers or []) for s in snaps_b)
    cross_list = bool(a_sees_b or b_sees_a)
    finding = cross_list and a_ok and b_ok
    return {
        "test_id": "ROLEDIFF",
        "category": "authorization",
        "observations": {
            "diff_count": len(meaningful),
            "cross_role_list": cross_list,
            "account_a_ok": a_ok,
            "account_b_ok": b_ok,
            "notes": [n for d in meaningful for n in d.notes][:20],
        },
        "finding_candidate": finding,
        "evidence_hints": [f"role compare on {p}" for p in paths],
    }
