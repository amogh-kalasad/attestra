"""K-03: role × sensitive-action authorization matrix (no database needed).

Two layers are checked:
1. the RBAC table (``auth.roles``) gives each sensitive action only to the intended roles;
2. each sensitive HTTP route actually depends on ``require(<that permission>)``, found by
   walking FastAPI's dependency tree, so a route cannot silently lose its guard.
"""
# @lat: [[attack-surface-and-platform#Tenant isolation and action matrix tests]]

from __future__ import annotations

import pytest

from attestra.auth.roles import PERMISSIONS, ROLES, has_permission

# action → (permission, roles that must be allowed). Everything else must be denied.
MATRIX: dict[str, tuple[str, frozenset[str]]] = {
    "start_scan": ("scan.start", frozenset({"admin", "lead", "tester"})),
    "approve_asset": ("asset.write", frozenset({"admin", "lead", "tester"})),
    "verify_asset_ownership": ("asset.verify_ownership", frozenset({"admin", "lead"})),
    "view_evidence": ("finding.read", frozenset(ROLES)),
    "sign_report": ("report.sign", frozenset({"admin", "lead"})),
    "approve_report": ("report.approve", frozenset({"admin", "lead", "reviewer"})),
    "halt_engagement": ("engagement.halt", frozenset({"admin", "lead"})),
    "manage_users_and_invites": ("user.manage", frozenset({"admin"})),
    "manage_webhooks_and_keys": ("webhook.manage", frozenset({"admin", "lead"})),
    "confirm_compliance": ("compliance.confirm", frozenset({"admin", "auditor"})),
    "allocate_credits": ("credits.allocate", frozenset({"admin"})),
}


@pytest.mark.parametrize("action", sorted(MATRIX))
@pytest.mark.parametrize("role", ROLES)
def test_role_action_matrix(role, action):
    permission, allowed = MATRIX[action]
    assert permission in PERMISSIONS, f"{permission} missing from RBAC table"
    assert has_permission(role, permission) is (role in allowed), f"{role} × {action}"


def test_unknown_permission_and_role_denied():
    assert has_permission("admin", "does.not.exist") is False
    assert has_permission("", "scan.start") is False
    assert has_permission("superuser", "report.sign") is False


def test_client_viewer_cannot_do_any_sensitive_write():
    for action in ("start_scan", "approve_asset", "sign_report", "approve_report", "halt_engagement"):
        assert not has_permission("client_viewer", MATRIX[action][0]), action


def _route_permissions(route) -> set[str]:
    """All ``permission`` values captured by require()/dep closures in a route's dependants."""
    found: set[str] = set()
    stack = [route.dependant]
    while stack:
        dep = stack.pop()
        call = getattr(dep, "call", None)
        if call is not None:
            if getattr(call, "permission", None):
                found.add(call.permission)
            for cell in getattr(call, "__closure__", None) or ():
                try:
                    val = cell.cell_contents
                except ValueError:
                    continue
                if isinstance(val, str) and val in PERMISSIONS:
                    found.add(val)
        stack.extend(getattr(dep, "dependencies", []) or [])
    return found


def _find(app, method: str, path: str):
    for r in app.routes:
        if getattr(r, "path", None) == path and method in (getattr(r, "methods", None) or set()):
            return r
    raise AssertionError(f"route {method} {path} not found")


API_ROUTES = [
    ("POST", "/api/engagements/{eid}/scans", "scan.start"),
    ("POST", "/api/engagements/{eid}/assets", "asset.write"),
    ("DELETE", "/api/assets/{aid}", "asset.write"),
    ("GET", "/api/evidence/{eid}/download", "finding.read"),
    ("POST", "/api/reports/{rid}/sign", "report.sign"),
    ("POST", "/api/engagements/{eid}/halt", "engagement.halt"),
    ("GET", "/api/engagements/{eid}/scans", "scan.read"),
]


@pytest.fixture(scope="module")
def app():
    from attestra.api import app as fastapi_app

    return fastapi_app


@pytest.mark.parametrize("method,path,permission", API_ROUTES)
def test_sensitive_api_routes_require_permission(app, method, path, permission):
    assert permission in _route_permissions(_find(app, method, path))


@pytest.mark.parametrize(
    "method,path,permission",
    [
        ("GET", "/api/engagements/{eid}/discovery/candidates", "engagement.read"),
        ("POST", "/api/engagements/{eid}/discovery/candidates/{cid}/approve", "asset.write"),
        ("POST", "/api/engagements/{eid}/discovery/candidates/{cid}/reject", "asset.write"),
    ],
)
def test_discovery_routes_require_permission(method, path, permission):
    from types import SimpleNamespace

    from attestra.discovery.routes import router

    assert permission in _route_permissions(_find(SimpleNamespace(routes=router.routes), method, path))


def test_discovery_approval_denied_for_read_only_roles():
    for role in ("client_viewer", "reviewer", "auditor"):
        assert not has_permission(role, "asset.write"), role
