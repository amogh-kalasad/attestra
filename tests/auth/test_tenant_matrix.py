"""Cross-tenant access matrix for scoped API routes."""
# @lat: [[tests#Phase 2 auth tests#tests/auth/test_tenant_matrix.py]]

from __future__ import annotations

from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient


def _make_tenant_engagement(s, name: str, actor: str = "seed"):
    from attestra import services

    today = date.today()
    return services.create_engagement(
        s,
        tenant=name,
        name=f"{name} eng",
        type="va",
        frameworks=[],
        window_start=today,
        window_end=today + timedelta(days=7),
        actor=actor,
    )


@pytest.fixture
def two_tenants(fresh_db):
    from attestra import db
    from attestra.auth.keys import create_api_key, create_user
    from attestra.models import TenantMembership

    with db.session() as s:
        e_a = _make_tenant_engagement(s, "Tenant A")
        e_b = _make_tenant_engagement(s, "Tenant B")
        viewer_a = create_user(
            s, username="viewera", role="client_viewer", password="pw-viewera", tenant_id=e_a.tenant_id
        )
        viewer_b = create_user(
            s, username="viewerb", role="client_viewer", password="pw-viewerb", tenant_id=e_b.tenant_id
        )
        staff = create_user(s, username="staffa", role="tester", password="pw-staffa")
        s.add(TenantMembership(user_id=staff.id, tenant_id=e_a.tenant_id, role="tester"))
        _, key_a = create_api_key(s, viewer_a)
        _, key_b = create_api_key(s, viewer_b)
        _, key_staff = create_api_key(s, staff)
        return {
            "eid_a": e_a.id,
            "eid_b": e_b.id,
            "key_a": key_a,
            "key_b": key_b,
            "key_staff": key_staff,
        }


def test_cross_tenant_get_returns_404(two_tenants):
    from attestra.api import app

    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {two_tenants['key_a']}"
        r = c.get(f"/api/engagements/{two_tenants['eid_b']}")
        assert r.status_code == 404


def test_same_tenant_get_ok(two_tenants):
    from attestra.api import app

    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {two_tenants['key_a']}"
        r = c.get(f"/api/engagements/{two_tenants['eid_a']}")
        assert r.status_code == 200
        assert r.json()["id"] == two_tenants["eid_a"]


def test_list_excludes_other_tenant(two_tenants):
    from attestra.api import app

    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {two_tenants['key_a']}"
        r = c.get("/api/engagements")
        assert r.status_code == 200
        ids = {row["id"] for row in r.json()}
        assert two_tenants["eid_a"] in ids
        assert two_tenants["eid_b"] not in ids


def test_staff_membership_scoped(two_tenants):
    from attestra.api import app

    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {two_tenants['key_staff']}"
        assert c.get(f"/api/engagements/{two_tenants['eid_a']}").status_code == 200
        assert c.get(f"/api/engagements/{two_tenants['eid_b']}").status_code == 404


@pytest.mark.parametrize(
    "role,permission,ok",
    [
        ("tester", "scan.start", True),
        ("client_viewer", "scan.start", False),
        ("reviewer", "report.approve", True),
        ("tester", "report.approve", False),
    ],
)
def test_role_permissions(role, permission, ok):
    from attestra.auth.roles import has_permission

    assert has_permission(role, permission) is ok
