"""K-02: sensitive engagement routes deny cross-tenant access with 404.

Needs the Mongo test harness (``fresh_db``). When the local Mongo requires credentials the
harness does not have, these tests are skipped with that reason instead of erroring.
"""
# @lat: [[attack-surface-and-platform#Tenant isolation and action matrix tests]]

from __future__ import annotations

from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient


def _mongo_or_skip(request) -> None:
    try:
        request.getfixturevalue("fresh_db")
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        if code == 13 or "requires authentication" in str(exc):
            pytest.skip("test MongoDB requires credentials (ATTESTRA_TEST_MONGODB_URI)")
        raise


@pytest.fixture
def tenants(request):
    _mongo_or_skip(request)
    from attestra import db, services
    from attestra.auth.keys import create_api_key, create_user
    from attestra.models import TenantMembership

    today = date.today()

    def eng(s, name):
        return services.create_engagement(
            s, tenant=name, name=f"{name} eng", type="va", frameworks=[],
            window_start=today, window_end=today + timedelta(days=7), actor="seed",
        )

    with db.session() as s:
        e_a, e_b = eng(s, "Iso Tenant A"), eng(s, "Iso Tenant B")
        staff = create_user(s, username="iso.tester", role="tester", password="pw-iso-tester-1")
        s.add(TenantMembership(user_id=staff.id, tenant_id=e_a.tenant_id, role="tester"))
        lead = create_user(s, username="iso.lead", role="lead", password="pw-iso-lead-1")
        s.add(TenantMembership(user_id=lead.id, tenant_id=e_a.tenant_id, role="lead"))
        _, key_staff = create_api_key(s, staff)
        _, key_lead = create_api_key(s, lead)
        return {"eid_a": e_a.id, "eid_b": e_b.id, "key_staff": key_staff, "key_lead": key_lead}


READ_ROUTES = [
    "/api/engagements/{eid}",
    "/api/engagements/{eid}/assets",
    "/api/engagements/{eid}/findings/export",
    "/api/engagements/{eid}/export/json",
    "/api/engagements/{eid}/export/sarif",
    "/api/engagements/{eid}/export/markdown",
    "/api/engagements/{eid}/scans",
    "/api/engagements/{eid}/schedules",
    "/api/automated-vapt/engagements/{eid}/executions",
    "/api/auth-web/engagements/{eid}/auth-profiles",
]


@pytest.mark.parametrize("path", READ_ROUTES)
def test_cross_tenant_read_routes_return_404(tenants, path):
    from attestra.api import app

    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {tenants['key_lead']}"
        r = c.get(path.format(eid=tenants["eid_b"]))
        if r.status_code == 403 and "disabled" in r.text:
            pytest.skip(f"{path}: feature flag off, route refuses before the tenant check")
        assert r.status_code == 404, (path, r.status_code)


def test_same_tenant_read_still_works(tenants):
    from attestra.api import app

    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {tenants['key_lead']}"
        assert c.get(f"/api/engagements/{tenants['eid_a']}/assets").status_code == 200


@pytest.mark.parametrize(
    "path,body",
    [
        ("/api/engagements/{eid}/assets", {"kind": "web_app", "identifier": "https://iso-b.example/"}),
        ("/api/engagements/{eid}/scans", {"asset_id": 1, "tool": "webcheck"}),
        ("/api/engagements/{eid}/reports", {"kind": "technical"}),
    ],
)
def test_cross_tenant_writes_return_404(tenants, path, body):
    from attestra.api import app

    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {tenants['key_lead']}"
        r = c.post(path.format(eid=tenants["eid_b"]), json=body)
        assert r.status_code in (404, 422), (path, r.status_code)
        assert r.status_code != 201


def test_cross_tenant_discovery_candidates_return_404(tenants, monkeypatch):
    from fastapi import FastAPI

    from attestra.discovery.routes import router

    monkeypatch.setenv("ATTESTRA_DISCOVERY_ENABLED", "1")
    from attestra import config

    monkeypatch.setattr(config, "DISCOVERY_ENABLED", True, raising=False)
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {tenants['key_lead']}"
        assert c.get(f"/api/engagements/{tenants['eid_b']}/discovery/candidates").status_code == 404
        assert c.post(f"/api/engagements/{tenants['eid_b']}/discovery/candidates/dc_x/approve").status_code == 404
