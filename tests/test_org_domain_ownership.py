"""Organization Domain ownership page: durable host tokens, download file, renew on expiry."""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from attestra import db, services
from attestra.auth.keys import create_user
from attestra.models import Engagement, Tenant, TenantOwnershipHost, utcnow
from attestra.org_ownership import service as org_own
from attestra.runner import ownership


@pytest.fixture
def org_lead(fresh_db):
    today = date.today()
    with db.session() as s:
        eng = services.create_engagement(
            s,
            tenant="Domain Own Org",
            name="DO Eng 1",
            type="va",
            frameworks=["pci_dss_4"],
            window_start=today - timedelta(days=1),
            window_end=today + timedelta(days=14),
            actor="lead",
        )
        tid = eng.tenant_id
        create_user(
            s,
            username="do-lead",
            role="lead",
            password="pw-domain-own-12",
            display_name="DO Lead",
            tenant_id=tid,
        )
        create_user(
            s,
            username="do-viewer",
            role="client_viewer",
            password="pw-domain-own-12",
            display_name="DO Viewer",
            tenant_id=tid,
        )
        return {"tenant_id": tid, "engagement_id": eng.id}


# @lat: [[tests#Phase 5 workflow#Organization domain ownership page]]
def test_org_domain_ownership_page_download_and_reuse(org_lead, monkeypatch):
    tid = org_lead["tenant_id"]
    from attestra.api import app

    client = TestClient(app)
    denied = client.post(
        "/login", data={"username": "do-viewer", "password": "pw-domain-own-12"}, follow_redirects=False
    )
    assert denied.status_code in (302, 303)
    page = client.get(f"/settings/domain-ownership?tenant_id={tid}", follow_redirects=False)
    assert page.status_code in (302, 303, 403)

    client = TestClient(app)
    client.post("/login", data={"username": "do-lead", "password": "pw-domain-own-12"}, follow_redirects=False)

    add = client.post(
        "/settings/domain-ownership/hosts",
        data={"tenant_id": str(tid), "hostname": "shop.example.com"},
        follow_redirects=False,
    )
    assert add.status_code == 303

    with db.session() as s:
        row = s.scalars(
            select(TenantOwnershipHost).where(
                TenantOwnershipHost.tenant_id == tid, TenantOwnershipHost.hostname == "shop.example.com"
            )
        ).one()
        hid = row.id
        token = row.ownership_token
        assert token

    page = client.get(f"/settings/domain-ownership?tenant_id={tid}")
    assert page.status_code == 200
    assert "Domain ownership" in page.text
    assert "shop.example.com" in page.text
    assert f"attestra-verify={token}" in page.text
    assert "Download attestra-verify.txt" in page.text
    assert "one-time" in page.text.lower() or "not session" in page.text.lower() or "until it expires" in page.text

    dl = client.get(f"/settings/domain-ownership/hosts/{hid}/attestra-verify.txt")
    assert dl.status_code == 200
    assert dl.text == token
    cd = dl.headers.get("content-disposition", "")
    assert "attestra-verify.txt" in cd
    assert "attachment" in cd

    # Same hostname again does not rotate token (not session-based)
    add2 = client.post(
        "/settings/domain-ownership/hosts",
        data={"tenant_id": str(tid), "hostname": "https://shop.example.com/app"},
        follow_redirects=False,
    )
    assert add2.status_code == 303
    with db.session() as s:
        row = s.get(TenantOwnershipHost, hid)
        assert row.ownership_token == token

    # Verify via mocked DNS
    def fake_check(asset, *, scope=None, scope_error=""):
        asset.ownership_verified_at = utcnow()
        return ownership.OwnershipCheck(ok=True, method="dns", dns_note="ok")

    monkeypatch.setattr(ownership, "check", fake_check)
    ver = client.post(f"/settings/domain-ownership/hosts/{hid}/verify", follow_redirects=False)
    assert ver.status_code == 303
    assert "verified" in ver.headers.get("location", "").lower() or "Valid" in ver.headers.get("location", "")

    with db.session() as s:
        row = s.get(TenantOwnershipHost, hid)
        assert row.ownership_verified_at is not None
        tenant = s.get(Tenant, tid)
        today = date.today()
        eng2 = services.create_engagement(
            s,
            tenant=tenant.name,
            name="DO Eng 2",
            type="va",
            frameworks=["pci_dss_4"],
            window_start=today - timedelta(days=1),
            window_end=today + timedelta(days=14),
            actor="lead",
        )
        a2 = services.add_asset(
            s,
            eng2.id,
            kind="web_app",
            identifier="https://shop.example.com/checkout",
            name="Checkout",
            environment="production",
            actor="lead",
        )
        assert a2.ownership_token == token
        assert a2.ownership_verified_at is not None
        assert services.asset_ownership_verified(s, a2, tenant_id=tid) is True

    # Expiry renews a new DNS token
    with db.session() as s:
        row = s.get(TenantOwnershipHost, hid)
        row.ownership_verified_at = utcnow() - timedelta(days=60)
        renewed = org_own.renew_org_ownership_host_if_expired(s, row, actor="do-lead")
        assert renewed is True
        assert row.ownership_token != token
        assert row.ownership_verified_at is None
