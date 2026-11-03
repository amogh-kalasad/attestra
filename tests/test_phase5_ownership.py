"""Phase 5 workflow: ownership token set/reuse and verify-now on the target page."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from attestra import db, services
from attestra.models import Asset, AuditEvent, utcnow
from attestra.runner import ownership


def _web_asset(s, eid: int, identifier: str = "https://shop.example.com") -> Asset:
    a = services.add_asset(
        s,
        eid,
        kind="web_app",
        identifier=identifier,
        name="Storefront",
        environment="production",
        actor="tester",
    )
    ownership.ensure_token(a)
    return a


# @lat: [[tests#Phase 5 workflow#Ownership token set clears verification]]
def test_set_ownership_token_clears_verification_and_audits_suffix(engagement):
    with db.session() as s:
        a = _web_asset(s, engagement, "https://a.example.com")
        original = a.ownership_token
        a.ownership_verified_at = utcnow()
        reused = "ReuseTokenValue0123456789abcd"
        out = services.set_ownership_token(s, engagement, a.id, reused, actor="lead")
        assert out.ownership_token == reused
        assert out.ownership_verified_at is None
        assert original != reused

        rows = list(
            s.scalars(
                select(AuditEvent).where(AuditEvent.action == "asset.ownership_token_set").order_by(AuditEvent.id)
            )
        )
        assert len(rows) == 1
        details = rows[0].details or {}
        assert details.get("token_suffix") == reused[-4:]
        assert reused not in str(details)
        assert details.get("changed") is True


# @lat: [[tests#Phase 5 workflow#Ownership token format rejected]]
def test_set_ownership_token_rejects_bad_format(engagement):
    with db.session() as s:
        a = _web_asset(s, engagement, "https://b.example.com")
        with pytest.raises(services.ServiceError, match="16"):
            services.set_ownership_token(s, engagement, a.id, "short", actor="lead")
        with pytest.raises(services.ServiceError):
            services.set_ownership_token(s, engagement, a.id, "bad token with spaces!!", actor="lead")
        with pytest.raises(services.ServiceError, match="required"):
            services.set_ownership_token(s, engagement, a.id, "   ", actor="lead")


# @lat: [[tests#Phase 5 workflow#Ownership reuse same token no clear]]
def test_set_same_token_keeps_verification(engagement):
    with db.session() as s:
        a = _web_asset(s, engagement, "https://c.example.com")
        token = a.ownership_token
        verified = utcnow()
        a.ownership_verified_at = verified
        services.set_ownership_token(s, engagement, a.id, token, actor="admin")
        assert a.ownership_token == token
        assert a.ownership_verified_at == verified


# @lat: [[tests#Phase 5 workflow#Ownership 30-day full flow]]
def test_ownership_30_day_full_flow(engagement, monkeypatch):
    """Unverified → verify → still valid → expire → gate refuse → re-verify."""
    from fastapi.testclient import TestClient

    from attestra.api import app
    from attestra.auth.keys import create_user
    from attestra.models import Engagement
    from attestra.runner.gate import GateError, check

    with db.session() as s:
        tid = s.get(Engagement, engagement).tenant_id
        a = _web_asset(s, engagement, "https://flow.example.com")
        aid, token = a.id, a.ownership_token
        create_user(
            s, username="lead-flow", role="lead", password="pw-1234567890", display_name="lead-flow", tenant_id=tid
        )

    client = TestClient(app)
    client.post("/login", data={"username": "lead-flow", "password": "pw-1234567890"}, follow_redirects=False)

    # 1) Not verified on engagement + target pages
    eng = client.get(f"/engagements/{engagement}")
    assert eng.status_code == 200
    assert "Not verified" in eng.text
    assert "attestra-verify=" in eng.text
    assert token in eng.text
    assert "Proof stays valid for 30 days" in eng.text

    target = client.get(f"/engagements/{engagement}/targets/{aid}")
    assert target.status_code == 200
    assert "Not verified" in target.text
    assert "Proof stays valid for 30 days" in target.text

    # 2) Verify now (DNS)
    def fake_check(asset, *, scope=None, scope_error=""):
        asset.ownership_verified_at = utcnow()
        return ownership.OwnershipCheck(ok=True, method="dns", dns_note="ok")

    monkeypatch.setattr(ownership, "check", fake_check)
    r = client.post(f"/engagements/{engagement}/targets/{aid}/verify-ownership-now", follow_redirects=False)
    assert r.status_code == 303
    from urllib.parse import unquote

    assert "Valid for 30 days" in unquote(r.headers["location"])

    with db.session() as s:
        asset = s.get(Asset, aid)
        assert ownership.is_verified(asset) is True
        assert ownership.is_expired(asset) is False
        until = ownership.verified_until(asset)
        assert until is not None
        assert until == ownership._as_utc(asset.ownership_verified_at) + timedelta(days=30)

    # 3) UI shows Verified until; early re-check is a no-op success
    target2 = client.get(f"/engagements/{engagement}/targets/{aid}")
    assert "Verified" in target2.text
    assert "valid until" in target2.text
    assert "Keep the DNS TXT" in target2.text

    eng2 = client.get(f"/engagements/{engagement}")
    assert "Verified" in eng2.text
    assert "Until" in eng2.text
    assert "verified" in eng2.text  # scan dropdown label

    with db.session() as s:
        result = services.verify_asset_ownership(s, engagement, aid, actor="lead-flow")
        assert result.ok is True
        assert "already verified" in result.message
        assert "stays valid until" in result.message

    # 4) Expire after 30 days: UI Expired + gate refuses ownership
    with db.session() as s:
        asset = s.get(Asset, aid)
        asset.ownership_verified_at = utcnow() - timedelta(days=30)
        assert ownership.is_verified(asset) is False
        assert ownership.is_expired(asset) is True

    expired_target = client.get(f"/engagements/{engagement}/targets/{aid}")
    assert "Expired" in expired_target.text
    assert "re-check required" in expired_target.text
    assert "Verify now" in expired_target.text

    expired_eng = client.get(f"/engagements/{engagement}")
    assert "Expired" in expired_eng.text
    assert "Renew ownership" in expired_eng.text
    assert "expired" in expired_eng.text  # scan dropdown

    with db.session() as s:
        with pytest.raises(GateError, match="ownership"):
            check(s, engagement, aid, tool="zap", profile="baseline", actor="lead-flow")

    # 5) Re-verify restores gate path past ownership (DNS pin may still refuse in tests)
    r2 = client.post(f"/engagements/{engagement}/targets/{aid}/verify-ownership", follow_redirects=False)
    assert r2.status_code == 303
    assert "Valid for 30 days" in unquote(r2.headers["location"])
    with db.session() as s:
        asset = s.get(Asset, aid)
        assert ownership.is_verified(asset) is True
        assert ownership.is_expired(asset) is False
        from attestra.runner.gate import policy_input

        inp = policy_input(s, engagement, aid, tool="zap", profile="baseline")
        assert inp["ownership_verified"] is True
        # Full check() may still fail DNS pin for example.com hosts; ownership must already pass.
        try:
            check(s, engagement, aid, tool="zap", profile="baseline", actor="lead-flow")
        except GateError as exc:
            assert "ownership" not in str(exc).lower()
        except OSError:
            pass


# @lat: [[tests#Phase 5 workflow#Ownership proof expires after 30 days]]
def test_ownership_proof_expires_after_30_days():
    now = utcnow()
    fresh = SimpleNamespace(
        ownership_verified_at=now - timedelta(days=29),
        identifier="https://fresh.example.com",
        notes="",
    )
    stale = SimpleNamespace(
        ownership_verified_at=now - timedelta(days=31),
        identifier="https://stale.example.com",
        notes="",
    )
    never = SimpleNamespace(ownership_verified_at=None, identifier="https://x.example.com", notes="")
    assert ownership.is_verified(fresh) is True
    assert ownership.is_expired(fresh) is False
    assert ownership.verified_until(fresh) == fresh.ownership_verified_at + timedelta(
        days=ownership.OWNERSHIP_VALIDITY_DAYS
    )
    assert ownership.is_verified(stale) is False
    assert ownership.is_expired(stale) is True
    assert ownership.is_verified(never) is False
    assert ownership.is_expired(never) is False


# @lat: [[tests#Phase 5 workflow#Ownership org host reuse across engagements]]
def test_ownership_org_host_reuse_across_engagements(engagement):
    from datetime import date

    from sqlalchemy import select

    from attestra.models import Engagement
    from attestra.runner.gate import policy_input

    today = date.today()
    with db.session() as s:
        from attestra.models import Tenant

        eng1 = s.get(Engagement, engagement)
        tid = eng1.tenant_id
        tenant = s.get(Tenant, tid)
        assert tenant is not None
        # Use the fixture web_app host so a second engagement can inherit it.
        a1 = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")
        ).first()
        assert a1 is not None
        a1.ownership_token = "SharedOrgTokenValue0123456789ab"
        a1.ownership_verified_at = utcnow()
        token = a1.ownership_token

        eng2 = services.create_engagement(
            s,
            tenant=tenant.name,
            name="Second shop eng",
            type="va",
            frameworks=["pci_dss_4"],
            window_start=today - timedelta(days=1),
            window_end=today + timedelta(days=14),
            actor="tester",
        )
        a2 = services.add_asset(
            s,
            eng2.id,
            kind="web_app",
            identifier="https://shop.example.com/checkout",
            name="Shop again",
            environment="production",
            actor="tester",
        )
        assert a2.ownership_token == token
        assert a2.ownership_verified_at is not None
        assert ownership.is_verified(
            a2, validity_days=services.ownership_validity_days_for_tenant(s, tid)
        )
        assert services.asset_ownership_verified(s, a2, tenant_id=tid) is True
        inp = policy_input(s, eng2.id, a2.id, tool="zap", profile="baseline")
        assert inp["ownership_verified"] is True

        # Expired org proof: reuse token, require re-verify
        a1.ownership_verified_at = utcnow() - timedelta(days=60)
        a2.ownership_verified_at = None
        a2.ownership_token = ""
        status = services.inherit_or_issue_ownership(s, a2, tenant_id=tid, actor="tester")
        assert status == "inherited_token"
        assert a2.ownership_token == token
        assert a2.ownership_verified_at is None
        assert services.asset_ownership_verified(s, a2, tenant_id=tid) is False

        # Fresh verify on one target propagates to the sibling with same host/token
        a2.ownership_verified_at = utcnow()
        n = services.propagate_ownership_verification(s, a2, tenant_id=tid, actor="tester")
        assert n >= 1
        s.refresh(a1)
        assert a1.ownership_token == token
        assert a1.ownership_verified_at is not None
        assert ownership._as_utc(a1.ownership_verified_at) == ownership._as_utc(a2.ownership_verified_at)


# @lat: [[tests#Phase 5 workflow#Ownership validity Super Admin configurable]]
def test_ownership_validity_super_admin_configurable(engagement):
    from types import SimpleNamespace

    from fastapi.testclient import TestClient

    from attestra.api import app
    from attestra.auth.keys import create_user
    from attestra.models import Engagement
    from attestra.runner.gate import GateError, check

    with db.session() as s:
        eng = s.get(Engagement, engagement)
        tid = eng.tenant_id
        assert services.ownership_validity_days_for_tenant(s, tid) == 30
        a = _web_asset(s, engagement, "https://cfg.example.com")
        aid = a.id
        a.ownership_verified_at = utcnow() - timedelta(days=10)
        create_user(
            s, username="admin-ov", role="admin", password="pw-1234567890", display_name="admin-ov", tenant_id=tid
        )
        create_user(
            s, username="lead-ov-cfg", role="lead", password="pw-1234567890", display_name="lead-ov-cfg", tenant_id=tid
        )
        lead = SimpleNamespace(role="lead", actor="lead-ov-cfg", tenant_id=tid, user_id=0)
        with pytest.raises(PermissionError, match="Super Admin"):
            services.set_ownership_validity_days(s, lead, tid, 7)
        admin = SimpleNamespace(role="admin", actor="admin-ov", tenant_id=tid, user_id=0)
        services.set_ownership_validity_days(s, admin, tid, 7)
        assert services.ownership_validity_days_for_tenant(s, tid) == 7
        asset = s.get(Asset, aid)
        assert ownership.is_verified(asset, validity_days=7) is False
        assert ownership.is_expired(asset, validity_days=7) is True
        assert ownership.is_verified(asset, validity_days=30) is True

    with db.session() as s:
        with pytest.raises(GateError, match="ownership"):
            check(s, engagement, aid, tool="zap", profile="baseline", actor="admin-ov")

    client = TestClient(app)
    denied = client.post("/login", data={"username": "lead-ov-cfg", "password": "pw-1234567890"}, follow_redirects=False)
    assert denied.status_code in (303, 302)
    lead_page = client.get("/settings/ownership", follow_redirects=False)
    assert lead_page.status_code in (303, 302, 403)

    client = TestClient(app)
    client.post("/login", data={"username": "admin-ov", "password": "pw-1234567890"}, follow_redirects=False)
    page = client.get(f"/settings/ownership?tenant_id={tid}")
    assert page.status_code == 200
    assert "Ownership verification" in page.text
    assert 'name="ownership_validity_days"' in page.text
    save = client.post(
        "/settings/ownership",
        data={"tenant_id": str(tid), "ownership_validity_days": "14"},
        follow_redirects=False,
    )
    assert save.status_code == 303
    with db.session() as s:
        assert services.ownership_validity_days_for_tenant(s, tid) == 14

    api = TestClient(app)
    # lead API key path: create admin key
    from attestra.auth.keys import create_api_key

    with db.session() as s:
        from attestra.models import User

        admin_user = s.scalars(select(User).where(User.username == "admin-ov")).one()
        lead_user = s.scalars(select(User).where(User.username == "lead-ov-cfg")).one()
        _, admin_key = create_api_key(s, admin_user)
        _, lead_key = create_api_key(s, lead_user)

    r_forbid = api.get(f"/api/settings/ownership?tenant_id={tid}", headers={"Authorization": f"Bearer {lead_key}"})
    assert r_forbid.status_code == 403
    r_ok = api.get(f"/api/settings/ownership?tenant_id={tid}", headers={"Authorization": f"Bearer {admin_key}"})
    assert r_ok.status_code == 200
    assert r_ok.json()["ownership_validity_days"] == 14
    r_put = api.put(
        f"/api/settings/ownership?tenant_id={tid}",
        headers={"Authorization": f"Bearer {admin_key}"},
        json={"ownership_validity_days": 21},
    )
    assert r_put.status_code == 200
    assert r_put.json()["ownership_validity_days"] == 21


# @lat: [[tests#Phase 5 workflow#Ownership expired allows re-verify]]
def test_expired_ownership_allows_re_verify(engagement, monkeypatch):
    with db.session() as s:
        a = _web_asset(s, engagement, "https://expire.example.com")
        a.ownership_verified_at = utcnow() - timedelta(days=31)
        aid = a.id

        def fake_check(asset, *, scope=None, scope_error=""):
            asset.ownership_verified_at = utcnow()
            return ownership.OwnershipCheck(ok=True, method="dns", dns_note="renewed")

        monkeypatch.setattr(ownership, "check", fake_check)
        result = services.verify_asset_ownership(s, engagement, aid, actor="lead")
        assert result.ok is True
        assert result.method == "dns"
        renewed = s.get(Asset, aid)
        assert ownership.is_verified(renewed) is True
        assert ownership.is_expired(renewed) is False


# @lat: [[tests#Phase 5 workflow#Ownership target page routes]]
def test_asset_page_set_token_and_verify_now_routes(engagement, monkeypatch):
    from fastapi.testclient import TestClient

    from attestra.api import app
    from attestra.auth.keys import create_user
    from attestra.models import Engagement

    with db.session() as s:
        tid = s.get(Engagement, engagement).tenant_id
        a = _web_asset(s, engagement, "https://d.example.com")
        aid, token = a.id, a.ownership_token
        create_user(
            s, username="lead-ov", role="lead", password="pw-1234567890", display_name="lead-ov", tenant_id=tid
        )

    client = TestClient(app)
    client.post("/login", data={"username": "lead-ov", "password": "pw-1234567890"}, follow_redirects=False)

    page = client.get(f"/engagements/{engagement}/targets/{aid}")
    assert page.status_code == 200
    assert "ownership-token" in page.text
    assert "verify-ownership-now" in page.text
    assert "Verify now" in page.text
    assert "Proof stays valid for 30 days" in page.text

    with db.session() as s:
        asset = s.get(Asset, aid)
        asset.ownership_verified_at = utcnow() - timedelta(days=31)
    expired_page = client.get(f"/engagements/{engagement}/targets/{aid}")
    assert expired_page.status_code == 200
    assert "Expired" in expired_page.text
    assert "re-check required" in expired_page.text
    assert "Verify now" in expired_page.text

    reused = "SharedTokenFromOtherAsset99xx"
    r = client.post(
        f"/engagements/{engagement}/targets/{aid}/ownership-token",
        data={"token": reused},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert f"/engagements/{engagement}/targets/{aid}" in r.headers["location"]

    with db.session() as s:
        asset = s.get(Asset, aid)
        assert asset.ownership_token == reused
        assert asset.ownership_verified_at is None

    def fake_check(asset, *, scope=None, scope_error=""):
        asset.ownership_verified_at = utcnow()
        return ownership.OwnershipCheck(ok=True, method="dns", dns_note="ok")

    monkeypatch.setattr(ownership, "check", fake_check)
    r2 = client.post(
        f"/engagements/{engagement}/targets/{aid}/verify-ownership-now",
        follow_redirects=False,
    )
    assert r2.status_code == 303
    assert "msg=" in r2.headers["location"]
    with db.session() as s:
        assert s.get(Asset, aid).ownership_verified_at is not None
        assert token != reused
