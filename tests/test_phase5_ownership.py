"""Phase 5 workflow: ownership token set/reuse and verify-now on the target page."""

from __future__ import annotations

from datetime import UTC, datetime

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
        verified = datetime(2024, 1, 2, tzinfo=UTC)
        a.ownership_verified_at = verified
        services.set_ownership_token(s, engagement, a.id, token, actor="admin")
        assert a.ownership_token == token
        assert a.ownership_verified_at == verified


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
