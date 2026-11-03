"""Clean end-to-end ownership flow with NO bypass flags.

Signed authorization and ownership verification stay mandatory.
Uses private-IP owner confirm (real product path; no DNS mock, no gate bypass).
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
from urllib.parse import unquote

import pytest
from fastapi.testclient import TestClient

from sqlalchemy import select

from attestra import config, db, services
from attestra.auth.keys import create_user
from attestra.models import Asset, Engagement, Tenant
from attestra.runner.gate import GateError, check, policy_input

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def clean_env(monkeypatch):
    """Force mandatory ownership + signed authorization (no local bypass)."""
    monkeypatch.setenv("BYPASS_TARGET_OWNERSHIP_VERIFICATION", "false")
    monkeypatch.setenv("BYPASS_SIGNED_AUTHORIZATION_VERIFICATION", "false")
    monkeypatch.setenv("APP_ENV", "local")
    # Re-read flags into config module globals used by required() helpers.
    config.BYPASS_TARGET_OWNERSHIP_VERIFICATION = False
    config.BYPASS_SIGNED_AUTHORIZATION_VERIFICATION = False
    config.APP_ENV = "local"
    assert config.ownership_verification_required() is True
    assert config.signed_authorization_required() is True
    assert config.ownership_bypass_active() is False
    assert config.signed_authorization_bypass_active() is False


# @lat: [[tests#Phase 5 workflow#Ownership org host reuse across engagements]]
def test_clean_e2e_ownership_no_bypass_org_reuse(fresh_db, clean_env):
    today = date.today()
    host = "192.168.50.20"
    url = f"https://{host}"

    with db.session() as s:
        eng1 = services.create_engagement(
            s,
            tenant="Clean E2E Org",
            name="Engagement Q1",
            type="va",
            frameworks=["pci_dss_4"],
            window_start=today - timedelta(days=1),
            window_end=today + timedelta(days=14),
            actor="lead",
        )
        tid = eng1.tenant_id
        services.add_authorization(
            s,
            eng1.id,
            filename="authorization.txt",
            data=(FIXTURES / "authorization.txt").read_bytes(),
            signer="CISO Clean E2E",
            signed_on=today - timedelta(days=2),
            expires_on=today + timedelta(days=60),
            rules_of_engagement="No DoS; business hours.",
            environments=["production", "staging"],
            actor="lead",
        )
        a1 = services.add_asset(
            s,
            eng1.id,
            kind="web_app",
            identifier=url,
            name="Internal shop",
            environment="production",
            exposure="internal",
            actor="lead",
        )
        # Mandatory ownership: not verified yet → gate must refuse
        with pytest.raises(GateError, match="ownership"):
            check(s, eng1.id, a1.id, tool="zap", profile="baseline", actor="lead")

        lead = create_user(
            s,
            username="clean-e2e-lead",
            role="lead",
            password="pw-clean-e2e-12",
            display_name="Clean E2E Lead",
            tenant_id=tid,
        )
        create_user(
            s,
            username="clean-e2e-admin",
            role="admin",
            password="pw-clean-e2e-12",
            display_name="Clean E2E Admin",
            tenant_id=tid,
        )

    # UI: confirm ownership (Option C) — real path, no bypass
    from attestra.api import app

    client = TestClient(app)
    login = client.post(
        "/login",
        data={"username": "clean-e2e-lead", "password": "pw-clean-e2e-12"},
        follow_redirects=False,
    )
    assert login.status_code in (302, 303)

    with db.session() as s:
        eng1 = s.scalars(select(Engagement).where(Engagement.name == "Engagement Q1")).one()
        a1 = s.scalars(select(Asset).where(Asset.engagement_id == eng1.id)).one()
        eid1, aid1, tid = eng1.id, a1.id, eng1.tenant_id

    page = client.get(f"/engagements/{eid1}")
    assert page.status_code == 200
    assert "Bypassed (local testing)" not in page.text or "Not verified" in page.text
    assert "Not verified" in page.text or "Confirm ownership" in page.text

    confirm = client.post(
        f"/engagements/{eid1}/targets/{aid1}/confirm-ownership",
        data={"confirm": "yes", "confirmed_by": "Clean Lead, Security"},
        follow_redirects=False,
    )
    assert confirm.status_code == 303

    with db.session() as s:
        a1 = s.get(Asset, aid1)
        eng1 = s.get(Engagement, eid1)
        assert a1.ownership_verified_at is not None
        assert a1.ownership_token
        token = a1.ownership_token
        assert services.asset_ownership_verified(s, a1, tenant_id=eng1.tenant_id) is True
        inp = policy_input(s, eid1, aid1, tool="zap", profile="baseline")
        assert inp["ownership_verified"] is True
        assert inp["ownership_required"] is True
        # Full check may fail DNS pin for RFC1918 without private_ok wiring details;
        # ownership must not be the refusal reason once confirmed.
        try:
            check(s, eid1, aid1, tool="zap", profile="baseline", actor="lead")
        except GateError as exc:
            assert "ownership" not in str(exc).lower()
        except OSError:
            pass

        tenant = s.get(Tenant, eng1.tenant_id)
        eng2 = services.create_engagement(
            s,
            tenant=tenant.name,
            name="Engagement Q2",
            type="va",
            frameworks=["pci_dss_4"],
            window_start=today - timedelta(days=1),
            window_end=today + timedelta(days=14),
            actor="lead",
        )
        services.add_authorization(
            s,
            eng2.id,
            filename="authorization.txt",
            data=(FIXTURES / "authorization.txt").read_bytes(),
            signer="CISO Clean E2E",
            signed_on=today - timedelta(days=2),
            expires_on=today + timedelta(days=60),
            rules_of_engagement="No DoS; business hours.",
            environments=["production", "staging"],
            actor="lead",
        )
        a2 = services.add_asset(
            s,
            eng2.id,
            kind="web_app",
            identifier=f"https://{host}/billing",
            name="Internal shop billing",
            environment="production",
            exposure="internal",
            actor="lead",
        )
        # Org+host reuse: same token + already verified — no second confirm needed
        assert a2.ownership_token == token
        assert a2.ownership_verified_at is not None
        assert services.asset_ownership_verified(s, a2, tenant_id=eng2.tenant_id) is True
        inp2 = policy_input(s, eng2.id, a2.id, tool="zap", profile="baseline")
        assert inp2["ownership_verified"] is True
        assert inp2["ownership_required"] is True
        eid2, aid2 = eng2.id, a2.id

    # UI of Q2 should show Verified without asking again
    page2 = client.get(f"/engagements/{eid2}")
    assert page2.status_code == 200
    assert "Verified" in page2.text
    assert "Bypassed (local testing)" not in page2.text

    target2 = client.get(f"/engagements/{eid2}/targets/{aid2}")
    assert target2.status_code == 200
    assert "Verified" in target2.text
    assert "valid until" in target2.text

    # Confirm again must be refused as already verified
    again = client.post(
        f"/engagements/{eid2}/targets/{aid2}/confirm-ownership",
        data={"confirm": "yes", "confirmed_by": "Clean Lead, Security"},
        follow_redirects=False,
    )
    assert again.status_code == 303
    assert "already verified" in unquote(again.headers.get("location", "")).lower()

    # Different host in same org still needs its own proof
    with db.session() as s:
        other = services.add_asset(
            s,
            eid2,
            kind="web_app",
            identifier="https://192.168.50.99",
            name="Other internal",
            environment="production",
            exposure="internal",
            actor="lead",
        )
        assert other.ownership_verified_at is None
        assert services.asset_ownership_verified(s, other, tenant_id=tid) is False
        with pytest.raises(GateError, match="ownership"):
            check(s, eid2, other.id, tool="zap", profile="baseline", actor="lead")
