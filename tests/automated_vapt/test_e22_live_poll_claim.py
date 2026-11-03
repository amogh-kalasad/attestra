"""E22: live-status polling payload + atomic automated execution claim for worker."""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from attestra import config, db, services
from attestra.api import app
from attestra.automated_vapt.core import orchestrator as orch
from attestra.auth.keys import create_api_key, create_user


@pytest.fixture
def elite_flag(monkeypatch):
    monkeypatch.setattr(config, "AUTOMATED_VAPT_ENABLED", True)


@pytest.fixture
def eng_with_asset(fresh_db, elite_flag):
    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s,
            tenant="LivePoll Client",
            name="LivePoll Eng",
            type="vapt",
            frameworks=["pci_dss_4"],
            window_start=today - timedelta(days=1),
            window_end=today + timedelta(days=30),
            actor="tester",
        )
        services.add_authorization(
            s,
            e.id,
            filename="roe.txt",
            data=b"authorized",
            signer="Client",
            signed_on=today - timedelta(days=1),
            expires_on=today + timedelta(days=30),
            rules_of_engagement="Local only.",
            environments=["dev", "staging"],
            actor="tester",
        )
        a = services.add_asset(
            s,
            e.id,
            kind="web_app",
            identifier="http://localhost:8765/",
            name="Local mock",
            environment="dev",
            actor="tester",
        )
        # API principal for this tenant
        u = create_user(s, username="livepoll-lead", role="lead", password="pw-1234567890", display_name="LP")
        u.tenant_id = e.tenant_id
        _, key = create_api_key(s, u)
        return {
            "engagement_id": e.id,
            "asset_id": a.id,
            "tenant_id": e.tenant_id,
            "api_key": key,
        }


def test_claim_queued_execution_atomic(eng_with_asset):
    eid = eng_with_asset["engagement_id"]
    aid = eng_with_asset["asset_id"]
    with db.session() as s:
        ex = orch.create_execution(
            s,
            engagement_id=eid,
            asset_id=aid,
            test_case_ids=["T01"],
            actor="tester",
            principal=None,
            profile="baseline",
            allow_private=True,
        )
        xid = ex.id
        assert ex.status == "QUEUED"

    with db.session() as s:
        claimed = orch.claim_queued_execution(s, worker_id="w-test")
        assert claimed is not None
        assert claimed.id == xid
        assert claimed.status == "RUNNING"
        assert claimed.started_at is not None
        # second claim finds nothing
        assert orch.claim_queued_execution(s, worker_id="w-other") is None


def test_ui_run_does_not_execute_inline(eng_with_asset):
    eid = eng_with_asset["engagement_id"]
    aid = eng_with_asset["asset_id"]
    with db.session() as s:
        ex = orch.create_execution(
            s,
            engagement_id=eid,
            asset_id=aid,
            test_case_ids=["T01"],
            actor="tester",
            principal=None,
            profile="baseline",
            allow_private=True,
        )
        xid = ex.id

    c = TestClient(app)
    c.post("/login", data={"username": "livepoll-lead", "password": "pw-1234567890"}, follow_redirects=False)
    r = c.post(f"/engagements/{eid}/automated-vapt/executions/{xid}/run", follow_redirects=False)
    assert r.status_code in (303, 302)
    with db.session() as s:
        ex = orch.get_execution(s, xid, principal=None)
        assert ex.status == "QUEUED"  # still queued; worker would claim


def test_live_status_endpoint(eng_with_asset):
    eid = eng_with_asset["engagement_id"]
    aid = eng_with_asset["asset_id"]
    key = eng_with_asset["api_key"]
    with db.session() as s:
        orch.create_execution(
            s,
            engagement_id=eid,
            asset_id=aid,
            test_case_ids=["T01"],
            actor="tester",
            principal=None,
            profile="baseline",
            allow_private=True,
        )
    c = TestClient(app)
    r = c.get(f"/api/engagements/{eid}/live-status", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["engagement_id"] == eid
    assert "scans" in data and "automated" in data and "worker" in data and "active" in data
    assert any(a["status"] == "QUEUED" for a in data["automated"])
    # no secrets-looking keys
    blob = str(data).lower()
    assert "bearer " not in blob
    assert "password" not in blob


def test_api_run_is_nonblocking(eng_with_asset):
    eid = eng_with_asset["engagement_id"]
    aid = eng_with_asset["asset_id"]
    key = eng_with_asset["api_key"]
    with db.session() as s:
        ex = orch.create_execution(
            s,
            engagement_id=eid,
            asset_id=aid,
            test_case_ids=["T01"],
            actor="tester",
            principal=None,
            profile="baseline",
            allow_private=True,
        )
        xid = ex.id
    c = TestClient(app)
    r = c.post(f"/api/automated-vapt/executions/{xid}/run", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "QUEUED"
    assert body.get("queued_for_worker") is True
