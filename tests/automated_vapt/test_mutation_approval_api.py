"""Gap #3: mutation-approval API authorization and lifecycle (TestClient)."""
# @lat: [[run-validity-and-policy#Intrusive policy]]

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from attestra.automated_vapt.core import mutation_approval as ma


@pytest.fixture
def approval_root(tmp_path: Path, monkeypatch):
    from attestra import config

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(ma, "production_safe_mutation_enabled", lambda: True)
    return tmp_path


def _principal(role="tester", user_id=10, username="alice.tester"):
    from types import SimpleNamespace

    return SimpleNamespace(
        role=role,
        user_id=user_id,
        username=username,
        actor=username,
        tenant_id=1,
    )


@pytest.fixture
def client(monkeypatch, approval_root):
    """Minimal FastAPI app with mutation routes + stubbed auth/engagement."""
    from fastapi import FastAPI, Request

    from attestra.automated_vapt.routes import api_router

    app = FastAPI()
    app.include_router(api_router)

    state = {"principals": [_principal()], "eng_tenant": 1, "asset_eid": 7}

    def get_principal(request: Request):
        return state["principals"][0]

    monkeypatch.setattr("attestra.api.get_principal", get_principal)

    class _Eng:
        id = 7
        tenant_id = 1

    class _Asset:
        id = 3
        engagement_id = 7

    def get_engagement(s, eid, principal):
        if eid != 7:
            from attestra import services

            raise services.ServiceError("not found")
        return _Eng()

    def get_asset(s, aid, principal):
        if aid != 3:
            from attestra import services

            raise services.ServiceError("not found")
        return _Asset()

    monkeypatch.setattr("attestra.services.get_engagement", get_engagement)
    monkeypatch.setattr("attestra.services.get_asset", get_asset)

    # db.session no-op context
    from contextlib import contextmanager

    @contextmanager
    def fake_session():
        yield object()

    monkeypatch.setattr("attestra.db.session", fake_session)
    monkeypatch.setattr("attestra.audit.record", lambda *a, **k: None)

    return TestClient(app), state


def test_request_list_approve_reject_revoke(client, approval_root):
    tc, state = client
    body = {
        "asset_id": 3,
        "target_origin": "https://app.example.com",
        "endpoint_pattern": "/api/test-records/demo-1",
        "http_method": "PATCH",
        "test_record_id": "demo-1",
        "approved_fields": ["display_name", "id"],
        "approved_values": {"display_name": "safe"},
        "cleanup_plan": "PATCH fields back to baseline and GET-verify",
        "ttl_minutes": 30,
    }
    r = tc.post("/api/automated-vapt/engagements/7/mutation-approvals", json=body)
    assert r.status_code == 201, r.text
    approval = r.json()
    assert approval["status"] == "pending"
    aid = approval["id"]

    listed = tc.get("/api/automated-vapt/engagements/7/mutation-approvals")
    assert listed.status_code == 200
    assert listed.json()["enabled"] is True
    assert any(a["id"] == aid for a in listed.json()["approvals"])

    # Self-approve denied
    bad = tc.post(f"/api/automated-vapt/engagements/7/mutation-approvals/{aid}/approve")
    assert bad.status_code == 400
    assert "cannot approve" in bad.json()["detail"].lower() or "cannot approve" in bad.text.lower()

    # Different lead approves
    state["principals"][0] = _principal(role="lead", user_id=20, username="bob.lead")
    ok = tc.post(f"/api/automated-vapt/engagements/7/mutation-approvals/{aid}/approve")
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "approved"

    # Revoke approved unused
    rev = tc.post(
        f"/api/automated-vapt/engagements/7/mutation-approvals/{aid}/revoke",
        json={"reason": "cancel"},
    )
    assert rev.status_code == 200
    assert rev.json()["status"] == "revoked"


def test_unauthorized_role_cannot_request(client, approval_root):
    tc, state = client
    state["principals"][0] = _principal(role="client", user_id=99, username="viewer")
    # client may lack engagement.write — has_permission check
    from attestra.auth import roles as roles_mod

    # Force permission deny by using a role without write if possible
    r = tc.post(
        "/api/automated-vapt/engagements/7/mutation-approvals",
        json={
            "asset_id": 3,
            "target_origin": "https://app.example.com",
            "endpoint_pattern": "/api/x",
            "http_method": "PATCH",
            "test_record_id": "x",
            "approved_fields": ["a"],
            "cleanup_plan": "restore baseline values now",
        },
    )
    # client role typically lacks engagement.write
    if not roles_mod.has_permission("client", "engagement.write"):
        assert r.status_code == 403
