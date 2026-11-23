"""AASI Phase 3 FastAPI routes — RBAC, feature flag, idempotency, approval audit.

Orchestrator and store are faked; no Mongo or provider required.
"""

from __future__ import annotations

import contextlib
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def env(monkeypatch):
    import attestra.api as api
    import attestra.audit as audit
    from attestra import aasi, config
    from attestra.aasi import routes
    from attestra.web import data_access

    state = SimpleNamespace(
        role="lead",
        audits=[],
        runs={},
        decisions={},
        started=[],
        approved=[],
        cancelled=[],
    )

    monkeypatch.setattr(config, "AASI_ENABLED", True, raising=False)
    monkeypatch.setattr(aasi, "enabled", lambda: bool(getattr(config, "AASI_ENABLED", False)))
    monkeypatch.setattr(
        api,
        "get_principal",
        lambda request: SimpleNamespace(
            role=state.role,
            actor=f"user:{state.role}",
            username=f"user:{state.role}",
            user_id=1,
            tenant_id=1,
        ),
    )
    monkeypatch.setattr(data_access, "session", contextlib.nullcontext)
    monkeypatch.setattr(
        audit,
        "record",
        lambda s, actor, action, *a, **k: state.audits.append({"actor": actor, "action": action, **k}),
    )

    def start_run(s, engagement_id, *, actor, principal, idempotency_key=None, asset_ids=None, objective=None):
        if int(engagement_id) == 8:
            raise LookupError("engagement 8 not found")
        if idempotency_key:
            for existing in state.runs.values():
                if existing.get("idempotency_key") == idempotency_key and existing["engagement_id"] == engagement_id:
                    return existing
        rid = f"run-{len(state.runs) + 1}"
        doc = {
            "id": rid,
            "engagement_id": engagement_id,
            "status": "AWAITING_APPROVAL",
            "idempotency_key": idempotency_key,
            "asset_ids": asset_ids or [],
            "objective": objective,
            "actor": actor,
        }
        state.runs[rid] = doc
        state.started.append(doc)
        state.decisions[rid] = [
            {"id": "d1", "run_id": rid, "kind": "recommendation", "payload": {"id": "rec-1", "test_id": "T01"}},
        ]
        return doc

    def get_run(s, engagement_id, run_id, *, principal):
        if int(engagement_id) == 8:
            raise LookupError("engagement 8 not found")
        run = state.runs.get(run_id)
        if run is None or run["engagement_id"] != engagement_id:
            raise LookupError("run not found")
        return run

    def list_decisions(s, engagement_id, run_id, *, principal):
        get_run(s, engagement_id, run_id, principal=principal)
        return list(state.decisions.get(run_id, []))

    def approve_recommendation(s, engagement_id, run_id, rec_id, *, actor, principal, note=None):
        run = get_run(s, engagement_id, run_id, principal=principal)
        state.approved.append({"run_id": run_id, "rec_id": rec_id, "actor": actor, "note": note})
        return {"run_id": run_id, "recommendation_id": rec_id, "status": "approved", "run_status": run["status"]}

    def cancel_run(s, engagement_id, run_id, *, actor, principal):
        run = get_run(s, engagement_id, run_id, principal=principal)
        run["status"] = "CANCELLED"
        state.cancelled.append({"run_id": run_id, "actor": actor})
        return run

    fake_orch = SimpleNamespace(
        start_run=start_run,
        approve_recommendation=approve_recommendation,
        cancel_run=cancel_run,
    )
    fake_store = SimpleNamespace(get_run=get_run, list_decisions=list_decisions)
    monkeypatch.setattr(routes, "_orch", lambda: fake_orch)
    monkeypatch.setattr(routes, "_store", lambda: fake_store)

    app = FastAPI()
    app.include_router(routes.api_router)
    state.client = TestClient(app)
    state.routes = routes
    return state


# @lat: [[tests#AASI Phase 3 routes#Status reports enabled flag]]
def test_status_enabled_true(env):
    r = env.client.get("/api/aasi/status")
    assert r.status_code == 200
    assert r.json() == {"enabled": True}


def test_status_enabled_false_when_off(env, monkeypatch):
    from attestra import config

    monkeypatch.setattr(config, "AASI_ENABLED", False, raising=False)
    r = env.client.get("/api/aasi/status")
    assert r.status_code == 200
    assert r.json() == {"enabled": False}


# @lat: [[tests#AASI Phase 3 routes#Mutating routes 404 when off]]
def test_mutating_404_when_aasi_off(env, monkeypatch):
    from attestra import config

    monkeypatch.setattr(config, "AASI_ENABLED", False, raising=False)
    assert env.client.post("/api/aasi/engagements/7/runs", json={}).status_code == 404
    assert env.client.get("/api/aasi/engagements/7/runs/run-1").status_code == 404
    assert env.client.get("/api/aasi/engagements/7/runs/run-1/decisions").status_code == 404
    assert (
        env.client.post("/api/aasi/engagements/7/runs/run-1/recommendations/rec-1/approve", json={}).status_code
        == 404
    )
    assert env.client.post("/api/aasi/engagements/7/runs/run-1/cancel").status_code == 404
    assert env.started == [] and env.approved == [] and env.cancelled == []


# @lat: [[tests#AASI Phase 3 routes#Idempotent start]]
def test_start_run_and_idempotency_header(env):
    r = env.client.post(
        "/api/aasi/engagements/7/runs",
        json={"objective": "cover ai_llm gaps"},
        headers={"Idempotency-Key": "k-1"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["id"] == "run-1"
    assert body["idempotency_key"] == "k-1"
    again = env.client.post(
        "/api/aasi/engagements/7/runs",
        json={"idempotency_key": "ignored-when-header"},
        headers={"Idempotency-Key": "k-1"},
    )
    assert again.status_code == 201
    assert again.json()["id"] == "run-1"
    assert len(env.started) == 1


def test_start_run_idempotency_body(env):
    r = env.client.post("/api/aasi/engagements/7/runs", json={"idempotency_key": "body-key"})
    assert r.status_code == 201
    again = env.client.post("/api/aasi/engagements/7/runs", json={"idempotency_key": "body-key"})
    assert again.json()["id"] == r.json()["id"]
    assert len(env.started) == 1


def test_get_run_and_decisions(env):
    rid = env.client.post("/api/aasi/engagements/7/runs", json={}).json()["id"]
    r = env.client.get(f"/api/aasi/engagements/7/runs/{rid}")
    assert r.status_code == 200 and r.json()["id"] == rid
    d = env.client.get(f"/api/aasi/engagements/7/runs/{rid}/decisions")
    assert d.status_code == 200
    assert d.json()["decisions"][0]["kind"] == "recommendation"


def test_cross_tenant_engagement_404(env):
    assert env.client.post("/api/aasi/engagements/8/runs", json={}).status_code == 404
    assert env.client.get("/api/aasi/engagements/8/runs/x").status_code == 404


def test_missing_run_404(env):
    assert env.client.get("/api/aasi/engagements/7/runs/missing").status_code == 404


# @lat: [[tests#AASI Phase 3 routes#Viewers read writers mutate]]
@pytest.mark.parametrize("role", ["client_viewer", "reviewer", "auditor"])
def test_viewer_may_read_not_mutate(env, role):
    rid = env.client.post("/api/aasi/engagements/7/runs", json={}).json()["id"]
    env.role = role
    assert env.client.get("/api/aasi/status").status_code == 200
    assert env.client.get(f"/api/aasi/engagements/7/runs/{rid}").status_code == 200
    assert env.client.get(f"/api/aasi/engagements/7/runs/{rid}/decisions").status_code == 200
    assert env.client.post("/api/aasi/engagements/7/runs", json={}).status_code == 403
    assert env.client.post(f"/api/aasi/engagements/7/runs/{rid}/recommendations/rec-1/approve", json={}).status_code == 403
    assert env.client.post(f"/api/aasi/engagements/7/runs/{rid}/cancel").status_code == 403
    assert env.approved == [] and env.cancelled == []


@pytest.mark.parametrize("role", ["tester", "lead", "admin"])
def test_writer_roles_can_approve_and_cancel(env, role):
    env.role = "lead"
    rid = env.client.post("/api/aasi/engagements/7/runs", json={}).json()["id"]
    env.audits.clear()
    env.role = role
    a = env.client.post(f"/api/aasi/engagements/7/runs/{rid}/recommendations/rec-1/approve", json={"note": "ok"})
    assert a.status_code == 200, a.text
    assert a.json()["status"] == "approved"
    assert any(x["action"] == "aasi.recommendation.approve" for x in env.audits)
    c = env.client.post(f"/api/aasi/engagements/7/runs/{rid}/cancel")
    assert c.status_code == 200 and c.json()["status"] == "CANCELLED"
    assert any(x["action"] == "aasi.run.cancel" for x in env.audits)


def test_api_router_name_for_parent_mount():
    from attestra.aasi.routes import api_router

    assert api_router.prefix == "/api/aasi"
