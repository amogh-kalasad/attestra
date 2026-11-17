"""A-07: candidate review API — permission, scope re-check, tenant isolation, flag gate.

Services, session and Mongo are replaced with fakes, so no database is needed.
"""
# @lat: [[attack-surface-and-platform#Candidate store and approval]]

from __future__ import annotations

import contextlib
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from attestra.discovery import candidates as dc
from attestra.discovery import pipeline
from attestra.discovery.candidates import Observation
from attestra.discovery.normalize import candidate_key
from tests.discovery._fakedb import FakeDB


@pytest.fixture
def env(monkeypatch):
    import attestra.api as api
    import attestra.audit as audit
    import attestra.runner.authorization as authz
    import attestra.services as services
    import attestra.web.data_access as data_access
    from attestra import config
    from attestra.discovery import routes

    db = FakeDB()
    state = SimpleNamespace(role="lead", added=[], audits=[], allowed_hosts={"example.com"}, db=db)
    monkeypatch.setattr(config, "DISCOVERY_ENABLED", True, raising=False)
    monkeypatch.setattr(api, "get_principal", lambda request: SimpleNamespace(role=state.role, actor=f"user:{state.role}", user_id=1))
    monkeypatch.setattr(data_access, "session", contextlib.nullcontext)

    def get_engagement(s, eid, principal=None):
        if int(eid) == 7:
            return SimpleNamespace(id=7, tenant_id=1)
        if int(eid) == 8:  # exists, but in another tenant → services raise LookupError
            raise LookupError("engagement 8 not found")
        raise LookupError("not found")

    monkeypatch.setattr(services, "get_engagement", get_engagement)
    monkeypatch.setattr(services, "tenant_ids_for", lambda s, p: {1})

    def add_asset(s, eid, **kw):
        state.added.append((eid, kw))
        return SimpleNamespace(id=55)

    monkeypatch.setattr(services, "add_asset", add_asset)
    monkeypatch.setattr(audit, "record", lambda s, actor, action, *a, **k: state.audits.append(action))
    monkeypatch.setattr(
        authz,
        "scope_for_engagement",
        lambda s, eid: authz.AuthorizedScope(
            name="t", allowed_hosts=frozenset(state.allowed_hosts), allowed_urls=(), allowed_paths=(), allowed_images=()
        ),
    )
    monkeypatch.setattr(routes, "_db", lambda: db)

    cands = pipeline.merge_observations(
        [Observation("www.example.com", "ct", "2026-11-01"), Observation("api.example.com", "subfinder", "2026-11-02")],
        apex="example.com",
        allowed_hosts=["example.com"],
    ).candidates
    dc.upsert_candidates(db, tenant_id=1, engagement_id=7, candidates=cands, actor="seed")
    other = pipeline.merge_observations([Observation("x.other.org", "ct")], apex="other.org", allowed_hosts=["other.org"]).candidates
    dc.upsert_candidates(db, tenant_id=2, engagement_id=8, candidates=other, actor="seed")

    app = FastAPI()
    app.include_router(routes.router)
    state.client = TestClient(app)
    return state


def cid(name, tenant=1, eng=7):
    return candidate_key(tenant, eng, name)


def test_disabled_flag_returns_404(env, monkeypatch):
    from attestra import config

    monkeypatch.setattr(config, "DISCOVERY_ENABLED", False, raising=False)
    assert env.client.get("/api/engagements/7/discovery/candidates").status_code == 404


def test_list_returns_only_this_engagement(env):
    r = env.client.get("/api/engagements/7/discovery/candidates")
    assert r.status_code == 200
    names = sorted(c["name"] for c in r.json()["candidates"])
    assert names == ["api.example.com", "www.example.com"]
    assert all(c["scannable"] is False for c in r.json()["candidates"])


def test_cross_tenant_engagement_404(env):
    assert env.client.get("/api/engagements/8/discovery/candidates").status_code == 404
    r = env.client.post(f"/api/engagements/8/discovery/candidates/{cid('x.other.org', 2, 8)}/approve", json={})
    assert r.status_code == 404
    assert env.added == []


def test_foreign_candidate_id_404_even_via_own_engagement(env):
    r = env.client.post(f"/api/engagements/7/discovery/candidates/{cid('x.other.org', 2, 8)}/approve", json={})
    assert r.status_code == 404
    assert env.added == []


@pytest.mark.parametrize("role", ["client_viewer", "reviewer", "auditor"])
def test_approve_requires_write_permission(env, role):
    env.role = role
    r = env.client.post(f"/api/engagements/7/discovery/candidates/{cid('www.example.com')}/approve", json={})
    assert r.status_code == 403
    assert env.added == []


def test_approve_creates_asset_with_intrusive_off(env):
    r = env.client.post(f"/api/engagements/7/discovery/candidates/{cid('www.example.com')}/approve", json={})
    assert r.status_code == 200, r.text
    assert r.json()["asset_id"] == 55
    eid, kw = env.added[0]
    assert eid == 7 and kw["identifier"] == "https://www.example.com/" and kw["intrusive_allowed"] is False
    doc = env.db[dc.COLLECTION].find_one({"_id": cid("www.example.com")})
    assert doc["status"] == "approved" and doc["asset_id"] == 55
    assert "discovery.candidate.approved" in env.audits
    again = env.client.post(f"/api/engagements/7/discovery/candidates/{cid('www.example.com')}/approve", json={})
    assert again.status_code == 409


def test_approve_refused_when_apex_left_scope(env):
    env.allowed_hosts = {"something-else.com"}
    r = env.client.post(f"/api/engagements/7/discovery/candidates/{cid('www.example.com')}/approve", json={})
    assert r.status_code == 403
    assert env.added == []
    assert env.db[dc.COLLECTION].find_one({"_id": cid("www.example.com")})["status"] == "pending"


def test_approve_bad_kind_400(env):
    r = env.client.post(f"/api/engagements/7/discovery/candidates/{cid('www.example.com')}/approve", json={"kind": "repo"})
    assert r.status_code == 400


def test_reject(env):
    r = env.client.post(f"/api/engagements/7/discovery/candidates/{cid('api.example.com')}/reject", json={"reason": "not ours"})
    assert r.status_code == 200
    assert r.json()["candidate"]["status"] == "rejected"
    assert env.added == []
    assert "discovery.candidate.rejected" in env.audits


def test_viewer_can_list_but_not_reject(env):
    env.role = "client_viewer"
    assert env.client.get("/api/engagements/7/discovery/candidates").status_code == 200
    assert env.client.post(f"/api/engagements/7/discovery/candidates/{cid('api.example.com')}/reject", json={}).status_code == 403
