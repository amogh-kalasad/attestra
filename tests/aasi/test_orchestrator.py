"""Unit tests for AASI Phase 3 recommend-only orchestrator."""

from __future__ import annotations

import threading

import pytest

# @lat: [[tests#AASI Phase 3 orchestrator]]

from attestra.aasi.orchestrator import (
    AasiDisabledError,
    AasiOrchestrator,
    MemoryStore,
    SimpleBudget,
    compute_intrusive,
    is_registered_test_id,
    registered_test_ids,
)
from attestra.aasi import roles as aasi_roles

TestRecommendation = aasi_roles.TestRecommendation


def _seed(**overrides):
    base = {
        "tenant_id": 1,
        "engagement_id": 99,
        "objective": "AI assessment",
        "authorized_assets": [{"id": 7, "kind": "ai_app"}],
        "authorized_test_types": ["ai_llm", "ai_agent"],
        "coverage_gaps": ["ai_llm", "garak"],
        "observations": [],
        "findings_meta": [],
        "plan_skips": [],
    }
    base.update(overrides)
    return base


# @lat: [[tests#AASI Phase 3 orchestrator#Disabled when flag off]]
def test_run_disabled_when_flag_off(monkeypatch):
    monkeypatch.setattr("attestra.aasi.enabled", lambda: False)
    orch = AasiOrchestrator(provider=None, store=MemoryStore(), require_enabled=True)
    result = orch.run(_seed())
    assert result.status == "DISABLED"
    assert result.reason == "aasi_disabled"

    with pytest.raises(AasiDisabledError):
        orch.run(_seed(), raise_if_disabled=True)


# @lat: [[tests#AASI Phase 3 orchestrator#Stub run awaiting approval]]
def test_stub_run_produces_pending_ai_recommendations(monkeypatch):
    monkeypatch.setattr("attestra.aasi.enabled", lambda: True)
    store = MemoryStore()
    orch = AasiOrchestrator(provider=None, store=store, budget=SimpleBudget(max_roles=5))
    result = orch.run(_seed())
    assert result.status == "AWAITING_APPROVAL"
    assert result.plan is not None
    assert result.recommendations
    assert result.pending_approval
    assert all(r.test_id.lower() in {"garak", "promptfoo", "safelabs", "pyrit"} for r in result.recommendations)
    assert result.planner_payload == []  # intrusive AI adapters need approve()
    assert store.decisions
    assert any(d.get("kind") == "recommendation" for d in store.decisions)


# @lat: [[tests#AASI Phase 3 orchestrator#Approval gate ignores model claim]]
def test_approval_gate_model_claim_has_no_effect(monkeypatch):
    monkeypatch.setattr("attestra.aasi.enabled", lambda: True)

    class ClaimProvider:
        def complete_json(self, system, prompt, schema=None):
            if "Role=strategist" in system:
                return {"objectives": ["o1"], "notes": "", "asset_ids": [7]}
            if "Role=hypothesis" in system:
                return {"hypotheses": []}
            if "Role=ai_security" in system:
                return {
                    "recommendations": [
                        {
                            "hypothesis_id": "",
                            "asset_id": 7,
                            "test_id": "garak",
                            "test_type": "ai_llm",
                            "expected_evidence": [],
                            "rationale": "x",
                            "approved": True,  # model claim — must be ignored
                            "status": "approved",
                        }
                    ]
                }
            if "Role=evidence_reviewer" in system:
                return {"missing": [], "contradictory": [], "suggested_retests": []}
            if "Role=quality_reviewer" in system:
                return {"completeness": "ok", "skipped": [], "unsupported_claims": [], "notes": ""}
            return {}

    orch = AasiOrchestrator(provider=ClaimProvider(), store=MemoryStore())
    result = orch.run(_seed())
    assert result.status == "AWAITING_APPROVAL"
    assert len(result.pending_approval) == 1
    assert result.approved == []
    assert result.planner_payload == []

    rec_id = result.pending_approval[0].id
    approved = orch.approve(rec_id, actor="tester")
    assert approved is not None
    assert approved.status == "approved"
    assert orch.planner_payloads()
    assert orch.planner_payloads()[0]["test_id"] == "garak"
    assert orch.planner_payloads()[0]["origin"] == "aasi"


# @lat: [[tests#AASI Phase 3 orchestrator#Unregistered test rejected]]
def test_unregistered_test_id_rejected(monkeypatch):
    monkeypatch.setattr("attestra.aasi.enabled", lambda: True)

    class BadProvider:
        def complete_json(self, system, prompt, schema=None):
            if "Role=strategist" in system:
                return {"objectives": ["o"], "notes": "", "asset_ids": [7]}
            if "Role=hypothesis" in system:
                return {"hypotheses": []}
            if "Role=ai_security" in system:
                return {
                    "recommendations": [
                        {
                            "hypothesis_id": "",
                            "asset_id": 7,
                            "test_id": "rm_rf_root",
                            "test_type": "ai_llm",
                            "expected_evidence": [],
                            "rationale": "evil",
                        },
                        {
                            "hypothesis_id": "",
                            "asset_id": 7,
                            "test_id": "garak",
                            "test_type": "ai_llm",
                            "expected_evidence": [],
                            "rationale": "ok",
                        },
                    ]
                }
            if "Role=evidence_reviewer" in system:
                return {"missing": [], "contradictory": [], "suggested_retests": []}
            if "Role=quality_reviewer" in system:
                return {"completeness": "ok", "skipped": [], "unsupported_claims": [], "notes": ""}
            return {}

    orch = AasiOrchestrator(provider=BadProvider(), store=MemoryStore())
    result = orch.run(_seed())
    assert any(r.get("reason") == "unregistered_test_id" for r in result.rejected)
    assert all(r.test_id != "rm_rf_root" for r in result.recommendations)
    assert any(r.test_id == "garak" for r in result.recommendations)


# @lat: [[tests#AASI Phase 3 orchestrator#Unauthorized asset rejected]]
def test_unauthorized_asset_rejected(monkeypatch):
    monkeypatch.setattr("attestra.aasi.enabled", lambda: True)

    class ScopeProvider:
        def complete_json(self, system, prompt, schema=None):
            if "Role=strategist" in system:
                return {"objectives": ["o"], "notes": "", "asset_ids": [7]}
            if "Role=hypothesis" in system:
                return {"hypotheses": []}
            if "Role=ai_security" in system:
                return {
                    "recommendations": [
                        {
                            "hypothesis_id": "",
                            "asset_id": 999,  # not authorized
                            "test_id": "garak",
                            "test_type": "ai_llm",
                            "expected_evidence": [],
                            "rationale": "escalation",
                        }
                    ]
                }
            if "Role=evidence_reviewer" in system:
                return {"missing": [], "contradictory": [], "suggested_retests": []}
            if "Role=quality_reviewer" in system:
                return {"completeness": "ok", "skipped": [], "unsupported_claims": [], "notes": ""}
            return {}

    orch = AasiOrchestrator(provider=ScopeProvider(), store=MemoryStore())
    result = orch.run(_seed())
    assert any(r.get("reason") == "unauthorized_asset" for r in result.rejected)
    assert result.recommendations == []


# @lat: [[tests#AASI Phase 3 orchestrator#Budget stops role sequence]]
def test_budget_stops_role_sequence(monkeypatch):
    monkeypatch.setattr("attestra.aasi.enabled", lambda: True)
    store = MemoryStore()
    # Only one role allowed — strategist runs, then BLOCKED before hypothesis.
    orch = AasiOrchestrator(provider=None, store=store, budget=SimpleBudget(max_roles=1))
    result = orch.run(_seed())
    assert result.status == "BLOCKED"
    assert result.reason in {"max_roles", "budget_exhausted"}
    assert result.plan is not None
    assert result.hypotheses == []
    assert any(d.get("kind") == "budget" for d in store.decisions)


# @lat: [[tests#AASI Phase 3 orchestrator#Cancellation stops cleanly]]
def test_cancellation_stops_cleanly(monkeypatch):
    monkeypatch.setattr("attestra.aasi.enabled", lambda: True)
    cancel = threading.Event()
    cancel.set()
    orch = AasiOrchestrator(provider=None, store=MemoryStore(), cancel_event=cancel)
    result = orch.run(_seed())
    assert result.status == "CANCELLED"


# @lat: [[tests#AASI Phase 3 orchestrator#Registered id helpers]]
def test_registered_test_id_helpers():
    ids = registered_test_ids()
    assert "garak" in ids
    assert "promptfoo" in ids
    assert is_registered_test_id("T01")
    assert is_registered_test_id("garak")
    assert not is_registered_test_id("not-a-real-test")
    assert compute_intrusive("garak") is True
    assert compute_intrusive("T01") is False
    assert compute_intrusive("SSRF") is True


# @lat: [[tests#AASI Phase 3 orchestrator#Validate strips model approval]]
def test_validate_recommendation_recomputes_intrusive(monkeypatch):
    monkeypatch.setattr("attestra.aasi.enabled", lambda: True)
    orch = AasiOrchestrator(provider=None, store=MemoryStore(), require_enabled=False)
    fake = TestRecommendation(
        id="rec-1",
        hypothesis_id="",
        asset_id=7,
        test_id="garak",
        test_type="ai_llm",
        intrusive=False,  # model lie
        needs_approval=False,
        status="approved",
    )
    ok, rejection = orch.validate_recommendation(fake, _seed())
    assert rejection is None
    assert ok is not None
    assert ok.intrusive is True
    assert ok.needs_approval is True
    assert ok.status == "pending"
