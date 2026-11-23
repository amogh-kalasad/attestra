"""Offline unit tests for AASI Phase 4 evidence-ID gate."""

from __future__ import annotations

import pytest

# @lat: [[tests#AASI Phase 4 evidence gate]]

from attestra.aasi.evidence_gate import (
    EvidenceGateError,
    assert_citations_valid,
    lookup_from_records,
)
from attestra.aasi.orchestrator import AasiOrchestrator, MemoryStore


def _record(cid: str, **overrides):
    base = {
        "id": cid,
        "tenant_id": 1,
        "engagement_id": 10,
        "kind": "evidence",
        "accessible": True,
    }
    base.update(overrides)
    return base


# @lat: [[tests#AASI Phase 4 evidence gate#Valid citations pass]]
def test_valid_citations_pass():
    lookup = lookup_from_records(
        [_record("ev-1"), _record("proof-2", kind="proof"), _record("f-3", kind="finding")]
    )
    assert_citations_valid(1, 10, ["ev-1", "proof-2", "f-3"], lookup)


# @lat: [[tests#AASI Phase 4 evidence gate#Missing citation rejected]]
def test_missing_citation_rejected():
    lookup = lookup_from_records([_record("ev-1")])
    with pytest.raises(EvidenceGateError, match="not found") as ei:
        assert_citations_valid(1, 10, ["ev-1", "ev-missing"], lookup)
    assert ei.value.reason == "not_found"
    assert ei.value.citation_id == "ev-missing"


# @lat: [[tests#AASI Phase 4 evidence gate#Tenant mismatch rejected]]
def test_tenant_mismatch_rejected():
    lookup = lookup_from_records([_record("ev-1", tenant_id=99)])
    with pytest.raises(EvidenceGateError) as ei:
        assert_citations_valid(1, 10, ["ev-1"], lookup)
    assert ei.value.reason == "tenant_mismatch"


# @lat: [[tests#AASI Phase 4 evidence gate#Engagement mismatch rejected]]
def test_engagement_mismatch_rejected():
    lookup = lookup_from_records([_record("ev-1", engagement_id=99)])
    with pytest.raises(EvidenceGateError) as ei:
        assert_citations_valid(1, 10, ["ev-1"], lookup)
    assert ei.value.reason == "engagement_mismatch"


# @lat: [[tests#AASI Phase 4 evidence gate#Deleted or expired rejected]]
def test_deleted_or_expired_rejected():
    lookup = lookup_from_records([_record("ev-del", deleted=True)])
    with pytest.raises(EvidenceGateError) as ei:
        assert_citations_valid(1, 10, ["ev-del"], lookup)
    assert ei.value.reason == "deleted"

    lookup2 = lookup_from_records([_record("ev-exp", is_expired=True)])
    with pytest.raises(EvidenceGateError) as ei2:
        assert_citations_valid(1, 10, ["ev-exp"], lookup2)
    assert ei2.value.reason == "expired"


# @lat: [[tests#AASI Phase 4 evidence gate#Not accessible rejected]]
def test_not_accessible_rejected():
    lookup = lookup_from_records([_record("ev-1", accessible=False)])
    with pytest.raises(EvidenceGateError) as ei:
        assert_citations_valid(1, 10, ["ev-1"], lookup)
    assert ei.value.reason == "not_accessible"


# @lat: [[tests#AASI Phase 4 evidence gate#Orchestrator persist_conclusion gates]]
def test_orchestrator_persist_conclusion_gates(monkeypatch):
    monkeypatch.setattr("attestra.aasi.enabled", lambda: True)
    store = MemoryStore()
    orch = AasiOrchestrator(provider=None, store=store, require_enabled=False)
    ctx = {
        "run_id": "run-gate",
        "tenant_id": 1,
        "engagement_id": 10,
        "evidence_meta": [_record("ev-ok")],
        "findings_meta": [],
        "observations": [],
    }
    # Seed last_result so rejections append.
    from attestra.aasi.orchestrator import OrchestratorResult

    orch._last_result = OrchestratorResult(status="PLANNING", run_id="run-gate")

    ok = orch.persist_conclusion(
        {
            "id": "c-ok",
            "run_id": "run-gate",
            "subject_ids": ["asset:1"],
            "conclusion_type": "hypothesis",
            "evidence_citations": ["ev-ok"],
            "recommended_action": "retest",
            "confidence": 0.5,
            "confidence_basis": "single cite",
        },
        ctx=ctx,
    )
    assert ok.id == "c-ok"
    assert any(d.get("kind") == "conclusion" for d in store.decisions)

    with pytest.raises(EvidenceGateError) as ei:
        orch.persist_conclusion(
            {
                "id": "c-bad",
                "run_id": "run-gate",
                "subject_ids": ["asset:1"],
                "conclusion_type": "validated",
                "evidence_citations": ["ev-forged"],
                "recommended_action": "report",
                "confidence": 0.9,
                "confidence_basis": "forged",
            },
            ctx=ctx,
        )
    assert ei.value.reason == "not_found"
    assert any(d.get("kind") == "conclusion_rejected" for d in store.decisions)
    assert any(r.get("reason") == "not_found" for r in orch._last_result.rejected)
