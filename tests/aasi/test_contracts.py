"""AASI Phase 3 contract validation (hypothesis, recommendation, conclusion)."""

from __future__ import annotations

import pytest

from attestra.aasi.contracts import (
    CLAIMING_FINDING_TYPES,
    CONCLUSION_TYPES,
    ContractError,
    Conclusion,
    Hypothesis,
    TestRecommendation,
    compute_intrusive,
    is_authorized_test_type,
    is_registered_test,
)


def _hypothesis(**overrides):
    base = {
        "id": "h1",
        "run_id": "run-1",
        "tenant_id": 1,
        "engagement_id": 2,
        "asset_id": 3,
        "statement": "Prompt injection may reach the tool planner",
        "basis": "inferred",
        "evidence_ids": ["ev-1"],
        "uncertainty": 0.4,
    }
    base.update(overrides)
    return Hypothesis.from_mapping(base)


def _recommendation(**overrides):
    base = {
        "id": "r1",
        "hypothesis_id": "h1",
        "asset_id": 3,
        "registered_test_id": "T01",
        "authorized_test_type": "ai_llm",
        "expected_evidence": ["tool-call-log"],
        "rationale": "Confirm planner exposure with a registered probe",
        "approval_required": False,
    }
    base.update(overrides)
    return base


def _conclusion(**overrides):
    base = {
        "id": "c1",
        "run_id": "run-1",
        "subject_ids": ["asset:3"],
        "conclusion_type": "hypothesis",
        "evidence_citations": ["ev-1"],
        "recommended_action": "queue registered test T01",
        "confidence": 0.55,
        "confidence_basis": "single observation plus catalogue match",
    }
    base.update(overrides)
    return Conclusion.from_mapping(base)


def test_hypothesis_valid_observed_and_inferred():
    h = _hypothesis(basis="observed", uncertainty="low")
    assert h.basis == "observed"
    assert h.uncertainty == "low"
    h2 = _hypothesis(basis="inferred", uncertainty=0.0)
    assert h2.uncertainty == 0.0


def test_hypothesis_merges_observation_ids_into_evidence_ids():
    h = _hypothesis(evidence_ids=["ev-1"], observation_ids=["obs-9", "ev-1"])
    assert h.evidence_ids == ("ev-1", "obs-9")


def test_hypothesis_rejects_bad_basis_and_uncertainty():
    with pytest.raises(ContractError, match="basis"):
        _hypothesis(basis="guessed")
    with pytest.raises(ContractError, match="uncertainty"):
        _hypothesis(uncertainty=1.5)
    with pytest.raises(ContractError, match="uncertainty"):
        _hypothesis(uncertainty="")
    with pytest.raises(ContractError, match="tenant_id"):
        _hypothesis(tenant_id=0)


def test_hypothesis_validate_against_known_evidence():
    h = _hypothesis(evidence_ids=["ev-1", "ev-2"])
    h.validate_against_known({"ev-1", "ev-2", "ev-3"})
    with pytest.raises(ContractError, match="unknown evidence_ids"):
        h.validate_against_known({"ev-1"})


def test_recommendation_computes_intrusive_ignores_model_flag():
    # Model claims intrusive=False for SSRF — catalogue wins.
    payload = _recommendation(registered_test_id="SSRF", intrusive=False, approval_required=True)
    rec = TestRecommendation.from_mapping(payload, against_catalogue=True)
    assert rec.intrusive is True
    assert compute_intrusive("SSRF") is True
    assert compute_intrusive("T01") is False

    safe = TestRecommendation.from_mapping(
        _recommendation(registered_test_id="T01", intrusive=True),
        against_catalogue=True,
    )
    assert safe.intrusive is False


def test_recommendation_rejects_unregistered_and_bad_type():
    with pytest.raises(ContractError, match="unregistered"):
        TestRecommendation.from_mapping(
            _recommendation(registered_test_id="NOT_A_REAL_TEST"),
            against_catalogue=True,
        )
    with pytest.raises(ContractError, match="unauthorized test type"):
        TestRecommendation.from_mapping(
            _recommendation(authorized_test_type="not_a_type"),
            against_catalogue=True,
        )
    assert is_registered_test("garak")
    assert is_authorized_test_type("ai_agent")


def test_recommendation_requires_bool_approval_required():
    with pytest.raises(ContractError, match="approval_required"):
        TestRecommendation.from_mapping(_recommendation(approval_required="yes"))


def test_conclusion_claiming_findings_require_citations():
    for kind in sorted(CLAIMING_FINDING_TYPES):
        with pytest.raises(ContractError, match="evidence_citations"):
            _conclusion(conclusion_type=kind, evidence_citations=[])
        ok = _conclusion(conclusion_type=kind, evidence_citations=["ev-1"])
        assert ok.conclusion_type == kind


def test_conclusion_non_claiming_may_omit_citations():
    c = _conclusion(conclusion_type="inconclusive", evidence_citations=[])
    assert c.evidence_citations == ()
    assert "inconclusive" in CONCLUSION_TYPES


def test_conclusion_rejects_unknown_type_and_bad_confidence():
    with pytest.raises(ContractError, match="conclusion_type"):
        _conclusion(conclusion_type="vibes")
    with pytest.raises(ContractError, match="confidence"):
        _conclusion(confidence=2.0)
    with pytest.raises(ContractError, match="subject_ids"):
        _conclusion(subject_ids=[])


def test_conclusion_validate_against_known_rejects_unknown():
    c = _conclusion(evidence_citations=["ev-1", "ev-missing"])
    with pytest.raises(ContractError, match="unknown evidence citations"):
        c.validate_against_known({"ev-1"})
    c.validate_against_known({"ev-1", "ev-missing"})
