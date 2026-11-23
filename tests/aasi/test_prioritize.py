"""Offline unit tests for AASI Phase 4 recommendation prioritization."""

from __future__ import annotations

# @lat: [[tests#AASI Phase 4 prioritize]]

from attestra.aasi.prioritize import (
    SCORE_CONFIRMED_ADJACENCY,
    SCORE_COVERAGE_GAP,
    SCORE_DEFAULT,
    prioritize_recommendations,
    score_recommendation,
)
from attestra.aasi.roles import TestRecommendation


def _rec(**overrides) -> TestRecommendation:
    base = dict(
        id="r1",
        hypothesis_id="h1",
        asset_id=7,
        test_id="other",
        test_type="ai_llm",
        intrusive=False,
        expected_evidence=(),
        rationale="probe",
        needs_approval=False,
        status="pending",
    )
    base.update(overrides)
    return TestRecommendation(**base)


# @lat: [[tests#AASI Phase 4 prioritize#Coverage gap ranks highest]]
def test_coverage_gap_ranks_highest():
    gap = _rec(id="gap", test_id="garak", test_type="ai_llm")
    adj = _rec(id="adj", test_id="promptfoo", test_type="ai_agent", asset_id=7)
    plain = _rec(id="plain", test_id="safelabs", test_type="ai_agent", asset_id=99)
    ranked = prioritize_recommendations(
        [plain, adj, gap],
        coverage_gaps=["garak"],
        findings_meta=[{"id": "f1", "asset_id": 7, "validation": "confirmed"}],
    )
    assert [r.id for r in ranked] == ["gap", "adj", "plain"]
    assert score_recommendation(gap, coverage_gaps=["garak"]) == SCORE_COVERAGE_GAP
    assert score_recommendation(gap, coverage_gaps=["ai_llm"]) == SCORE_COVERAGE_GAP
    assert (
        score_recommendation(
            adj,
            coverage_gaps=[],
            findings_meta=[{"asset_id": 7, "validation": "confirmed"}],
        )
        == SCORE_CONFIRMED_ADJACENCY
    )
    assert score_recommendation(plain, coverage_gaps=[], findings_meta=[]) == SCORE_DEFAULT


# @lat: [[tests#AASI Phase 4 prioritize#Confirmed adjacency over default]]
def test_confirmed_adjacency_over_default():
    near = _rec(id="near", test_id="pyrit", asset_id=3)
    far = _rec(id="far", test_id="pyrit", asset_id=9)
    ranked = prioritize_recommendations(
        [far, near],
        coverage_gaps=[],
        confirmed_finding_assets=[3],
    )
    assert [r.id for r in ranked] == ["near", "far"]


# @lat: [[tests#AASI Phase 4 prioritize#Stable for equal scores]]
def test_stable_for_equal_scores():
    a = _rec(id="a", test_id="x", asset_id=1)
    b = _rec(id="b", test_id="y", asset_id=2)
    ranked = prioritize_recommendations([a, b], coverage_gaps=[], findings_meta=[])
    assert [r.id for r in ranked] == ["a", "b"]


# @lat: [[tests#AASI Phase 4 prioritize#Mapping and contract field aliases]]
def test_mapping_and_contract_field_aliases():
    payload = {
        "id": "c1",
        "registered_test_id": "garak",
        "authorized_test_type": "ai_llm",
        "asset_id": 5,
    }
    assert score_recommendation(payload, coverage_gaps=["garak"]) == SCORE_COVERAGE_GAP
    assert score_recommendation(
        {"id": "c2", "test_id": "z", "asset_id": 5},
        coverage_gaps=[],
        findings_meta=[{"asset_id": 5, "status": "validated"}],
    ) == SCORE_CONFIRMED_ADJACENCY
