"""AASI Phase 2: coverage ledger origin + AI-tool outcome → NOT_TESTED."""

from __future__ import annotations

from attestra.automated_vapt.coverage.ledger import (
    ORIGIN_AASI,
    ORIGIN_CATALOGUE,
    CoverageLedgerEntry,
    entries_from_case_result,
    is_ai_coverage_category,
    merge_ledger,
    normalize_coverage_category,
    normalize_origin,
)
from attestra.automated_vapt.core import run_validity as rv


# @lat: [[tests#AASI Phase 2 coverage origin#Origin defaults to catalogue]]
def test_origin_defaults_to_catalogue():
    row = CoverageLedgerEntry(test_id="T01")
    assert row.origin == ORIGIN_CATALOGUE
    assert row.to_dict()["origin"] == "catalogue"


# @lat: [[tests#AASI Phase 2 coverage origin#Origin aasi accepted]]
def test_origin_aasi_accepted():
    row = CoverageLedgerEntry(test_id="AI-1", category="ai_llm", origin="aasi")
    assert row.origin == ORIGIN_AASI
    built = entries_from_case_result(
        {"test_id": "AI-1", "category": "ai_llm", "origin": "aasi", "status": "PASSED"},
        engagement_id=1,
        execution_id=9,
        asset_id=3,
    )
    assert len(built) == 1
    assert built[0].origin == ORIGIN_AASI
    assert built[0].category == "ai_llm"
    assert built[0].asset_id == 3


# @lat: [[tests#AASI Phase 2 coverage origin#Invalid origin normalized]]
def test_invalid_origin_normalized_to_catalogue():
    assert normalize_origin("") == ORIGIN_CATALOGUE
    assert normalize_origin(None) == ORIGIN_CATALOGUE
    assert normalize_origin("AGENT") == ORIGIN_CATALOGUE
    assert normalize_origin("Catalogue") == ORIGIN_CATALOGUE
    row = CoverageLedgerEntry(test_id="T02", origin="bogus")
    assert row.origin == ORIGIN_CATALOGUE


def test_ai_coverage_category_helpers():
    assert is_ai_coverage_category("ai_llm")
    assert is_ai_coverage_category("AI_AGENT")
    assert not is_ai_coverage_category("injection")
    assert normalize_coverage_category("AI_LLM") == "ai_llm"
    assert normalize_coverage_category("infrastructure") == "infrastructure"


def test_merge_dedup_considers_asset_category_origin():
    base = CoverageLedgerEntry(
        test_id="AI-1",
        category="ai_llm",
        target_endpoint="/v1/chat",
        http_method="POST",
        execution_status="PASSED",
        engagement_id=1,
        execution_id=1,
        asset_id=10,
        origin=ORIGIN_CATALOGUE,
    )
    same_key = CoverageLedgerEntry(
        test_id="AI-1",
        category="ai_llm",
        target_endpoint="/v1/chat",
        http_method="POST",
        execution_status="FINDING",
        engagement_id=1,
        execution_id=1,
        asset_id=10,
        origin=ORIGIN_CATALOGUE,
        result="updated",
    )
    other_category = CoverageLedgerEntry(
        test_id="AI-1",
        category="ai_agent",
        target_endpoint="/v1/chat",
        http_method="POST",
        execution_status="PASSED",
        engagement_id=1,
        execution_id=1,
        asset_id=10,
        origin=ORIGIN_CATALOGUE,
    )
    other_origin = CoverageLedgerEntry(
        test_id="AI-1",
        category="ai_llm",
        target_endpoint="/v1/chat",
        http_method="POST",
        execution_status="SKIPPED",
        engagement_id=1,
        execution_id=1,
        asset_id=10,
        origin=ORIGIN_AASI,
        limitation="aasi probe skipped; not full coverage",
    )
    merged = merge_ledger([base], [same_key, other_category, other_origin])
    assert len(merged) == 3
    by = {(r["category"], r["origin"]): r for r in merged}
    assert by[("ai_llm", "catalogue")]["execution_status"] == "FINDING"
    assert by[("ai_llm", "catalogue")]["result"] == "updated"
    assert ("ai_agent", "catalogue") in by
    assert ("ai_llm", "aasi") in by


def test_legacy_dict_without_origin_merges_as_catalogue():
    legacy = {
        "test_id": "T03",
        "category": "",
        "target_endpoint": "/x",
        "http_method": "GET",
        "execution_status": "PASSED",
        "execution_id": 1,
        "asset_id": None,
        "auth_context": "anonymous",
    }
    newer = CoverageLedgerEntry(
        test_id="T03",
        target_endpoint="/x",
        http_method="GET",
        execution_status="FAILED",
        execution_id=1,
        origin=ORIGIN_CATALOGUE,
    )
    merged = merge_ledger([legacy], [newer])
    assert len(merged) == 1
    assert merged[0]["execution_status"] == "FAILED"
    assert merged[0]["origin"] == ORIGIN_CATALOGUE


# @lat: [[tests#AASI Phase 2 coverage origin#AI tool failures are NOT_TESTED]]
def test_ai_tool_outcome_maps_failures_to_not_tested():
    assert rv.ai_tool_outcome_to_status(error="timeout") == "NOT_TESTED"
    assert rv.ai_tool_outcome_to_status(error=RuntimeError("boom")) == "NOT_TESTED"
    assert rv.ai_tool_outcome_to_status(raw_empty=True) == "NOT_TESTED"
    assert rv.ai_tool_outcome_to_status(refused=True) == "NOT_TESTED"
    assert rv.ai_tool_outcome_to_status(rate_limited=True) == "NOT_TESTED"
    assert rv.ai_tool_outcome_to_status(failed=True) == "NOT_TESTED"
    for status in (
        rv.ai_tool_outcome_to_status(error="x"),
        rv.ai_tool_outcome_to_status(raw_empty=True),
        rv.ai_tool_outcome_to_status(refused=True),
        rv.ai_tool_outcome_to_status(rate_limited=True),
        rv.ai_tool_outcome_to_status(failed=True),
    ):
        assert status == "NOT_TESTED"
        assert status != "PASSED"


def test_ai_tool_outcome_clean_returns_none_never_passed():
    assert rv.ai_tool_outcome_to_status() is None
    assert rv.ai_tool_outcome_to_status(error=None, raw_empty=False, refused=False) is None
    assert rv.ai_tool_outcome_to_status(error="") is None
    assert rv.ai_tool_outcome_to_status() != "PASSED"


def test_not_tested_status_gates_and_ledger_maps_to_skipped():
    assert (
        rv.gate_case_status(
            status_hint="NOT_TESTED",
            finding_candidate=False,
            case_state=rv.VALID,
        )
        == "NOT_TESTED"
    )
    rows = entries_from_case_result(
        {
            "test_id": "garak-run",
            "category": "ai_llm",
            "origin": "aasi",
            "status": "NOT_TESTED",
            "detail": "empty tool output",
        },
        engagement_id=1,
        execution_id=2,
    )
    assert len(rows) == 1
    # Phase 4 ledger vocabulary maps NOT_TESTED → SKIPPED.
    assert rows[0].execution_status == "SKIPPED"
    assert rows[0].origin == ORIGIN_AASI
    assert "not full coverage" in rows[0].limitation.lower()
