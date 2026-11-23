"""Penetration-testing coverage honesty (Phase 3 snapshot + Phase 4 ledger).

Tracks checklist and automated-execution coverage separately from vulnerability
counts. Phase 4 adds a per-case execution ledger on AutomatedTestExecution.result_json
and API/report surfacing via build_coverage_ledger / collect_engagement_ledger.
"""

from __future__ import annotations

from attestra.automated_vapt.coverage.ledger import (
    AI_COVERAGE_CATEGORIES,
    ALLOWED_ORIGINS,
    ORIGIN_AASI,
    ORIGIN_CATALOGUE,
    CoverageLedgerEntry,
    build_coverage_ledger,
    collect_engagement_ledger,
    entries_from_case_result,
    is_ai_coverage_category,
    merge_ledger,
    normalize_coverage_category,
    normalize_origin,
)
from attestra.automated_vapt.coverage.models import CoverageSnapshot
from attestra.automated_vapt.coverage.snapshot import build_coverage_snapshot
from attestra.automated_vapt.testing.coverage_matrix import (
    PHASE3_COVERAGE,
    deferred_capabilities,
    implemented_test_ids,
)

__all__ = [
    "AI_COVERAGE_CATEGORIES",
    "ALLOWED_ORIGINS",
    "ORIGIN_AASI",
    "ORIGIN_CATALOGUE",
    "CoverageLedgerEntry",
    "CoverageSnapshot",
    "PHASE3_COVERAGE",
    "build_coverage_ledger",
    "build_coverage_snapshot",
    "collect_engagement_ledger",
    "deferred_capabilities",
    "entries_from_case_result",
    "implemented_test_ids",
    "is_ai_coverage_category",
    "merge_ledger",
    "normalize_coverage_category",
    "normalize_origin",
]
