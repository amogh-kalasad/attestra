"""Penetration-testing coverage honesty (Phase 3 lightweight snapshot).

Tracks checklist and automated-execution coverage separately from vulnerability
counts. Deeper endpoint/param/role engines land in Phase 4.
"""

from __future__ import annotations

from attestra.automated_vapt.coverage.models import CoverageSnapshot
from attestra.automated_vapt.coverage.snapshot import build_coverage_snapshot
from attestra.automated_vapt.testing.coverage_matrix import (
    PHASE3_COVERAGE,
    deferred_capabilities,
    implemented_test_ids,
)

__all__ = [
    "CoverageSnapshot",
    "PHASE3_COVERAGE",
    "build_coverage_snapshot",
    "deferred_capabilities",
    "implemented_test_ids",
]
