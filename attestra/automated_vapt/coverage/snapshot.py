"""Build a Phase 3 coverage honesty snapshot for an engagement."""
# @lat: [[architecture#World-class PT coverage honesty (Phase 3)]]

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra.automated_vapt.coverage.models import CoverageSnapshot
from attestra.models import AuthChecklistItem, AuthRouteInventory, AutomatedTestExecution

# Case outcomes that count as a successful automated execution of a test case.
_CASE_SUCCESS = frozenset({"PASSED"})
# Outcomes that demonstrate the case ran and reported a problem (not a skip).
_CASE_FAILED = frozenset({"FAILED", "FINDING"})
_CASE_SKIPPED = frozenset({"SKIPPED", "DEFERRED"})


def _cases_from_execution(ex: AutomatedTestExecution) -> list[dict[str, Any]]:
    try:
        data = json.loads(ex.result_json or "{}")
    except (TypeError, ValueError):
        return []
    cases = data.get("cases") if isinstance(data, dict) else None
    return [c for c in (cases or []) if isinstance(c, dict)]


def build_coverage_snapshot(session: Session, engagement_id: int) -> dict:
    """Aggregate checklist + route + automated-execution coverage for ``engagement_id``.

    Returns a plain dict (via [[attestra/automated_vapt/coverage/models.py#CoverageSnapshot#to_dict]])
    suitable for reports and services. Does not include vulnerability severity totals.
    """
    snap = CoverageSnapshot(engagement_id=engagement_id)

    routes = list(
        session.scalars(
            select(AuthRouteInventory).where(AuthRouteInventory.engagement_id == engagement_id)
        ).all()
    )
    by_route = Counter(r.status for r in routes)
    snap.endpoints_discovered = len(routes)
    snap.endpoints_tested = by_route.get("visited", 0)
    # Untested = still discovered, or never visited for other non-visited reasons.
    snap.endpoints_untested = max(0, snap.endpoints_discovered - snap.endpoints_tested)
    snap.tested_roles = sorted(
        {
            (r.role_name or "").strip()
            for r in routes
            if (r.role_name or "").strip() and r.status == "visited"
        }
    )

    checklist_rows = list(
        session.scalars(
            select(AuthChecklistItem).where(AuthChecklistItem.engagement_id == engagement_id)
        ).all()
    )
    cl = Counter(c.status for c in checklist_rows)
    snap.checklist_total = len(checklist_rows)
    snap.checklist_passed = cl.get("passed", 0)
    snap.checklist_failed = cl.get("failed", 0)
    snap.checklist_blocked = cl.get("blocked", 0)
    snap.checklist_skipped = cl.get("not_tested", 0)
    snap.checklist_not_started = cl.get("not_started", 0)
    snap.checklist_not_applicable = cl.get("not_applicable", 0)

    executions = list(
        session.scalars(
            select(AutomatedTestExecution).where(
                AutomatedTestExecution.engagement_id == engagement_id,
                AutomatedTestExecution.status.in_(("COMPLETED", "FAILED")),
            )
        ).all()
    )
    ok = fail = skipped = 0
    for ex in executions:
        for case in _cases_from_execution(ex):
            st = str(case.get("status") or "").upper()
            if st in _CASE_SUCCESS:
                ok += 1
            elif st in _CASE_FAILED:
                fail += 1
            elif st in _CASE_SKIPPED:
                skipped += 1
    snap.automated_cases_successful = ok
    snap.automated_cases_failed = fail
    snap.automated_cases_skipped = skipped

    snap.incomplete = bool(
        snap.endpoints_discovered == 0
        or snap.endpoints_untested > 0
        or snap.checklist_not_started
        or snap.checklist_blocked
        or snap.checklist_skipped
        or snap.automated_cases_skipped
    )
    return snap.to_dict()
