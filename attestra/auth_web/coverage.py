"""Coverage summary for authenticated website security testing."""
# @lat: [[architecture#Authenticated website testing]]

from __future__ import annotations

from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra.models import (
    AUTH_PROFILE_STATUSES,
    CHECKLIST_STATUSES,
    ELEMENT_TEST_STATUSES,
    ROUTE_VISIT_STATUSES,
    SEVERITIES,
    AuthChecklistItem,
    AuthCredentialProfile,
    AuthElementInventory,
    AuthRouteInventory,
    Finding,
)

EXCLUSIONS_NOTE = (
    "Skipped, blocked, and out-of-scope routes are not counted as covered or passed. "
    "Checklist items must not be marked passed merely because they were skipped."
)


def _route_bucket(rows: list[AuthRouteInventory]) -> dict:
    by_status = Counter(r.status for r in rows)
    discovered = len(rows)
    visited = by_status.get("visited", 0)
    coverage_pct = round((visited / discovered) * 100.0, 1) if discovered else 0.0
    return {
        "discovered": discovered,
        "visited": visited,
        "skipped": by_status.get("skipped", 0),
        "failed": by_status.get("failed", 0),
        "blocked": by_status.get("blocked", 0),
        # Remaining unvisited discoveries (status still "discovered").
        "unvisited": by_status.get("discovered", 0),
        "coverage_pct": coverage_pct,
    }


def coverage_summary(
    session: Session,
    engagement_id: int,
    asset_id: int | None = None,
) -> dict:
    """Aggregate route, element, checklist, profile, and finding coverage for an engagement."""
    route_q = select(AuthRouteInventory).where(AuthRouteInventory.engagement_id == engagement_id)
    if asset_id is not None:
        route_q = route_q.where(AuthRouteInventory.asset_id == asset_id)
    routes = list(session.scalars(route_q).all())

    route_summary = _route_bucket(routes)
    by_role: dict[str, dict] = {}
    roles = sorted({(r.role_name or "") for r in routes})
    for role in roles:
        role_rows = [r for r in routes if (r.role_name or "") == role]
        key = role or "(anonymous)"
        by_role[key] = _route_bucket(role_rows)
    route_summary["by_role"] = by_role

    route_ids = [r.id for r in routes]
    if route_ids:
        elements = list(
            session.scalars(
                select(AuthElementInventory).where(AuthElementInventory.route_id.in_(route_ids))
            ).all()
        )
    else:
        elements = []
    el_status = Counter(e.test_status for e in elements)
    tested = sum(el_status[s] for s in ELEMENT_TEST_STATUSES if s != "not_tested")
    elements_summary = {
        "discovered": len(elements),
        "tested": tested,
        "by_status": {s: el_status.get(s, 0) for s in ELEMENT_TEST_STATUSES},
    }

    checklist_rows = list(
        session.scalars(
            select(AuthChecklistItem).where(AuthChecklistItem.engagement_id == engagement_id)
        ).all()
    )
    cl_status = Counter(c.status for c in checklist_rows)
    # Never treat a non-passed status as passed (no skipped→passed folding).
    checklist_summary = {
        "total": len(checklist_rows),
        "by_status": {s: cl_status.get(s, 0) for s in CHECKLIST_STATUSES},
        "passed": cl_status.get("passed", 0),
    }

    profiles = list(
        session.scalars(
            select(AuthCredentialProfile).where(AuthCredentialProfile.engagement_id == engagement_id)
        ).all()
    )
    if asset_id is not None:
        profiles = [p for p in profiles if p.asset_id is None or p.asset_id == asset_id]
    pr_status = Counter(p.status for p in profiles)
    auth_profiles = {
        "total": len(profiles),
        "by_status": {s: pr_status.get(s, 0) for s in AUTH_PROFILE_STATUSES},
    }

    finding_q = select(Finding).where(Finding.engagement_id == engagement_id)
    if asset_id is not None:
        finding_q = finding_q.where(Finding.asset_id == asset_id)
    findings = list(session.scalars(finding_q).all())
    sev = Counter(f.severity for f in findings)
    findings_by_severity = {s: sev.get(s, 0) for s in SEVERITIES}

    incomplete = bool(
        route_summary["discovered"] == 0
        or route_summary["visited"] < route_summary["discovered"]
        or route_summary["failed"]
        or route_summary["blocked"]
        or checklist_summary["by_status"].get("not_started", 0)
        or checklist_summary["by_status"].get("not_tested", 0)
        or checklist_summary["by_status"].get("blocked", 0)
        or auth_profiles["by_status"].get("pending", 0)
        or auth_profiles["by_status"].get("invalid", 0)
        or auth_profiles["by_status"].get("blocked_mfa", 0)
        or auth_profiles["by_status"].get("blocked_sso", 0)
    )

    return {
        "engagement_id": engagement_id,
        "asset_id": asset_id,
        "routes": route_summary,
        "elements": elements_summary,
        "checklist": checklist_summary,
        "findings_by_severity": findings_by_severity,
        "auth_profiles": auth_profiles,
        "exclusions_note": EXCLUSIONS_NOTE,
        "incomplete": incomplete,
        # Status vocabularies for callers/UI (read-only hints).
        "route_statuses": list(ROUTE_VISIT_STATUSES),
        "checklist_statuses": list(CHECKLIST_STATUSES),
    }
