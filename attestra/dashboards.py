"""Staff metrics dashboard: open severity, SLA ageing, trend, site grades."""
# @lat: [[interfaces#Web dashboard#Metrics dashboard]]

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from attestra.models import OPEN_STATUSES, Finding
from attestra.services import list_tenant_sites, scoped

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_DUE_SOON_DAYS = 7
_TREND_WEEKS = 8
_SITE_GRADE_LIMIT = 5


def _empty_open_by_severity() -> dict[str, int]:
    return {sev: 0 for sev in _SEVERITIES}


def _week_start(day: date) -> date:
    """Monday of the ISO week containing ``day``."""
    return day - timedelta(days=day.weekday())


def _as_date(value: date | datetime | None) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).date()
    return value


def summary_for_principal(
    session: Session,
    principal,
    *,
    today: date | None = None,
    trend_weeks: int = _TREND_WEEKS,
    site_limit: int = _SITE_GRADE_LIMIT,
) -> dict[str, Any]:
    """Aggregate open findings, SLA buckets, weekly trend, and site grades for a principal.

    Scoped to engagements the principal can see. Empty tenants return zero counts
    and empty site lists.
    """
    # @lat: [[interfaces#Web dashboard#Metrics dashboard]]
    today = today or date.today()
    due_soon_end = today + timedelta(days=_DUE_SOON_DAYS)
    weeks_n = max(1, int(trend_weeks))
    site_n = max(0, int(site_limit))

    open_by_severity = _empty_open_by_severity()
    sla_ageing = {"ok": 0, "due_soon": 0, "overdue": 0}
    opened_by_week: dict[date, int] = defaultdict(int)

    findings = list(session.scalars(scoped(session, Finding, principal)))
    open_findings = [f for f in findings if f.status in OPEN_STATUSES]

    for f in open_findings:
        sev = (f.severity or "info").lower()
        if sev not in open_by_severity:
            open_by_severity[sev] = 0
        open_by_severity[sev] += 1

        due = f.sla_due
        if due is None:
            sla_ageing["ok"] += 1
        elif due < today:
            sla_ageing["overdue"] += 1
        elif due <= due_soon_end:
            sla_ageing["due_soon"] += 1
        else:
            sla_ageing["ok"] += 1

    # Inflow trend: findings first seen in each of the last N calendar weeks.
    this_monday = _week_start(today)
    week_starts = [this_monday - timedelta(weeks=i) for i in range(weeks_n - 1, -1, -1)]
    week_set = set(week_starts)
    for f in findings:
        seen = _as_date(f.first_seen)
        if seen is None:
            continue
        ws = _week_start(seen)
        if ws in week_set:
            opened_by_week[ws] += 1

    weeks = [{"week_start": ws.isoformat(), "opened": int(opened_by_week.get(ws, 0))} for ws in week_starts]

    current_open = sum(open_by_severity.values())
    # Previous snapshot proxy: open findings that already existed before this week.
    previous_open = sum(1 for f in open_findings if (_as_date(f.first_seen) or today) < this_monday)
    trend = {
        "weeks": weeks,
        "current_open": current_open,
        "previous_open": previous_open,
        "delta": current_open - previous_open,
    }

    sites = list_tenant_sites(session, principal, sort="grade")
    graded = [r for r in sites if r.get("grade")]
    # list_tenant_sites default sort is worst grade first.
    worst = graded[:site_n]
    best = list(reversed(graded[-site_n:])) if graded else []
    site_grades = {
        "worst": [
            {
                "asset_id": r["asset_id"],
                "engagement_id": r["engagement_id"],
                "name": r["name"] or r["identifier"],
                "identifier": r["identifier"],
                "grade": r["grade"],
                "score": r["score"],
                "url": r["url"],
                "open_by_sev": r["open_by_sev"],
            }
            for r in worst
        ],
        "best": [
            {
                "asset_id": r["asset_id"],
                "engagement_id": r["engagement_id"],
                "name": r["name"] or r["identifier"],
                "identifier": r["identifier"],
                "grade": r["grade"],
                "score": r["score"],
                "url": r["url"],
                "open_by_sev": r["open_by_sev"],
            }
            for r in best
        ],
    }

    return {
        "open_by_severity": open_by_severity,
        "sla_ageing": sla_ageing,
        "trend": trend,
        "site_grades": site_grades,
    }
