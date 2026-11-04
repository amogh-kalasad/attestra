"""Session-tracked Report lookups that honour the session's tenant scope.

SQL (Postgres) enforces tenant scope with RLS; MongoSession has no RLS, so readers that
used a bare ``s.get(Report, id)`` / ``select(Report)`` must filter explicitly. Rows returned
here are the session's own objects (ORM rows or MongoRecords), so callers may still update
or delete them through the session.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from attestra.models import Engagement, Report


def session_tenant_ids(s: Any) -> frozenset[int] | None:
    ids = (getattr(s, "info", None) or {}).get("tenant_ids")
    return None if ids is None else frozenset(int(t) for t in ids)


def _in_scope(s: Any, r: Any, ids: frozenset[int] | None, cache: dict[int, int | None]) -> bool:
    if ids is None:
        return True
    eid = r.engagement_id
    if eid not in cache:
        eng = s.get(Engagement, eid)
        cache[eid] = None if eng is None else eng.tenant_id
    return cache[eid] in ids


def get_report_row(s: Any, report_id: int | None, tenant_ids: Iterable[int] | None = None) -> Report | None:
    """Report by id, or None when missing or outside ``tenant_ids`` (default: the session scope)."""
    if not report_id:
        return None
    r = s.get(Report, int(report_id))
    if r is None:
        return None
    ids = session_tenant_ids(s) if tenant_ids is None else frozenset(int(t) for t in tenant_ids)
    return r if _in_scope(s, r, ids, {}) else None


def scoped_reports(s: Any, rows: Iterable[Report]) -> list[Report]:
    """Filter report rows to the session's tenant scope."""
    ids = session_tenant_ids(s)
    cache: dict[int, int | None] = {}
    return [r for r in rows if _in_scope(s, r, ids, cache)]