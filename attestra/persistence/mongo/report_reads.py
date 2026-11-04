"""Mongo read helpers for reports, exports and compliance timelines (mongofull, reports track).

Every helper returns :class:`~attestra.persistence.mongo.read_models.DocView` rows (ORM
look-alikes) from the mirrored domain collections, scoped to one engagement:

* engagement-level helpers check the engagement exists in Mongo and, when ``tenant_id`` is
  given, that it belongs to that tenant (raises ``LookupError`` "not found" otherwise, so
  cross-tenant existence is never leaked);
* finding-id helpers only return rows for findings of that engagement, so a caller can not
  widen the scope by passing foreign finding ids.

MongoDB is the only backend: there is no SQL fallback. Report writes go through
:mod:`attestra.persistence.mongo.report_store`.
"""
from __future__ import annotations

from typing import Any, Iterable

from attestra.persistence.mongo.read_models import DocView, view_all

_CHUNK = 500


def _db():
    from attestra.persistence.mongo.adapters import _db as get

    return get()


# ------------------------------------------------------------------ scope
def engagement_doc(engagement_id: int, tenant_id: int | None = None) -> dict[str, Any]:
    """The engagement document, tenant-checked. Raises LookupError when not visible."""
    doc = _db()["engagements"].find_one({"_id": int(engagement_id)})
    if not doc or (tenant_id is not None and doc.get("tenant_id") != int(tenant_id)):
        raise LookupError(f"engagement {engagement_id} not found")
    return doc


def _finding_ids_in(engagement_id: int, ids: Iterable[int]) -> list[int]:
    wanted = sorted({int(i) for i in ids})
    if not wanted:
        return []
    out: list[int] = []
    col = _db()["findings"]
    for i in range(0, len(wanted), _CHUNK):
        q = {"_id": {"$in": wanted[i : i + _CHUNK]}, "engagement_id": int(engagement_id)}
        out.extend(int(d["_id"]) for d in col.find(q, {"_id": 1}))
    return out


def _by_finding(model: type, engagement_id: int, ids: Iterable[int], sort: list) -> list[DocView]:
    scoped = _finding_ids_in(engagement_id, ids)
    rows: list[DocView] = []
    for i in range(0, len(scoped), _CHUNK):
        rows.extend(view_all(model, {"finding_id": {"$in": scoped[i : i + _CHUNK]}}, sort=sort))
    if len(scoped) > _CHUNK:  # keep one global order across chunks
        key, direction = sort[0]
        rows.sort(key=lambda r: r._doc.get(key) or 0, reverse=direction < 0)
    return rows


# ------------------------------------------------------------------ engagement rows
def previous_engagement(tenant_id: int, before_id: int) -> DocView | None:
    from attestra.models import Engagement

    rows = view_all(
        Engagement, {"tenant_id": int(tenant_id), "_id": {"$lt": int(before_id)}}, sort=[("_id", -1)], limit=1
    )
    return rows[0] if rows else None


def findings(engagement_id: int, tenant_id: int | None = None) -> list[DocView]:
    from attestra.models import Finding

    engagement_doc(engagement_id, tenant_id)
    return view_all(Finding, {"engagement_id": int(engagement_id)}, sort=[("_id", 1)])


def scan_runs(engagement_id: int, *, newest_first: bool = False, limit: int = 0,
              tenant_id: int | None = None) -> list[DocView]:
    from attestra.models import ScanRun

    engagement_doc(engagement_id, tenant_id)
    return view_all(ScanRun, {"engagement_id": int(engagement_id)},
                    sort=[("_id", -1 if newest_first else 1)], limit=limit)


def import_runs(engagement_id: int, tenant_id: int | None = None) -> list[DocView]:
    from attestra.models import ImportRun

    engagement_doc(engagement_id, tenant_id)
    return view_all(ImportRun, {"engagement_id": int(engagement_id)}, sort=[("_id", 1)])


def reports(engagement_id: int, *, kind: str = "", framework: str | None = None, newest_first: bool = False,
            limit: int = 0, tenant_id: int | None = None) -> list[DocView]:
    from attestra.models import Report

    engagement_doc(engagement_id, tenant_id)
    q: dict[str, Any] = {"engagement_id": int(engagement_id)}
    if kind:
        q["kind"] = kind
    if framework:
        q["framework"] = framework
    return view_all(Report, q, sort=[("_id", -1 if newest_first else 1)], limit=limit)


def max_report_version(engagement_id: int, kind: str, framework: str) -> int:
    doc = _db()["reports"].find_one(
        {"engagement_id": int(engagement_id), "kind": kind, "framework": framework},
        {"version": 1}, sort=[("version", -1)],
    )
    return int(doc.get("version") or 0) if doc else 0


def report(report_id: int, tenant_ids: Iterable[int] | None = None) -> DocView | None:
    """One report; ``tenant_ids`` (None = unrestricted) filters via its engagement."""
    from attestra.models import Report

    doc = _db()["reports"].find_one({"_id": int(report_id)})
    if not doc:
        return None
    if tenant_ids is not None:
        eng = _db()["engagements"].find_one({"_id": doc.get("engagement_id")}, {"tenant_id": 1})
        if not eng or eng.get("tenant_id") not in {int(t) for t in tenant_ids}:
            return None
    return DocView(Report, doc)


# ------------------------------------------------------------------ finding children
def retests_for_findings(engagement_id: int, ids: Iterable[int], *, newest_first: bool = True) -> list[DocView]:
    from attestra.models import Retest

    return _by_finding(Retest, engagement_id, ids, [("_id", -1 if newest_first else 1)])


def observations_for_findings(engagement_id: int, ids: Iterable[int]) -> list[DocView]:
    from attestra.models import FindingObservation

    return _by_finding(FindingObservation, engagement_id, ids, [("_id", 1)])


def evidence_for_findings(engagement_id: int, ids: Iterable[int]) -> list[DocView]:
    from attestra.models import Evidence

    return _by_finding(Evidence, engagement_id, ids, [("_id", 1)])


def evidence_for_engagement(engagement_id: int, tenant_id: int | None = None) -> list[DocView]:
    engagement_doc(engagement_id, tenant_id)
    ids = [int(d["_id"]) for d in _db()["findings"].find({"engagement_id": int(engagement_id)}, {"_id": 1})]
    return evidence_for_findings(engagement_id, ids)


# ------------------------------------------------------------------ report-time mutability
class Annotatable:
    """Wrap a read-only DocView so report code can hang transient attributes on it.

    ``crossmerge.collapse`` and the report consolidation set ``cross_sources`` /
    ``effective_severity`` ... on finding objects; ORM rows accept that, DocViews do not.
    Reads fall through to the wrapped row; nothing is ever written back.
    """

    __slots__ = ("_row", "_extra")

    def __init__(self, row: Any):
        object.__setattr__(self, "_row", row)
        object.__setattr__(self, "_extra", {})

    def __getattr__(self, name: str) -> Any:
        extra = object.__getattribute__(self, "_extra")
        if name in extra:
            return extra[name]
        return getattr(object.__getattribute__(self, "_row"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        object.__getattribute__(self, "_extra")[name] = value

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Annotatable):
            return object.__getattribute__(self, "_row") == object.__getattribute__(other, "_row")
        return object.__getattribute__(self, "_row") == other

    def __hash__(self) -> int:
        return hash(object.__getattribute__(self, "_row"))

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Annotatable {object.__getattribute__(self, '_row')!r}>"


def annotatable(rows: Iterable[Any]) -> list[Any]:
    """DocViews wrapped for transient report attributes; other rows passed through."""
    return [Annotatable(r) if isinstance(r, DocView) else r for r in rows]