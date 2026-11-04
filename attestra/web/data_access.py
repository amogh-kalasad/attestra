"""Route data-access seam for the web UI and REST API (mongofull, web/API track).

Every read/write a route used to do inline with ``db.session()`` / ``select()`` goes
through this module, so the routes themselves hold no SQLAlchemy code and the backend
can be switched here in one place.

Backend: MongoDB only. ``session()`` yields ``db.session()`` (a ``MongoSession``) for the
domain services; identity/settings data and audit events are read from Mongo directly.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

from attestra import db


def _mdb():
    from attestra.persistence.mongo.adapters import _db

    return _db()


class MongoRow(SimpleNamespace):
    """Attribute view of a Mongo document so templates/serialisers work unchanged."""

    def __getattr__(self, name: str) -> Any:  # missing optional fields read as None
        if name.startswith("__"):
            raise AttributeError(name)
        return None


def _row(doc: dict[str, Any]) -> MongoRow:
    d = dict(doc)
    if "_id" in d:
        d.setdefault("id", d.pop("_id"))
    return MongoRow(**d)


def _find(collection: str, query: dict, *, sort: list | None = None, limit: int = 0) -> list[MongoRow]:
    cur = _mdb()[collection].find(query)
    if sort:
        cur = cur.sort(sort)
    if limit:
        cur = cur.limit(int(limit))
    return [_row(d) for d in cur]


# ------------------------------------------------------------------ unit of work
@contextmanager
def session() -> Iterator[Any]:
    """Unit of work for one request: ``db.session()`` (``MongoSession``)."""
    with db.session() as s:
        yield s


def commit(s) -> None:
    if hasattr(s, "commit"):
        s.commit()


# ------------------------------------------------------------------ identity
def _principal_from_user(user) -> Any:
    from attestra.auth.keys import Principal

    get = user.get if isinstance(user, dict) else lambda k, d=None: getattr(user, k, d)
    return Principal(
        user_id=int(get("id") if get("id") is not None else get("_id")),
        username=get("username"),
        display_name=get("display_name") or "",
        role=get("role"),
        tenant_id=get("tenant_id"),
    )


def principal_for_uid(s, uid: int):
    """Active user behind a session cookie, or None (disabled/deleted users rejected)."""
    from attestra.persistence.mongo import collections as C

    user = _mdb()[C.USERS].find_one({"_id": int(uid)})
    if not user or not user.get("active"):
        return None
    return _principal_from_user(user)


def authenticate_bearer(s, raw_key: str):
    from attestra.users import mongo_service

    return mongo_service.authenticate_api_key(_mdb(), raw_key)


def authenticate_password(s, username: str, password: str):
    from attestra.users import mongo_service

    return mongo_service.authenticate_password(_mdb(), username, password)


def tenants_for_principal(s, principal) -> list:
    """Admin: all tenants by name. Others: their home tenant only."""
    from attestra.persistence.mongo import collections as C

    if principal.role == "admin":
        return _find(C.TENANTS, {}, sort=[("name", 1)])
    if principal.tenant_id:
        return _find(C.TENANTS, {"_id": int(principal.tenant_id)})
    return []


# ------------------------------------------------------------------ engagements / single rows (services getters)
# Delegates to the stable services getters (tenant-checked when a principal is given). The
# unscoped getters return None for a missing row so existing ``if not x: 404`` call sites keep
# working; callers that already checked engagement access pass no principal.
def list_engagements(s, principal) -> list:
    """Tenant-scoped engagements, newest first (ORM objects: templates walk relationships)."""
    from attestra import services

    return services.list_engagements(s, principal)


def scoped_engagements_query(s, principal):
    from attestra import services
    from attestra.models import Engagement

    return services.scoped(s, Engagement, principal).order_by(Engagement.id.desc())


def _or_none(fn, *args):
    try:
        return fn(*args)
    except LookupError:
        return None


def get_finding(s, fid: int, principal=None):
    from attestra import services

    return _or_none(services.get_finding, s, int(fid), principal)


def get_finding_in_engagement(s, eid: int, fid: int):
    """Finding ``fid`` if it belongs to engagement ``eid`` (caller checked engagement access)."""
    f = get_finding(s, fid)
    if not f or f.engagement_id != eid:
        raise LookupError(f"finding {fid} not found")
    return f


def get_evidence(s, evid: int, principal=None):
    from attestra import services

    return _or_none(services.get_evidence, s, int(evid), principal)


def get_asset(s, aid: int, principal=None):
    from attestra import services

    return _or_none(services.get_asset, s, int(aid), principal)


def get_report(s, rid: int, principal=None):
    from attestra import services

    return _or_none(services.get_report, s, int(rid), principal)


def scoped_report(s, rid: int, principal):
    """Report visible to ``principal`` (tenant-scoped) or None."""
    return get_report(s, rid, principal)


# ------------------------------------------------------------------ evidence bytes
def evidence_bytes(path, tenant_id: int) -> bytes:
    """Tenant-checked evidence bytes (local file or ``mongo://`` GridFS sidecar); LookupError."""
    from attestra import services

    return services.read_evidence_bytes(path, int(tenant_id))


def stored_bytes(path) -> bytes:
    """Bytes behind a stored path, following ``mongo://`` sidecars (no tenant check)."""
    from attestra import services

    return services.read_stored_bytes(path)


def download_response(data: bytes, filename: str, media_type: str = "application/octet-stream"):
    """Attachment response for in-memory bytes (same Content-Disposition shape as FileResponse)."""
    from urllib.parse import quote

    from fastapi.responses import Response

    name = filename or "download"
    quoted = quote(name)
    if quoted != name:
        disp = f"attachment; filename*=utf-8''{quoted}"
    else:
        disp = f'attachment; filename="{name}"'
    return Response(content=data, media_type=media_type, headers={"Content-Disposition": disp})


# ------------------------------------------------------------------ identity/settings unit of work
def mongo_identity() -> bool:
    """Users, invites, API keys, webhooks, alert and CA settings live in Mongo (always)."""
    return True


@contextmanager
def identity_session() -> Iterator[Any]:
    """Unit of work for identity/settings routes: always ``None`` (Mongo-only).

    Callers use the ``mongo_service`` modules / settings repositories directly and pass the
    yielded ``None`` to helpers that ignore their session argument (e.g. ``services.tenant_ids_for``).
    """
    yield None


def mongo_db():
    """The live Mongo database handle (tests point it at an attestra_test_* DB)."""
    return _mdb()


def as_obj(value):
    """Wrap a Mongo dict (or list of dicts) as attribute rows; ORM objects pass through."""
    if isinstance(value, list):
        return [as_obj(v) for v in value]
    if isinstance(value, dict):
        return _row(value)
    return value


def tenant_ids_for(s, principal):
    """Tenant ids the principal may touch (None = unrestricted; Mongo memberships)."""
    from attestra import services

    return services.tenant_ids_for(s, principal)


def tenant_exists(s, tenant_id: int) -> bool:
    from attestra.persistence.mongo import collections as C

    return _mdb()[C.TENANTS].count_documents({"_id": int(tenant_id)}, limit=1) > 0


def all_tenants(s) -> list:
    """Every tenant ordered by id (admin pickers)."""
    from attestra.persistence.mongo import collections as C

    return _find(C.TENANTS, {}, sort=[("_id", 1)])


# ------------------------------------------------------------------ lists (read-only, from Mongo)
def import_runs_for_engagement(s, eid: int) -> list:
    from attestra.persistence.mongo import collections as C

    return _find(C.IMPORT_RUNS, {"engagement_id": int(eid)}, sort=[("_id", -1)])


def reports_for_engagement(s, eid: int) -> list:
    from attestra.persistence.mongo import collections as C

    return _find(C.REPORTS, {"engagement_id": int(eid)}, sort=[("_id", -1)])


def findings_for_engagement(s, eid: int) -> list:
    """Raw findings (ORM: callers such as dedup read relationships)."""
    from sqlalchemy import select

    from attestra.models import Finding

    return list(s.scalars(select(Finding).where(Finding.engagement_id == eid)))


def observations_for_finding(s, fid: int) -> list:
    from attestra.persistence.mongo import collections as C

    return _find(C.FINDING_OBSERVATIONS, {"finding_id": int(fid)}, sort=[("_id", 1)])


def evidence_for_finding(s, fid: int) -> list:
    from sqlalchemy import select

    from attestra.models import Evidence

    return list(s.scalars(select(Evidence).where(Evidence.finding_id == fid).order_by(Evidence.id)))


def proof_replays_for_finding(s, fid: int) -> list:
    from attestra.persistence.mongo import collections as C

    return _find(C.PROOF_REPLAYS, {"finding_id": int(fid)}, sort=[("_id", -1)])


# ------------------------------------------------------------------ audit (Mongo-owned)
def audit_events(s) -> list:
    """Whole audit chain, oldest first."""
    from attestra.persistence.mongo import collections as C

    return _find(C.AUDIT_EVENTS, {}, sort=[("_id", 1)])


def audit_events_for_engagement(s, eid: int, finding_ids, report_ids, *, limit: int = 500) -> list:
    """Events on the engagement, its findings and its reports, newest first."""
    finding_ids = [int(i) for i in finding_ids or []]
    report_ids = [int(i) for i in report_ids or []]
    from attestra.persistence.mongo import collections as C

    clauses: list[dict] = [{"entity": "engagement", "entity_id": int(eid)}]
    if finding_ids:
        clauses.append({"entity": "finding", "entity_id": {"$in": finding_ids}})
    if report_ids:
        clauses.append({"entity": "report", "entity_id": {"$in": report_ids}})
    return _find(C.AUDIT_EVENTS, {"$or": clauses}, sort=[("_id", -1)], limit=limit)

