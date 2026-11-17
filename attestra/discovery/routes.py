"""Discovery candidate review API (A-07).

* ``GET  /api/engagements/{eid}/discovery/candidates`` — ``engagement.read``
* ``POST /api/engagements/{eid}/discovery/candidates/{cid}/approve`` — ``asset.write``
* ``POST /api/engagements/{eid}/discovery/candidates/{cid}/reject`` — ``asset.write``

Every route resolves the engagement through the caller's tenant scope first (cross-tenant
→ 404), returns 404 while discovery is disabled, and approval re-checks that the
candidate is still under an apex in the signed scope before creating the Asset through
``services.add_asset``. Approved assets start with ``intrusive_allowed=False``; scanning
them still goes through the normal dispatch gate (authorization, ownership, window).
INT mounts ``router`` in ``api.py``.
"""
# @lat: [[attack-surface-and-platform#Candidate store and approval]]

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from attestra.auth.roles import has_permission
from attestra.discovery import DiscoveryDisabled, discovery_enabled
from attestra.discovery import candidates as dc
from attestra.discovery.normalize import host_denied, under_apex
from attestra.persistence.mongo.tenant import SYSTEM_SCOPE, TenantAccessDenied

router = APIRouter(prefix="/api/engagements/{eid}/discovery", tags=["discovery"])

APPROVE_KINDS = ("web_app", "api", "host")


def _require(permission: str):
    def dep(request: Request):
        from attestra.api import get_principal

        principal = get_principal(request)
        if not has_permission(principal.role, permission):
            raise HTTPException(403, f"permission denied: {permission}")
        return principal

    dep.permission = permission  # type: ignore[attr-defined]  # K-03 introspection
    return dep


def _db():
    from attestra.persistence.mongo.adapters import _db as mongo_db

    return mongo_db()


def _scope_for(s, principal):
    """Principal's tenant set; ``None`` from tenant_ids_for means platform-wide (admin),
    which is passed on as the explicit SYSTEM_SCOPE (K-01)."""
    from attestra import services

    allowed = services.tenant_ids_for(s, principal)
    return SYSTEM_SCOPE if allowed is None else frozenset(allowed)


def _guard_enabled() -> None:
    if not discovery_enabled():
        raise HTTPException(404, "asset discovery is off")


def _err(exc: Exception) -> HTTPException:
    from attestra import services

    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, (LookupError, TenantAccessDenied, DiscoveryDisabled)):
        return HTTPException(404, "not found")
    if isinstance(exc, dc.CandidateError):
        return HTTPException(409, str(exc))
    if isinstance(exc, services.ServiceError):
        msg = str(exc)
        return HTTPException(403 if ("not allowed" in msg or "scope" in msg or "halted" in msg) else 400, msg)
    return HTTPException(500, "discovery error")


class ApproveIn(BaseModel):
    kind: str = Field(default="web_app")
    scheme: str = Field(default="https", pattern="^(https|http)$")
    environment: str = Field(default="production", max_length=40)
    reason: str = Field(default="", max_length=500)


class RejectIn(BaseModel):
    reason: str = Field(default="", max_length=500)


@router.get("/candidates")
def list_candidates(eid: int, status: str | None = None, principal=Depends(_require("engagement.read"))):
    _guard_enabled()
    from attestra import services
    from attestra.web import data_access

    try:
        with data_access.session() as s:
            services.get_engagement(s, eid, principal)
            return {"candidates": dc.list_candidates(_db(), tenant_ids=_scope_for(s, principal), engagement_id=eid, status=status)}
    except Exception as exc:  # noqa: BLE001
        raise _err(exc) from exc


def _still_in_scope(s, eid: int, doc: dict) -> bool:
    from attestra.runner.authorization import AuthorizationError, scope_for_engagement
    from attestra.runner.ct_suggestions import apex_in_scope

    try:
        scope = scope_for_engagement(s, eid)
    except AuthorizationError:
        return False
    apex = str(doc.get("apex") or "")
    name = str(doc.get("name") or "")
    return apex_in_scope(scope, apex) and under_apex(name, apex) and not host_denied(name, scope.deny_hosts)


@router.post("/candidates/{cid}/approve")
def approve_candidate(eid: int, cid: str, body: ApproveIn | None = None, principal=Depends(_require("asset.write"))):
    _guard_enabled()
    from attestra import audit, services
    from attestra.web import data_access

    body = body or ApproveIn()
    if body.kind not in APPROVE_KINDS:
        raise HTTPException(400, f"kind must be one of {APPROVE_KINDS}")
    try:
        with data_access.session() as s:
            eng = services.get_engagement(s, eid, principal)
            scope_ids = _scope_for(s, principal)
            doc = dc.get_candidate(_db(), cid, tenant_ids=scope_ids, engagement_id=eid)
            if int(doc.get("tenant_id", -1)) != int(eng.tenant_id):
                raise LookupError("candidate not found")
            if doc.get("status") != dc.PENDING:
                raise dc.CandidateError(f"candidate already {doc.get('status')}")
            if not doc.get("in_scope") or not _still_in_scope(s, eid, doc):
                raise services.ServiceError("candidate is not under an apex in the signed scope")
            name = str(doc["name"])
            identifier = name if body.kind == "host" else f"{body.scheme}://{name}/"
            asset = services.add_asset(
                s,
                eid,
                kind=body.kind,
                identifier=identifier,
                actor=principal.actor,
                name=name,
                environment=body.environment,
                intrusive_allowed=False,
                notes=f"Approved from discovery candidate {cid} (sources: {', '.join(doc.get('sources') or [])})"[:500],
            )
            out = dc.set_review(
                _db(), cid, tenant_ids=scope_ids, engagement_id=eid, status=dc.APPROVED,
                actor=principal.actor, reason=body.reason, asset_id=asset.id,
            )
            audit.record(s, principal.actor, "discovery.candidate.approved", "engagement", eid, candidate=cid, asset_id=asset.id, name=name)
            return {"candidate": out, "asset_id": asset.id}
    except Exception as exc:  # noqa: BLE001
        raise _err(exc) from exc


@router.post("/candidates/{cid}/reject")
def reject_candidate(eid: int, cid: str, body: RejectIn | None = None, principal=Depends(_require("asset.write"))):
    _guard_enabled()
    from attestra import audit, services
    from attestra.web import data_access

    body = body or RejectIn()
    try:
        with data_access.session() as s:
            services.get_engagement(s, eid, principal)
            out = dc.set_review(
                _db(), cid, tenant_ids=_scope_for(s, principal), engagement_id=eid, status=dc.REJECTED,
                actor=principal.actor, reason=body.reason,
            )
            audit.record(s, principal.actor, "discovery.candidate.rejected", "engagement", eid, candidate=cid)
            return {"candidate": out}
    except Exception as exc:  # noqa: BLE001
        raise _err(exc) from exc
