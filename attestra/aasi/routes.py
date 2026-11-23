"""AASI Phase 3 FastAPI routes (recommend-only).

Prefix ``/api/aasi``. Agents recommend; humans approve. Parent mounts
``api_router`` — this module does not touch ``attestra/api.py``.

When AASI is off (``ATTESTRA_AASI``), ``GET /status`` returns ``{enabled: false}``
and all other endpoints return 404 (same advertising-avoidance pattern as
discovery and AI narratives).

HTTP handlers call injectable ``_orch()`` / ``_store()`` facades (mocked in
unit tests). Defaults wrap [[attestra/aasi/store.py#AasiStore]] and
[[attestra/aasi/orchestrator.py#AasiOrchestrator]].
"""
# @lat: [[aasi#Phase 3 FastAPI routes]]

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from attestra.auth.roles import has_permission

api_router = APIRouter(prefix="/api/aasi", tags=["aasi"])

PERM_READ = "engagement.read"
PERM_WRITE = "engagement.write"

# Orchestrator decision kinds that map onto store DECISION_KINDS.
_KIND_MAP = {
    "hypothesis": "hypothesis",
    "recommendation": "recommendation",
    "planner_outcome": "planner_outcome",
    "approval": "approval",
    "conclusion": "conclusion",
    "plan": "conclusion",
    "budget": "conclusion",
    "quality": "conclusion",
    "cancellation": "conclusion",
    "failure": "conclusion",
}


def _principal(request: Request):
    from attestra.api import get_principal

    return get_principal(request)


def _require(permission: str):
    def dep(request: Request):
        principal = _principal(request)
        if not has_permission(principal.role, permission):
            raise HTTPException(403, f"permission denied: {permission}")
        return principal

    dep.permission = permission  # type: ignore[attr-defined]
    return dep


def _actor(principal) -> str:
    return getattr(principal, "actor", None) or getattr(principal, "username", "") or "api"


def _require_aasi_enabled() -> None:
    from attestra.aasi import enabled

    if not enabled():
        raise HTTPException(404, "not found")


def _err(exc: Exception) -> HTTPException:
    from attestra import services
    from attestra.persistence.mongo.tenant import TenantAccessDenied

    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, (LookupError, TenantAccessDenied)):
        return HTTPException(404, str(exc).strip("'\""))
    if isinstance(exc, PermissionError):
        return HTTPException(403, str(exc))
    if isinstance(exc, services.ServiceError):
        msg = str(exc)
        lower = msg.lower()
        if "not found" in lower:
            return HTTPException(404, msg)
        if "not allowed" in lower or "permission" in lower or "disabled" in lower:
            return HTTPException(403, msg)
        return HTTPException(400, msg)
    msg = str(exc)
    lower = msg.lower()
    if "not found" in lower:
        return HTTPException(404, msg)
    return HTTPException(400, msg)


def _tenant_ids(s, principal):
    from attestra import services

    allowed = services.tenant_ids_for(s, principal)
    return None if allowed is None else frozenset(allowed)


def _mongo_store(s, principal):
    from attestra.aasi.store import AasiStore

    return AasiStore(tenant_ids=_tenant_ids(s, principal))


def _engagement(s, engagement_id: int, principal):
    from attestra import services

    return services.get_engagement(s, engagement_id, principal)


def _assets_seed(s, engagement_id: int, asset_ids: list[int] | None) -> list[dict[str, Any]]:
    from sqlalchemy import select

    from attestra.models import Asset

    rows = list(s.scalars(select(Asset).where(Asset.engagement_id == int(engagement_id))))
    out: list[dict[str, Any]] = []
    wanted = set(int(x) for x in asset_ids) if asset_ids else None
    for a in rows:
        if wanted is not None and int(a.id) not in wanted:
            continue
        out.append(
            {
                "id": int(a.id),
                "kind": getattr(a, "kind", None) or "ai_app",
                "test_types": list(getattr(a, "test_types", None) or []),
            }
        )
    return out


def _persist_orch_decisions(mongo, run_id: int, tenant_id: int, decisions: list[dict[str, Any]]) -> None:
    for d in decisions:
        raw_kind = str(d.get("kind") or "conclusion")
        kind = _KIND_MAP.get(raw_kind)
        if kind is None:
            continue
        payload = dict(d.get("payload") or {})
        payload.setdefault("orch_kind", raw_kind)
        try:
            mongo.append_decision(
                int(run_id),
                int(tenant_id),
                kind,
                payload,
                role=str(d.get("role") or ""),
                cites=list(d.get("cites") or []),
            )
        except Exception:  # noqa: BLE001 — best-effort; run already created
            continue


def _set_run_status(mongo, run_id: int, tenant_id: int, status: str, **extra: Any) -> dict[str, Any] | None:
    from attestra.persistence.mongo.serialization import utcnow, with_id

    fields = {"status": status, "updated_at": utcnow(), **extra}
    mongo.runs.update_one({"_id": int(run_id), "tenant_id": int(tenant_id)}, {"$set": fields})
    doc = mongo.get_run(int(run_id), int(tenant_id))
    return doc if doc is None else with_id(doc) if "_id" in doc and "id" not in doc else doc


class _DefaultStore:
    """HTTP-facing store adapter over AasiStore."""

    def get_run(self, s, engagement_id: int, run_id: str | int, *, principal):
        eng = _engagement(s, engagement_id, principal)
        mongo = _mongo_store(s, principal)
        try:
            rid = int(run_id)
        except (TypeError, ValueError) as e:
            raise LookupError("run not found") from e
        run = mongo.get_run(rid, int(eng.tenant_id))
        if run is None or int(run.get("engagement_id", -1)) != int(engagement_id):
            raise LookupError("run not found")
        return run

    def list_decisions(self, s, engagement_id: int, run_id: str | int, *, principal):
        run = self.get_run(s, engagement_id, run_id, principal=principal)
        mongo = _mongo_store(s, principal)
        return mongo.list_decisions(int(run["id"]), int(run["tenant_id"]))


class _DefaultOrch:
    """HTTP-facing orchestrator adapter: Mongo run + recommend-only loop."""

    def start_run(
        self,
        s,
        engagement_id: int,
        *,
        actor: str,
        principal,
        idempotency_key: str | None = None,
        asset_ids: list[int] | None = None,
        objective: str | None = None,
    ):
        from attestra.aasi.orchestrator import AasiOrchestrator, MemoryStore

        eng = _engagement(s, engagement_id, principal)
        mongo = _mongo_store(s, principal)
        key = (idempotency_key or "").strip() or f"aasi-{engagement_id}-{uuid.uuid4().hex}"
        run = mongo.create_run(
            int(eng.tenant_id),
            int(engagement_id),
            key,
            status="PLANNING",
            extra={"actor": actor, "objective": objective or "", "asset_ids": list(asset_ids or [])},
        )
        # Idempotent replay: skip re-orchestration when already advanced.
        if run.get("status") not in ("CREATED", "PLANNING"):
            return run

        assets = _assets_seed(s, engagement_id, asset_ids)
        test_types: list[str] = []
        for a in assets:
            test_types.extend(str(t) for t in (a.get("test_types") or []))
        if not test_types:
            test_types = ["ai_llm", "ai_agent"]

        mem = MemoryStore()
        orch = AasiOrchestrator(provider=None, store=mem, require_enabled=True)
        result = orch.run(
            {
                "tenant_id": int(eng.tenant_id),
                "engagement_id": int(engagement_id),
                "run_id": str(run["id"]),
                "objective": objective or "AASI assessment",
                "authorized_assets": assets,
                "authorized_test_types": sorted(set(test_types)),
                "coverage_gaps": ["ai_llm"] if assets else [],
            }
        )
        _persist_orch_decisions(mongo, int(run["id"]), int(eng.tenant_id), list(mem.decisions))
        updated = _set_run_status(
            mongo,
            int(run["id"]),
            int(eng.tenant_id),
            result.status,
            orch_run_id=result.run_id,
            reason=result.reason or "",
        )
        out = dict(updated or run)
        out["orchestrator"] = result.to_dict()
        return out

    def approve_recommendation(
        self,
        s,
        engagement_id: int,
        run_id: str | int,
        rec_id: str,
        *,
        actor: str,
        principal,
        note: str | None = None,
    ):
        store = _store()
        run = store.get_run(s, engagement_id, run_id, principal=principal)
        mongo = _mongo_store(s, principal)
        decision = mongo.append_decision(
            int(run["id"]),
            int(run["tenant_id"]),
            "approval",
            {
                "recommendation_id": rec_id,
                "actor": actor,
                "note": note or "",
                "model_claim_ignored": True,
            },
            role="human",
        )
        return {
            "run_id": run["id"],
            "recommendation_id": rec_id,
            "status": "approved",
            "run_status": run.get("status"),
            "decision": decision,
        }

    def cancel_run(self, s, engagement_id: int, run_id: str | int, *, actor: str, principal):
        store = _store()
        run = store.get_run(s, engagement_id, run_id, principal=principal)
        mongo = _mongo_store(s, principal)
        try:
            mongo.append_decision(
                int(run["id"]),
                int(run["tenant_id"]),
                "conclusion",
                {"cancelled": True, "actor": actor},
                role="human",
            )
        except Exception:  # noqa: BLE001
            pass
        updated = _set_run_status(mongo, int(run["id"]), int(run["tenant_id"]), "CANCELLED")
        return updated or {**run, "status": "CANCELLED"}


def _orch():
    return _DefaultOrch()


def _store():
    return _DefaultStore()


class StartRunIn(BaseModel):
    idempotency_key: str | None = Field(default=None, max_length=200)
    asset_ids: list[int] | None = None
    objective: str | None = Field(default=None, max_length=2000)


class ApproveIn(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


@api_router.get("/status")
def aasi_status(principal=Depends(_require(PERM_READ))):
    """Feature probe. Always answers; never 404s solely because AASI is off."""
    from attestra.aasi import enabled

    return {"enabled": bool(enabled())}


@api_router.post("/engagements/{engagement_id}/runs", status_code=201)
def start_run(
    engagement_id: int,
    body: StartRunIn | None = None,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    principal=Depends(_require(PERM_WRITE)),
):
    _require_aasi_enabled()
    body = body or StartRunIn()
    key = (idempotency_key or body.idempotency_key or "").strip() or None
    from attestra.web import data_access

    try:
        with data_access.session() as s:
            run = _orch().start_run(
                s,
                engagement_id,
                actor=_actor(principal),
                principal=principal,
                idempotency_key=key,
                asset_ids=body.asset_ids,
                objective=body.objective,
            )
            return run if isinstance(run, dict) else dict(run)
    except Exception as e:
        raise _err(e) from e


@api_router.get("/engagements/{engagement_id}/runs/{run_id}")
def get_run(engagement_id: int, run_id: str, principal=Depends(_require(PERM_READ))):
    _require_aasi_enabled()
    from attestra.web import data_access

    try:
        with data_access.session() as s:
            run = _store().get_run(s, engagement_id, run_id, principal=principal)
            return run if isinstance(run, dict) else dict(run)
    except Exception as e:
        raise _err(e) from e


@api_router.get("/engagements/{engagement_id}/runs/{run_id}/decisions")
def list_decisions(engagement_id: int, run_id: str, principal=Depends(_require(PERM_READ))):
    _require_aasi_enabled()
    from attestra.web import data_access

    try:
        with data_access.session() as s:
            rows = _store().list_decisions(s, engagement_id, run_id, principal=principal)
            return {"decisions": list(rows)}
    except Exception as e:
        raise _err(e) from e


@api_router.post("/engagements/{engagement_id}/runs/{run_id}/recommendations/{rec_id}/approve")
def approve_recommendation(
    engagement_id: int,
    run_id: str,
    rec_id: str,
    body: ApproveIn | None = None,
    principal=Depends(_require(PERM_WRITE)),
):
    """Human approval only — model output claiming approval has no effect here."""
    _require_aasi_enabled()
    body = body or ApproveIn()
    from attestra import audit
    from attestra.web import data_access

    try:
        with data_access.session() as s:
            out = _orch().approve_recommendation(
                s,
                engagement_id,
                run_id,
                rec_id,
                actor=_actor(principal),
                principal=principal,
                note=body.note,
            )
            audit.record(
                s,
                _actor(principal),
                "aasi.recommendation.approve",
                "aasi_run",
                None,
                engagement_id=engagement_id,
                run_id=str(run_id),
                recommendation_id=rec_id,
            )
            return out if isinstance(out, dict) else dict(out)
    except Exception as e:
        raise _err(e) from e


@api_router.post("/engagements/{engagement_id}/runs/{run_id}/cancel")
def cancel_run(engagement_id: int, run_id: str, principal=Depends(_require(PERM_WRITE))):
    _require_aasi_enabled()
    from attestra import audit
    from attestra.web import data_access

    try:
        with data_access.session() as s:
            out = _orch().cancel_run(
                s,
                engagement_id,
                run_id,
                actor=_actor(principal),
                principal=principal,
            )
            audit.record(
                s,
                _actor(principal),
                "aasi.run.cancel",
                "aasi_run",
                None,
                engagement_id=engagement_id,
                run_id=str(run_id),
            )
            return out if isinstance(out, dict) else dict(out)
    except Exception as e:
        raise _err(e) from e
