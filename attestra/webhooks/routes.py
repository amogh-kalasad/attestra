"""API routes: per-tenant webhook endpoints, delivery log, workflow rules."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from attestra import services
from attestra.web import data_access
from attestra.webhooks import formats
from attestra.webhooks import service as wh

router = APIRouter()


def _require(permission: str):
    from attestra.api import require

    return require(permission)


def _call(mongo_fn, principal):
    """Run ``mongo_fn(db, tenant_ids)`` with HTTP error mapping."""
    from attestra.persistence.mongo.secrets_codec import SecretCodecError

    try:
        return mongo_fn(data_access.mongo_db(), services.tenant_ids_for(None, principal))
    except SecretCodecError as e:
        raise HTTPException(503, f"webhook secret encryption unavailable: {e}") from e
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except wh.WebhookError as e:
        raise HTTPException(400, str(e)) from e


def _tenant_ok(s, principal, tenant_id: int) -> None:
    """Scope check plus row existence (``tenant_ids_for`` None = all tenants, not skip existence)."""
    allowed = services.tenant_ids_for(s, principal)
    if not data_access.tenant_exists(s, tenant_id) or (allowed is not None and tenant_id not in allowed):
        raise LookupError(f"tenant {tenant_id} not found")


class EndpointIn(BaseModel):
    tenant_id: int
    url: str
    name: str = ""
    format: str = Field("json", description=" | ".join(formats.FORMATS))
    events: list[str] = Field(default_factory=list, description="empty = all: " + ", ".join(formats.EVENTS))


class RuleIn(BaseModel):
    tenant_id: int
    action: str = Field(description=" | ".join(wh.ACTIONS))
    name: str = ""
    event: str = ""
    min_severity: str = "info"
    status: str = ""
    endpoint_id: int | None = None
    assignee: str = ""


def _ep_out(ep) -> dict:
    ep = data_access.as_obj(ep)
    return {"id": ep.id, "tenant_id": ep.tenant_id, "name": ep.name, "url": ep.url, "format": ep.format, "events": ep.events, "active": ep.active}


def _rule_out(r) -> dict:
    r = data_access.as_obj(r)
    return {"id": r.id, "tenant_id": r.tenant_id, "name": r.name, "event": r.event, "min_severity": r.min_severity,
            "status": r.status, "action": r.action, "endpoint_id": r.endpoint_id, "assignee": r.assignee, "active": r.active}


@router.get("/api/webhooks")
def list_endpoints(principal=Depends(_require("webhook.manage"))):
    def mongo_fn(mdb, allowed):
        from attestra.webhooks import mongo_service as mwh

        return [_ep_out(e) for e in mwh.list_endpoints(mdb, allowed)]

    return _call(mongo_fn, principal)


@router.post("/api/webhooks", status_code=201)
def create_endpoint(body: EndpointIn, principal=Depends(_require("webhook.manage"))):
    def mongo_fn(mdb, allowed):
        from attestra.webhooks import mongo_service as mwh

        _tenant_ok(None, principal, body.tenant_id)
        ep, secret = mwh.create_endpoint(mdb, allowed, body.tenant_id, url=body.url, actor=principal.actor,
                                         name=body.name, fmt=body.format, events=body.events)
        return {**_ep_out(ep), "secret": secret, "note": "store the secret now; it is not shown again"}

    return _call(mongo_fn, principal)


@router.delete("/api/webhooks/{wid}")
def delete_endpoint(wid: int, principal=Depends(_require("webhook.manage"))):
    def mongo_fn(mdb, allowed):
        from attestra.webhooks import mongo_service as mwh

        return _ep_out(mwh.deactivate_endpoint(mdb, allowed, wid, actor=principal.actor))

    return _call(mongo_fn, principal)


@router.get("/api/webhooks/{wid}/deliveries")
def deliveries(wid: int, principal=Depends(_require("webhook.manage"))):
    def mongo_fn(mdb, allowed):
        from attestra.webhooks import mongo_service as mwh

        rows = mwh.list_deliveries(mdb, allowed, wid, limit=200)
        return [{"id": d["id"], "event": d.get("event"), "status": d.get("status"), "attempts": d.get("attempts", 0),
                 "last_status_code": d.get("last_status_code"), "last_error": d.get("last_error", ""),
                 "next_attempt_at": d.get("next_attempt_at"), "delivered_at": d.get("delivered_at")} for d in rows]

    return _call(mongo_fn, principal)


@router.post("/api/webhooks/dispatch")
def dispatch(principal=Depends(_require("webhook.manage"))):
    def mongo_fn(mdb, allowed):
        from attestra.webhooks import mongo_service as mwh

        done = mwh.dispatch_due(mdb, tenant_ids=allowed)
        return {"attempted": len(done), "delivered": sum(1 for d in done if d.get("status") == "delivered")}

    return _call(mongo_fn, principal)


@router.get("/api/workflow-rules")
def list_rules(principal=Depends(_require("webhook.manage"))):
    def mongo_fn(mdb, allowed):
        from attestra.webhooks import mongo_service as mwh

        return [_rule_out(r) for r in mwh.list_rules(mdb, allowed)]

    return _call(mongo_fn, principal)


@router.post("/api/workflow-rules", status_code=201)
def create_rule(body: RuleIn, principal=Depends(_require("webhook.manage"))):
    def mongo_fn(mdb, allowed):
        from attestra.webhooks import mongo_service as mwh

        _tenant_ok(None, principal, body.tenant_id)
        data = body.model_dump(exclude={"tenant_id"})
        return _rule_out(mwh.create_rule(mdb, allowed, body.tenant_id, actor=principal.actor, **data))

    return _call(mongo_fn, principal)


def _deactivate_rule(rid: int, principal):
    def mongo_fn(mdb, allowed):
        from attestra.webhooks import mongo_service as mwh

        return _rule_out(mwh.deactivate_rule(mdb, allowed, rid, actor=principal.actor))

    return _call(mongo_fn, principal)


@router.delete("/api/workflow-rules/{rid}", summary="Deactivate a workflow rule")
def deactivate_rule_delete(rid: int, principal=Depends(_require("webhook.manage"))):
    """Soft-deactivate (active=False). Kept as DELETE for backward compatibility."""
    return _deactivate_rule(rid, principal)


@router.post("/api/workflow-rules/{rid}/deactivate", summary="Deactivate a workflow rule")
def deactivate_rule(rid: int, principal=Depends(_require("webhook.manage"))):
    """Soft-deactivate a workflow rule (same as DELETE; preferred name)."""
    return _deactivate_rule(rid, principal)
