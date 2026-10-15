"""API routes: per-tenant webhook endpoints, delivery log, workflow rules."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from attestra import db, services
from attestra.models import WebhookDelivery, WebhookEndpoint, WorkflowRule
from attestra.webhooks import formats
from attestra.webhooks import service as wh

router = APIRouter()


def _require(permission: str):
    from attestra.api import require

    return require(permission)


def _call(fn):
    try:
        with db.session() as s:
            return fn(s)
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except wh.WebhookError as e:
        raise HTTPException(400, str(e)) from e


def _tenant_ok(s, principal, tenant_id: int) -> None:
    allowed = services.tenant_ids_for(s, principal)
    if allowed is not None and tenant_id not in allowed:
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


def _ep_out(ep: WebhookEndpoint) -> dict:
    return {"id": ep.id, "tenant_id": ep.tenant_id, "name": ep.name, "url": ep.url, "format": ep.format, "events": ep.events, "active": ep.active}


def _rule_out(r: WorkflowRule) -> dict:
    return {"id": r.id, "tenant_id": r.tenant_id, "name": r.name, "event": r.event, "min_severity": r.min_severity,
            "status": r.status, "action": r.action, "endpoint_id": r.endpoint_id, "assignee": r.assignee, "active": r.active}


@router.get("/api/webhooks")
def list_endpoints(principal=Depends(_require("webhook.manage"))):
    def fn(s):
        allowed = services.tenant_ids_for(s, principal)
        q = select(WebhookEndpoint).order_by(WebhookEndpoint.id)
        if allowed is not None:
            q = q.where(WebhookEndpoint.tenant_id.in_(allowed))
        return [_ep_out(e) for e in s.scalars(q)]

    return _call(fn)


@router.post("/api/webhooks", status_code=201)
def create_endpoint(body: EndpointIn, principal=Depends(_require("webhook.manage"))):
    def fn(s):
        _tenant_ok(s, principal, body.tenant_id)
        ep = wh.create_endpoint(s, body.tenant_id, url=body.url, actor=principal.actor, name=body.name, fmt=body.format, events=body.events)
        return {**_ep_out(ep), "secret": ep.secret, "note": "store the secret now; it is not shown again"}

    return _call(fn)


@router.delete("/api/webhooks/{wid}")
def delete_endpoint(wid: int, principal=Depends(_require("webhook.manage"))):
    def fn(s):
        ep = s.get(WebhookEndpoint, wid)
        if not ep:
            raise LookupError(f"webhook {wid} not found")
        _tenant_ok(s, principal, ep.tenant_id)
        return _ep_out(wh.deactivate_endpoint(s, wid, actor=principal.actor))

    return _call(fn)


@router.get("/api/webhooks/{wid}/deliveries")
def deliveries(wid: int, principal=Depends(_require("webhook.manage"))):
    def fn(s):
        ep = s.get(WebhookEndpoint, wid)
        if not ep:
            raise LookupError(f"webhook {wid} not found")
        _tenant_ok(s, principal, ep.tenant_id)
        rows = s.scalars(select(WebhookDelivery).where(WebhookDelivery.endpoint_id == wid).order_by(WebhookDelivery.id.desc()).limit(200))
        return [{"id": d.id, "event": d.event, "status": d.status, "attempts": d.attempts, "last_status_code": d.last_status_code,
                 "last_error": d.last_error, "next_attempt_at": d.next_attempt_at, "delivered_at": d.delivered_at} for d in rows]

    return _call(fn)


@router.post("/api/webhooks/dispatch")
def dispatch(principal=Depends(_require("webhook.manage"))):
    def fn(s):
        done = wh.dispatch_due(s, tenant_ids=services.tenant_ids_for(s, principal))
        return {"attempted": len(done), "delivered": sum(1 for d in done if d.status == "delivered")}

    return _call(fn)


@router.get("/api/workflow-rules")
def list_rules(principal=Depends(_require("webhook.manage"))):
    def fn(s):
        allowed = services.tenant_ids_for(s, principal)
        q = select(WorkflowRule).order_by(WorkflowRule.id)
        if allowed is not None:
            q = q.where(WorkflowRule.tenant_id.in_(allowed))
        return [_rule_out(r) for r in s.scalars(q)]

    return _call(fn)


@router.post("/api/workflow-rules", status_code=201)
def create_rule(body: RuleIn, principal=Depends(_require("webhook.manage"))):
    def fn(s):
        _tenant_ok(s, principal, body.tenant_id)
        data = body.model_dump(exclude={"tenant_id"})
        return _rule_out(wh.create_rule(s, body.tenant_id, actor=principal.actor, **data))

    return _call(fn)


@router.delete("/api/workflow-rules/{rid}")
def delete_rule(rid: int, principal=Depends(_require("webhook.manage"))):
    def fn(s):
        r = s.get(WorkflowRule, rid)
        if not r:
            raise LookupError(f"rule {rid} not found")
        _tenant_ok(s, principal, r.tenant_id)
        r.active = False
        return _rule_out(r)

    return _call(fn)
