"""API routes for ticket sync and tracker webhooks (Step 7.2)."""

from __future__ import annotations

import json
import os

from fastapi import APIRouter, Depends, HTTPException, Request

from attestra import db
from attestra.integrations import tickets

router = APIRouter()


def _require(permission: str):
    from attestra.api import require

    return require(permission)


@router.post("/api/findings/{fid}/ticket")
def create_ticket(fid: int, principal=Depends(_require("finding.write"))):
    from attestra import services
    from attestra.models import Finding

    try:
        with db.session() as s:
            f = s.get(Finding, fid)
            if not f:
                raise LookupError(f"finding {fid} not found")
            services.assert_engagement_access(s, f.engagement_id, principal)
            f = tickets.sync_ticket(s, fid, actor=principal.actor)
            return {"id": f.id, "ticket_ref": f.ticket_ref}
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except tickets.TicketError as e:
        raise HTTPException(409, str(e)) from e
    except services.ServiceError as e:
        raise HTTPException(403, str(e)) from e


@router.post("/api/integrations/tickets/{backend}/webhook")
async def ticket_webhook(backend: str, request: Request):
    if backend not in tickets.BACKENDS:
        raise HTTPException(404, "unknown backend")
    secret = os.environ.get("ATTESTRA_TICKETS_WEBHOOK_SECRET", "")
    if not secret:
        raise HTTPException(404, "ticket webhooks are disabled")
    raw = await request.body()
    sig = request.headers.get("X-Hub-Signature-256") or request.headers.get("X-Attestra-Signature", "")
    if not tickets.verify_signature(secret, raw, sig):
        raise HTTPException(401, "bad signature")
    try:
        parsed = tickets.parse_webhook(backend, json.loads(raw or b"{}"))
    except ValueError as e:
        raise HTTPException(400, "invalid JSON") from e
    if not parsed:
        return {"applied": False}
    ref, state = parsed
    with db.session() as s:
        f = tickets.apply_ticket_state(s, ref, state, actor=f"webhook:{backend}")
        return {"applied": f is not None, "finding": f.id if f else None, "status": f.status if f else None}
