"""Hash-chained audit log: each event's hash covers the previous event's hash."""
# @lat: [[audit]]

from __future__ import annotations

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra.models import AuditEvent, utcnow

GENESIS = "0" * 64


def _digest(prev_hash: str, ts: str, actor: str, action: str, entity: str, entity_id, details: dict) -> str:
    payload = json.dumps(
        [prev_hash, ts, actor, action, entity, entity_id, details], sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def record(s: Session, actor: str, action: str, entity: str, entity_id: int | None = None, **details) -> AuditEvent:
    last = s.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)).first()
    prev = last.hash if last else GENESIS
    ts = utcnow()
    ev = AuditEvent(
        ts=ts, actor=actor, action=action, entity=entity, entity_id=entity_id, details=details, prev_hash=prev
    )
    ev.hash = _digest(prev, ts.isoformat(), actor, action, entity, entity_id, details)
    s.add(ev)
    s.flush()
    return ev


def verify(s: Session) -> tuple[bool, int | None]:
    """Return (ok, first_bad_event_id)."""
    prev = GENESIS
    for ev in s.scalars(select(AuditEvent).order_by(AuditEvent.id)):
        ts = ev.ts if ev.ts.tzinfo else ev.ts.replace(tzinfo=utcnow().tzinfo)
        expected = _digest(prev, ts.isoformat(), ev.actor, ev.action, ev.entity, ev.entity_id, ev.details)
        if ev.prev_hash != prev or ev.hash != expected:
            return False, ev.id
        prev = ev.hash
    return True, None
