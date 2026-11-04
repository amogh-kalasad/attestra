"""Hash-chained audit log: each event's hash covers the previous event's hash."""
# @lat: [[audit]]

from __future__ import annotations

import hashlib
import json

from sqlalchemy.orm import Session

from attestra.models import AuditEvent

GENESIS = "0" * 64


def _digest(prev_hash: str, ts: str, actor: str, action: str, entity: str, entity_id, details: dict) -> str:
    payload = json.dumps(
        [prev_hash, ts, actor, action, entity, entity_id, details], sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def record(s: Session, actor: str, action: str, entity: str, entity_id: int | None = None, **details) -> AuditEvent:
    from attestra.persistence.mongo.adapters import mongo_audit_record

    doc = mongo_audit_record(actor, action, entity, entity_id, **details)
    # Return a lightweight stand-in so callers that read .id still work.
    ev = AuditEvent(
        ts=doc["ts"],
        actor=actor,
        action=action,
        entity=entity,
        entity_id=entity_id,
        details=details,
        prev_hash=doc["prev_hash"],
        hash=doc["hash"],
    )
    ev.id = doc["id"]
    return ev


def verify(s: Session | None = None) -> tuple[bool, int | None]:
    """Return (ok, first_bad_event_id)."""
    from attestra.persistence.mongo.adapters import mongo_audit_verify

    return mongo_audit_verify()


def find_events(
    s: Session | None,
    *,
    action: str | None = None,
    entity: str | None = None,
    entity_id: int | None = None,
    limit: int | None = None,
) -> list[AuditEvent]:
    """Backend-neutral audit read (oldest first). Mongo docs come back as detached AuditEvent objects."""
    from attestra.persistence.mongo.adapters import _db

    q: dict = {}
    if action is not None:
        q["action"] = action
    if entity is not None:
        q["entity"] = entity
    if entity_id is not None:
        q["entity_id"] = entity_id
    cur = _db()["audit_events"].find(q).sort("_id", 1)
    if limit:
        cur = cur.limit(int(limit))
    out = []
    for d in cur:
        ev = AuditEvent(
            ts=d.get("ts"), actor=d.get("actor"), action=d.get("action"), entity=d.get("entity"),
            entity_id=d.get("entity_id"), details=d.get("details") or {},
            prev_hash=d.get("prev_hash"), hash=d.get("hash"),
        )
        ev.id = d["_id"]
        out.append(ev)
    return out
