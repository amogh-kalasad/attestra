"""Tenant-scoped Mongo persistence for AASI runs and append-only decisions.

Uses ``aasi_runs`` / ``aasi_decisions`` (migration 0005). Never stores raw
chain-of-thought — only structured payload summaries. Reads and writes always
filter by ``tenant_id``.
"""
# @lat: [[aasi#Phase 3 Mongo persistence]]

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any

from pymongo.errors import DuplicateKeyError

from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo.serialization import utcnow, with_id
from attestra.persistence.mongo.sequences import next_id
from attestra.persistence.mongo.tenant import TenantAccessDenied, require_tenant_access

SCHEMA_VERSION = 1

RUN_STATUSES = frozenset(
    {
        "CREATED",
        "SCOPE_CHECK",
        "PLANNING",
        "AWAITING_APPROVAL",
        "EXECUTING",
        "REVIEW",
        "COMPLETED",
        "BLOCKED",
        "FAILED",
        "CANCELLED",
    }
)

DECISION_KINDS = frozenset(
    {
        "hypothesis",
        "recommendation",
        "planner_outcome",
        "approval",
        "conclusion",
    }
)

# Payload keys that look like raw reasoning / CoT — stripped, never persisted.
_COT_KEY_RE = re.compile(
    r"(chain[_\s-]?of[_\s-]?thought|^cot$|raw_reasoning|reasoning_trace|thought_process)",
    re.IGNORECASE,
)


def canonical_json_hash(value: Any) -> str:
    """SHA-256 of canonical JSON (sorted keys, compact separators)."""
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sanitize_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Return a structured summary dict with CoT-like keys removed."""
    if not payload:
        return {}
    if not isinstance(payload, dict):
        raise TypeError("decision payload must be a dict summary")
    out: dict[str, Any] = {}
    for key, val in payload.items():
        if _COT_KEY_RE.search(str(key)):
            continue
        if isinstance(val, dict):
            out[key] = sanitize_payload(val)
        else:
            out[key] = val
    return out


def _db():
    from attestra.persistence.mongo.adapters import _db as get

    return get()


class AasiStore:
    """Mongo-backed AASI run / decision store (tenant-scoped)."""

    def __init__(self, db=None, *, tenant_ids: frozenset[int] | None = None):
        self.db = db if db is not None else _db()
        self.tenant_ids = tenant_ids
        self.runs = self.db[C.AASI_RUNS]
        self.decisions = self.db[C.AASI_DECISIONS]

    def _require_tenant(self, tenant_id: int) -> int:
        tid = int(tenant_id)
        require_tenant_access(tid, self.tenant_ids)
        return tid

    def create_run(
        self,
        tenant_id: int,
        engagement_id: int,
        idempotency_key: str,
        *,
        correlation_id: str = "",
        status: str = "CREATED",
        budget: dict[str, Any] | None = None,
        usage: dict[str, Any] | None = None,
        provider: dict[str, Any] | None = None,
        tasks: list[dict[str, Any]] | None = None,
        retain_until: datetime | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a run unique on ``(tenant_id, idempotency_key)``.

        On conflict with the same key, returns the existing document (idempotent).
        """
        tid = self._require_tenant(tenant_id)
        key = (idempotency_key or "").strip()
        if not key:
            raise ValueError("idempotency_key is required")
        if status not in RUN_STATUSES:
            raise ValueError(f"invalid run status: {status!r}")

        existing = self.runs.find_one({"tenant_id": tid, "idempotency_key": key})
        if existing:
            return with_id(existing)

        now = utcnow()
        run_id = next_id(self.db, C.AASI_RUNS)
        doc: dict[str, Any] = {
            "_id": run_id,
            "tenant_id": tid,
            "engagement_id": int(engagement_id),
            "correlation_id": correlation_id or "",
            "status": status,
            "budget": dict(budget or {}),
            "usage": dict(
                usage
                or {
                    "calls": 0,
                    "tokens_in": 0,
                    "tokens_out": 0,
                    "wall_s": 0,
                }
            ),
            "provider": dict(provider or {}),
            "tasks": list(tasks or []),
            "idempotency_key": key,
            "schema_version": SCHEMA_VERSION,
            "created_at": now,
            "updated_at": now,
        }
        if retain_until is not None:
            doc["retain_until"] = retain_until
        if extra:
            # Soft retention / opaque metadata only; never overwrite core keys.
            blocked = {
                "_id",
                "id",
                "tenant_id",
                "engagement_id",
                "idempotency_key",
                "schema_version",
            }
            for k, v in extra.items():
                if k not in blocked:
                    doc[k] = v

        try:
            self.runs.insert_one(doc)
        except DuplicateKeyError:
            prior = self.runs.find_one({"tenant_id": tid, "idempotency_key": key})
            if prior:
                return with_id(prior)
            raise

        try:
            from attestra.persistence.mongo.adapters import mongo_audit_record

            mongo_audit_record(
                "aasi",
                "aasi.run.create",
                "aasi_run",
                run_id,
                tenant_id=tid,
                engagement_id=int(engagement_id),
                idempotency_key=key,
            )
        except Exception:  # noqa: BLE001 — persistence must not fail if audit is unavailable
            pass

        return with_id(doc)

    def get_run(self, run_id: int, tenant_id: int) -> dict[str, Any] | None:
        """Fetch one run; always filters by ``tenant_id`` (and store scope)."""
        tid = self._require_tenant(tenant_id)
        doc = self.runs.find_one({"_id": int(run_id), "tenant_id": tid})
        if not doc:
            return None
        return with_id(doc)

    def append_decision(
        self,
        run_id: int,
        tenant_id: int,
        kind: str,
        payload: dict[str, Any] | None,
        *,
        role: str = "",
        cites: list[str] | None = None,
        audit_hash: str | None = None,
        retain_until: datetime | None = None,
        compute_audit_hash: bool = True,
    ) -> dict[str, Any]:
        """Append-only decision insert. Never updates prior decision documents.

        ``payload`` must be a structured summary; CoT-like keys are stripped.
        """
        tid = self._require_tenant(tenant_id)
        if kind not in DECISION_KINDS:
            raise ValueError(f"invalid decision kind: {kind!r}")

        run = self.get_run(run_id, tid)
        if run is None:
            raise TenantAccessDenied("not found")

        summary = sanitize_payload(payload)
        digest = audit_hash
        if digest is None and compute_audit_hash:
            digest = canonical_json_hash(
                {
                    "run_id": int(run_id),
                    "tenant_id": tid,
                    "kind": kind,
                    "role": role or "",
                    "payload": summary,
                    "cites": list(cites or []),
                }
            )

        now = utcnow()
        decision_id = next_id(self.db, C.AASI_DECISIONS)
        doc: dict[str, Any] = {
            "_id": decision_id,
            "run_id": int(run_id),
            "tenant_id": tid,
            "engagement_id": int(run["engagement_id"]),
            "role": role or "",
            "kind": kind,
            "payload": summary,
            "cites": list(cites or []),
            "schema_version": SCHEMA_VERSION,
            "created_at": now,
        }
        if digest:
            doc["audit_hash"] = digest
        if retain_until is not None:
            doc["retain_until"] = retain_until
        elif run.get("retain_until") is not None:
            doc["retain_until"] = run["retain_until"]

        # Insert only — no update path for prior decisions.
        self.decisions.insert_one(doc)

        try:
            from attestra.persistence.mongo.adapters import mongo_audit_record

            mongo_audit_record(
                "aasi",
                "aasi.decision.append",
                "aasi_decision",
                decision_id,
                tenant_id=tid,
                engagement_id=int(run["engagement_id"]),
                run_id=int(run_id),
                kind=kind,
                audit_hash=digest or "",
            )
        except Exception:  # noqa: BLE001
            pass

        return with_id(doc)

    def list_decisions(
        self,
        run_id: int,
        tenant_id: int,
        *,
        kind: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """List decisions for a run; always filters by ``tenant_id``."""
        tid = self._require_tenant(tenant_id)
        q: dict[str, Any] = {"run_id": int(run_id), "tenant_id": tid}
        if kind is not None:
            if kind not in DECISION_KINDS:
                raise ValueError(f"invalid decision kind: {kind!r}")
            q["kind"] = kind
        cursor = self.decisions.find(q).sort("created_at", 1)
        if limit is not None:
            cursor = cursor.limit(int(limit))
        return [with_id(d) for d in cursor]


__all__ = [
    "SCHEMA_VERSION",
    "RUN_STATUSES",
    "DECISION_KINDS",
    "AasiStore",
    "canonical_json_hash",
    "sanitize_payload",
]
