"""Webhook repositories: endpoints (encrypted secrets), deliveries, workflow rules, assignments.

Endpoint secrets are stored only as ``secret_enc`` (Fernet, see ``secrets_codec``). Public
reads (``get`` / ``list``) strip ``secret_enc``; ``reveal_secret`` is the single decrypt
path (used for HMAC signing at delivery time).
"""

from __future__ import annotations

import secrets as _secrets
from datetime import datetime
from typing import Any

from pymongo import ReturnDocument

from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo.repositories.base import BaseRepository
from attestra.persistence.mongo.secrets_codec import (
    SecretCodecError,
    decrypt_secret,
    encrypt_secret,
    fingerprint,
)
from attestra.persistence.mongo.serialization import ensure_utc, utcnow, with_id
from attestra.persistence.mongo.tenant import TenantAccessDenied, require_tenant_access, tenant_filter

_PRIVATE = ("secret_enc", "secret")


def _public(doc: dict[str, Any]) -> dict[str, Any]:
    out = with_id(doc)
    for key in _PRIVATE:
        out.pop(key, None)
    return out


class WebhookEndpointRepository(BaseRepository):
    collection_name = C.WEBHOOK_ENDPOINTS

    def create(
        self,
        tenant_id: int,
        *,
        url: str,
        created_by: str,
        name: str = "",
        fmt: str = "json",
        events: list[str] | None = None,
        secret: str | None = None,
        doc_id: int | None = None,
    ) -> tuple[dict[str, Any], str]:
        """Insert an endpoint; returns (public doc, plaintext secret shown once).

        Raises ``SecretCodecError`` (nothing written) when no encryption key is configured.
        """
        require_tenant_access(int(tenant_id), self.tenant_ids)
        plain = secret or _secrets.token_hex(32)
        enc = encrypt_secret(plain)  # fail closed before any write
        doc = self.insert_with_id(
            {
                "tenant_id": int(tenant_id),
                "name": name,
                "url": url.strip(),
                "secret_enc": enc,
                "secret_fp": fingerprint(plain),
                "secret_unavailable": False,
                "format": fmt,
                "events": list(events or []),
                "active": True,
                "created_by": created_by,
                "created_at": utcnow(),
            },
            doc_id=doc_id,
        )
        return _public(doc), plain

    def get(self, endpoint_id: int) -> dict[str, Any] | None:
        doc = self.col.find_one({"_id": int(endpoint_id)})
        if not doc or not self.in_scope(doc):
            return None
        return _public(doc)

    def list(self, *, tenant_id: int | None = None, active_only: bool = False) -> list[dict[str, Any]]:
        q: dict[str, Any] = dict(tenant_filter("tenant_id", self.tenant_ids))
        if tenant_id is not None:
            if self.tenant_ids is not None and int(tenant_id) not in self.tenant_ids:
                return []
            q["tenant_id"] = int(tenant_id)
        if active_only:
            q["active"] = True
        return [_public(d) for d in self.col.find(q).sort("_id", 1)]

    def deactivate(self, endpoint_id: int) -> dict[str, Any] | None:
        if self.get(endpoint_id) is None:
            return None
        doc = self.col.find_one_and_update(
            {"_id": int(endpoint_id)}, {"$set": {"active": False}}, return_document=ReturnDocument.AFTER
        )
        return _public(doc) if doc else None

    def rotate_secret(self, endpoint_id: int) -> str | None:
        """New random secret (encrypted at rest); returns plaintext once, or None if not found."""
        if self.get(endpoint_id) is None:
            return None
        plain = _secrets.token_hex(32)
        self.col.update_one(
            {"_id": int(endpoint_id)},
            {"$set": {"secret_enc": encrypt_secret(plain), "secret_fp": fingerprint(plain), "secret_unavailable": False}},
        )
        return plain

    def reveal_secret(self, endpoint_id: int) -> str:
        """Decrypt the signing secret. Raises LookupError / SecretCodecError."""
        doc = self.col.find_one({"_id": int(endpoint_id)}, {"secret_enc": 1, "tenant_id": 1})
        if not doc or not self.in_scope(doc):
            raise LookupError(f"webhook {endpoint_id} not found")
        enc = doc.get("secret_enc")
        if not enc:
            raise SecretCodecError("webhook secret unavailable; rotate it after configuring the key")
        return decrypt_secret(enc)


class WorkflowRuleRepository(BaseRepository):
    collection_name = C.WORKFLOW_RULES

    def create(self, tenant_id: int, *, action: str, created_by: str, name: str = "", event: str = "",
               min_severity: str = "info", status: str = "", endpoint_id: int | None = None,
               assignee: str = "", doc_id: int | None = None) -> dict[str, Any]:
        require_tenant_access(int(tenant_id), self.tenant_ids)
        return self.insert_with_id(
            {
                "tenant_id": int(tenant_id), "name": name, "event": event, "min_severity": min_severity,
                "status": status, "action": action, "endpoint_id": endpoint_id, "assignee": assignee,
                "active": True, "created_by": created_by, "created_at": utcnow(),
            },
            doc_id=doc_id,
        )

    def get(self, rule_id: int) -> dict[str, Any] | None:
        doc = self.col.find_one({"_id": int(rule_id)})
        if not doc or not self.in_scope(doc):
            return None
        return with_id(doc)

    def list(self, *, tenant_id: int | None = None, active_only: bool = False) -> list[dict[str, Any]]:
        q: dict[str, Any] = dict(tenant_filter("tenant_id", self.tenant_ids))
        if tenant_id is not None:
            if self.tenant_ids is not None and int(tenant_id) not in self.tenant_ids:
                return []
            q["tenant_id"] = int(tenant_id)
        if active_only:
            q["active"] = True
        return [with_id(d) for d in self.col.find(q).sort("_id", 1)]

    def deactivate(self, rule_id: int) -> dict[str, Any] | None:
        if self.get(rule_id) is None:
            return None
        doc = self.col.find_one_and_update(
            {"_id": int(rule_id)}, {"$set": {"active": False}}, return_document=ReturnDocument.AFTER
        )
        return with_id(doc) if doc else None


class WebhookDeliveryRepository(BaseRepository):
    collection_name = C.WEBHOOK_DELIVERIES

    def queue(self, endpoint: dict[str, Any], event: str, payload: dict[str, Any]) -> dict[str, Any]:
        require_tenant_access(int(endpoint["tenant_id"]), self.tenant_ids)
        return self.insert_with_id({
            "tenant_id": int(endpoint["tenant_id"]), "endpoint_id": int(endpoint["id"]), "event": event,
            "payload": payload, "status": "pending", "attempts": 0, "next_attempt_at": utcnow(),
            "last_status_code": None, "last_error": "", "created_at": utcnow(), "delivered_at": None,
        })

    def get(self, delivery_id: int) -> dict[str, Any] | None:
        doc = self.col.find_one({"_id": int(delivery_id)})
        if not doc or not self.in_scope(doc):
            return None
        return with_id(doc)

    def list_for_endpoint(self, endpoint_id: int, *, limit: int = 100) -> list[dict[str, Any]]:
        q: dict[str, Any] = {"endpoint_id": int(endpoint_id)}
        q.update(tenant_filter("tenant_id", self.tenant_ids))
        return [with_id(d) for d in self.col.find(q).sort("_id", -1).limit(int(limit))]

    def claim_due(self, *, now: datetime | None = None, limit: int = 50, lease_seconds: int = 120) -> list[dict[str, Any]]:
        """Atomically lease due pending deliveries (safe with several dispatchers).

        A claimed delivery is ``status='sending'`` with ``lease_until``; stale leases (crashed
        dispatcher) are re-claimable once expired.
        """
        from datetime import timedelta

        now = ensure_utc(now) or utcnow()
        base: dict[str, Any] = dict(tenant_filter("tenant_id", self.tenant_ids))
        due_q = {
            **base,
            "$or": [
                {"status": "pending", "next_attempt_at": {"$lte": now}},
                {"status": "sending", "lease_until": {"$lte": now}},
            ],
        }
        out: list[dict[str, Any]] = []
        for cand in self.col.find(due_q, {"_id": 1}).sort("_id", 1).limit(int(limit)):
            doc = self.col.find_one_and_update(
                {"_id": cand["_id"], **due_q},
                {"$set": {"status": "sending", "lease_until": now + timedelta(seconds=lease_seconds)}},
                return_document=ReturnDocument.AFTER,
            )
            if doc:
                out.append(with_id(doc))
        return out

    def finish(self, delivery_id: int, **fields: Any) -> dict[str, Any] | None:
        allowed = {"status", "attempts", "next_attempt_at", "last_status_code", "last_error", "delivered_at"}
        bad = set(fields) - allowed
        if bad:
            raise ValueError(f"unknown delivery fields: {sorted(bad)}")
        doc = self.col.find_one_and_update(
            {"_id": int(delivery_id)},
            {"$set": fields, "$unset": {"lease_until": ""}},
            return_document=ReturnDocument.AFTER,
        )
        return with_id(doc) if doc else None


class FindingAssignmentRepository(BaseRepository):
    collection_name = C.FINDING_ASSIGNMENTS

    def _finding_tenant(self, finding_id: int) -> int | None:
        f = self.db[C.FINDINGS].find_one({"_id": int(finding_id)}, {"engagement_id": 1})
        if not f:
            return None
        eng = self.db[C.ENGAGEMENTS].find_one({"_id": int(f["engagement_id"])}, {"tenant_id": 1})
        return int(eng["tenant_id"]) if eng and eng.get("tenant_id") is not None else None

    def create(self, finding_id: int, assignee: str, *, rule_id: int | None = None, assigned_by: str = "") -> dict[str, Any]:
        if self.tenant_ids is not None:
            tid = self._finding_tenant(finding_id)
            if tid is None or tid not in self.tenant_ids:
                raise TenantAccessDenied("not found")
        return self.insert_with_id({
            "finding_id": int(finding_id), "assignee": assignee, "rule_id": rule_id,
            "assigned_by": assigned_by, "created_at": utcnow(),
        })

    def list_for_finding(self, finding_id: int) -> list[dict[str, Any]]:
        if self.tenant_ids is not None:
            tid = self._finding_tenant(finding_id)
            if tid is None or tid not in self.tenant_ids:
                return []
        return [with_id(d) for d in self.col.find({"finding_id": int(finding_id)}).sort("_id", 1)]


__all__ = [
    "FindingAssignmentRepository",
    "WebhookDeliveryRepository",
    "WebhookEndpointRepository",
    "WorkflowRuleRepository",
]
