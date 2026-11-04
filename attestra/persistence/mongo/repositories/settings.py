"""Settings repositories: per-tenant email alert settings, alert dedup, Certification Authority.

``as_row(doc)`` turns a document into an attribute object so the existing pure helpers
(``alerts.service.settings_dict``, ``certification.service.settings_dict`` /
``format_address``) can be reused unchanged for Mongo reads.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo.repositories.base import BaseRepository
from attestra.persistence.mongo.serialization import ensure_utc, utcnow, with_id
from attestra.persistence.mongo.tenant import TenantAccessDenied, require_tenant_access

EMAIL_ALERT_DEFAULTS: dict[str, Any] = {
    "notify_new_high": True,
    "notify_header_change": True,
    "notify_sla_missed": True,
    "recipients": [],
    "updated_by": "",
    "updated_at": None,
}
EMAIL_ALERT_FIELDS = frozenset({"notify_new_high", "notify_header_change", "notify_sla_missed", "recipients"})

CA_SINGLETON_ID = 1
CA_FIELDS = (
    "legal_name", "signer_name", "signer_title", "authorization_statement", "logo",
    "address_line1", "address_line2", "city", "state", "postal_code", "country",
    "contact_name", "contact_email", "contact_phone", "website",
)


def as_row(doc: dict[str, Any] | None, defaults: dict[str, Any] | None = None) -> SimpleNamespace | None:
    if doc is None:
        return None
    data = dict(defaults or {})
    data.update({k: v for k, v in doc.items() if k != "_id"})
    data.setdefault("id", doc.get("_id"))
    if data.get("updated_at") is not None:
        data["updated_at"] = ensure_utc(data["updated_at"])
    return SimpleNamespace(**data)


class EmailAlertSettingsRepository(BaseRepository):
    collection_name = C.EMAIL_ALERT_SETTINGS

    def get(self, tenant_id: int) -> dict[str, Any] | None:
        require_tenant_access(int(tenant_id), self.tenant_ids)
        doc = self.col.find_one({"tenant_id": int(tenant_id)})
        return with_id(doc) if doc else None

    def ensure(self, tenant_id: int) -> dict[str, Any]:
        doc = self.get(tenant_id)
        if doc is not None:
            return doc
        try:
            return self.insert_with_id({"tenant_id": int(tenant_id), **EMAIL_ALERT_DEFAULTS, "recipients": []})
        except DuplicateKeyError:  # concurrent ensure
            return self.get(tenant_id)  # type: ignore[return-value]

    def update(self, tenant_id: int, *, actor: str, **fields: Any) -> dict[str, Any]:
        bad = set(fields) - EMAIL_ALERT_FIELDS
        if bad:
            raise ValueError(f"unknown alert settings fields: {sorted(bad)}")
        self.ensure(tenant_id)
        sets = {k: (list(v) if k == "recipients" else bool(v)) for k, v in fields.items() if v is not None}
        sets.update({"updated_by": actor, "updated_at": utcnow()})
        doc = self.col.find_one_and_update(
            {"tenant_id": int(tenant_id)}, {"$set": sets}, return_document=ReturnDocument.AFTER
        )
        return with_id(doc)

    def recipients_for(self, tenant_id: int, flag: str) -> list[str]:
        """Recipients when ``flag`` (e.g. ``notify_new_high``) is on; [] when no settings doc."""
        doc = self.get(tenant_id)
        if doc is None or not doc.get(flag, False):
            return []
        return list(doc.get("recipients") or [])


class EmailAlertSentRepository(BaseRepository):
    """Send-once dedup keyed by (event_type, entity_type, entity_id)."""

    collection_name = C.EMAIL_ALERT_SENT

    def already_sent(self, event_type: str, entity_type: str, entity_id: int) -> bool:
        return self.col.count_documents(
            {"event_type": event_type, "entity_type": entity_type, "entity_id": int(entity_id)}, limit=1
        ) > 0

    def mark_sent(self, tenant_id: int, event_type: str, entity_type: str, entity_id: int) -> bool:
        """Returns True when this call claimed the slot (False if already marked)."""
        require_tenant_access(int(tenant_id), self.tenant_ids)
        try:
            self.insert_with_id({
                "tenant_id": int(tenant_id), "event_type": event_type, "entity_type": entity_type,
                "entity_id": int(entity_id), "sent_at": utcnow(),
            })
            return True
        except DuplicateKeyError:
            return False


class CertificationAuthorityRepository(BaseRepository):
    """Platform singleton (``_id`` = 1). Writes require an unscoped (super-admin) caller."""

    collection_name = C.CERTIFICATION_AUTHORITY

    def get(self) -> dict[str, Any] | None:
        doc = self.col.find_one({"_id": CA_SINGLETON_ID})
        return with_id(doc) if doc else None

    def update(self, *, actor: str, **fields: Any) -> dict[str, Any]:
        if self.tenant_ids is not None:
            raise TenantAccessDenied("certification authority settings require an unscoped caller")
        bad = set(fields) - set(CA_FIELDS)
        if bad:
            raise ValueError(f"unknown certification fields: {sorted(bad)}")
        sets = {k: ("" if v is None else str(v)) for k, v in fields.items()}
        sets.update({"updated_by": actor, "updated_at": utcnow()})
        doc = self.col.find_one_and_update(
            {"_id": CA_SINGLETON_ID},
            {"$set": sets, "$setOnInsert": {k: "" for k in CA_FIELDS if k not in sets}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return with_id(doc)


__all__ = [
    "CA_FIELDS",
    "CertificationAuthorityRepository",
    "EmailAlertSentRepository",
    "EmailAlertSettingsRepository",
    "as_row",
]
