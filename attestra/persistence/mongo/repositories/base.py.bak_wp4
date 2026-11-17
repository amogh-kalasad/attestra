"""Shared repository primitives."""

from __future__ import annotations

from typing import Any

from pymongo.database import Database

from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo.sequences import next_id
from attestra.persistence.mongo.serialization import with_id
from attestra.persistence.mongo.tenant import TenantAccessDenied, TenantIds


class BaseRepository:
    collection_name: str = ""
    sequence_name: str = ""

    def __init__(self, db: Database, *, tenant_ids: TenantIds = None):
        self.db = db
        self.tenant_ids = tenant_ids
        self.col = db[self.collection_name]

    def allocate_id(self) -> int:
        return next_id(self.db, self.sequence_name or self.collection_name)

    def _doc_tenant(self, doc: dict[str, Any]) -> int | None:
        if self.collection_name == C.TENANTS:
            return int(doc["_id"])
        tid = doc.get("tenant_id")
        if tid is None and doc.get("engagement_id") is not None:
            eng = self.db[C.ENGAGEMENTS].find_one({"_id": int(doc["engagement_id"])}, {"tenant_id": 1})
            tid = eng.get("tenant_id") if eng else None
        if tid is None and doc.get("user_id") is not None:
            user = self.db[C.USERS].find_one({"_id": int(doc["user_id"])}, {"tenant_id": 1})
            tid = user.get("tenant_id") if user else None
        return int(tid) if tid is not None else None

    def in_scope(self, doc: dict[str, Any]) -> bool:
        """Mongo replacement for RLS on single-doc access. Unscoped (None) sees all."""
        if self.tenant_ids is None:
            return True
        tid = self._doc_tenant(doc)
        return tid is not None and tid in self.tenant_ids

    def get_raw(self, doc_id: int) -> dict[str, Any] | None:
        doc = self.col.find_one({"_id": int(doc_id)})
        if not doc:
            return None
        if not self.in_scope(doc):
            raise TenantAccessDenied("not found")
        return with_id(doc)

    def insert_with_id(self, fields: dict[str, Any], *, doc_id: int | None = None) -> dict[str, Any]:
        new_id = int(doc_id) if doc_id is not None else self.allocate_id()
        doc = {"_id": new_id, **fields}
        if self.tenant_ids is not None:
            # Defense in depth: never let a scoped caller write a doc that
            # resolves to a foreign tenant (docs with no resolvable tenant are
            # left to the per-repository create() guards).
            tid = self._doc_tenant(doc)
            if tid is not None and tid not in self.tenant_ids:
                raise TenantAccessDenied("not found")
        self.col.insert_one(doc)
        return with_id(doc)

    def replace(self, doc_id: int, fields: dict[str, Any]) -> dict[str, Any] | None:
        existing = self.col.find_one({"_id": int(doc_id)})
        if not existing or not self.in_scope(existing):
            return None
        doc = {"_id": int(doc_id), **fields}
        if not self.in_scope(doc):
            raise TenantAccessDenied("not found")
        result = self.col.replace_one({"_id": int(doc_id)}, doc)
        if result.matched_count == 0:
            return None
        return with_id(doc)

    def delete(self, doc_id: int) -> bool:
        existing = self.col.find_one({"_id": int(doc_id)})
        if not existing or not self.in_scope(existing):
            return False
        return self.col.delete_one({"_id": int(doc_id)}).deleted_count == 1
