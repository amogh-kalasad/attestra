"""C-01..C-04: versioned storage of imported API inventories (``api_inventories``).

One document per (tenant, engagement, asset, sha256). Re-uploading the same bytes returns
the existing version (dedup); a changed file becomes version N+1. Every query filters on
``tenant_id`` + ``engagement_id`` + ``asset_id``; nothing is ever read across tenants.

The collection name and its unique index ``(tenant_id, engagement_id, asset_id, sha256)``
are registered by INT in ``persistence/mongo/collections.py`` / ``indexes.py``; this module
only needs [[COLLECTION]]. [[MemoryBackend]] is the in-process backend used by unit tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from attestra.automated_vapt.api_inventory.model import ApiInventory, ApiOperation

# @lat: [[web-api-probes#API inventory storage]]

COLLECTION = "api_inventories"


class Backend(Protocol):
    def find_one(self, flt: dict[str, Any], sort: list[tuple[str, int]] | None = None) -> dict[str, Any] | None: ...
    def find(self, flt: dict[str, Any], sort: list[tuple[str, int]] | None = None, limit: int = 0) -> list[dict[str, Any]]: ...
    def insert_one(self, doc: dict[str, Any]) -> Any: ...


class MemoryBackend:
    """In-memory backend (tests / no-DB contexts)."""

    def __init__(self) -> None:
        self.docs: list[dict[str, Any]] = []

    def _match(self, d: dict[str, Any], flt: dict[str, Any]) -> bool:
        return all(d.get(k) == v for k, v in flt.items())

    def find(self, flt, sort=None, limit=0):
        rows = [dict(d) for d in self.docs if self._match(d, flt)]
        for key, direction in reversed(sort or []):
            rows.sort(key=lambda r: r.get(key) or 0, reverse=direction < 0)
        return rows[:limit] if limit else rows

    def find_one(self, flt, sort=None):
        rows = self.find(flt, sort, 1)
        return rows[0] if rows else None

    def insert_one(self, doc):
        for d in self.docs:
            if all(d.get(k) == doc.get(k) for k in ("tenant_id", "engagement_id", "asset_id", "sha256")):
                raise ValueError("duplicate api inventory")
        self.docs.append(dict(doc))
        return doc


class MongoBackend:
    """Backend on the live Mongo database (``get_db()[COLLECTION]``)."""

    def __init__(self) -> None:
        from attestra.persistence.mongo.client import get_db

        self.coll = get_db()[COLLECTION]

    def find(self, flt, sort=None, limit=0):
        cur = self.coll.find(flt, {"_id": 0})
        if sort:
            cur = cur.sort(sort)
        if limit:
            cur = cur.limit(limit)
        return list(cur)

    def find_one(self, flt, sort=None):
        rows = self.find(flt, sort, 1)
        return rows[0] if rows else None

    def insert_one(self, doc):
        self.coll.insert_one(dict(doc))
        return doc


@dataclass
class SavedInventory:
    version: int
    duplicate: bool
    doc: dict[str, Any]

    def public(self) -> dict[str, Any]:
        d = self.doc
        return {
            "version": self.version,
            "duplicate": self.duplicate,
            "asset_id": d.get("asset_id"),
            "sha256": d.get("sha256"),
            "kind": d.get("kind"),
            "filename": d.get("filename"),
            "created_at": d.get("created_at"),
            "created_by": d.get("created_by"),
            "summary": d.get("summary") or {},
            "unsupported": (d.get("unsupported") or [])[:50],
            "warnings": (d.get("warnings") or [])[:20],
        }


def _key(tenant_id: int, engagement_id: int, asset_id: int) -> dict[str, Any]:
    if tenant_id is None or engagement_id is None or asset_id is None:
        raise ValueError("tenant_id, engagement_id and asset_id are required")
    return {"tenant_id": int(tenant_id), "engagement_id": int(engagement_id), "asset_id": int(asset_id)}


def save(
    inv: ApiInventory,
    *,
    tenant_id: int,
    engagement_id: int,
    asset_id: int,
    actor: str = "",
    backend: Backend | None = None,
) -> SavedInventory:
    be = backend or MongoBackend()
    key = _key(tenant_id, engagement_id, asset_id)
    if not inv.sha256:
        raise ValueError("inventory has no sha256")
    existing = be.find_one({**key, "sha256": inv.sha256})
    if existing:
        return SavedInventory(int(existing.get("version") or 1), True, existing)
    last = be.find_one(key, sort=[("version", -1)])
    version = int((last or {}).get("version") or 0) + 1
    doc = {
        **key,
        **inv.to_doc(),
        "version": version,
        "created_at": datetime.now(UTC).isoformat(),
        "created_by": (actor or "")[:120],
    }
    be.insert_one(doc)
    return SavedInventory(version, False, doc)


def latest(*, tenant_id: int, engagement_id: int, asset_id: int, backend: Backend | None = None) -> ApiInventory | None:
    be = backend or MongoBackend()
    d = be.find_one(_key(tenant_id, engagement_id, asset_id), sort=[("version", -1)])
    return ApiInventory.from_doc(d) if d else None


def list_versions(*, tenant_id: int, engagement_id: int, asset_id: int, backend: Backend | None = None, limit: int = 20) -> list[SavedInventory]:
    be = backend or MongoBackend()
    rows = be.find(_key(tenant_id, engagement_id, asset_id), sort=[("version", -1)], limit=limit)
    return [SavedInventory(int(r.get("version") or 0), False, r) for r in rows]


def ops_for_ctx(inv: ApiInventory | None) -> list[ApiOperation]:
    """Operations to place on ``ctx.extra['_api_inventory_ops']`` (all, for coverage/indicators)."""
    return list(inv.operations) if inv is not None else []
