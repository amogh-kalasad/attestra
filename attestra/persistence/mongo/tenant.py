"""Tenant scope helpers for Mongo repositories.

``None`` means unrestricted (admin / explicit operator). An empty frozenset means
no access. Missing tenant context for non-admin callers must not default to
unrestricted when a repository requires a scope.

K-01 strict mode (``ATTESTRA_TENANT_STRICT=1``, off by default): ``None`` no longer
means "unrestricted". It is treated as *missing tenant context*: a warning is logged
and the scope collapses to "no access" (fail closed). Code that legitimately needs
platform-wide access (schedulers, maintenance, migrations, admin principals) passes
the explicit :data:`SYSTEM_SCOPE` sentinel instead of ``None``.
"""
# @lat: [[attack-surface-and-platform#Tenant strict mode]]

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from typing import Any

from pymongo.database import Database

from attestra.persistence.mongo import collections as C

log = logging.getLogger("attestra.tenant")

TenantIds = frozenset[int] | None

_TRUE = frozenset({"1", "true", "yes", "on"})


class _SystemScope(frozenset):
    """Explicit platform-wide scope (K-01).

    Subclasses ``frozenset`` and is *empty*, so any code path that does not know the
    sentinel and treats it as a plain tenant set gets "no access" (fail closed), never
    "everything".
    """

    _instance: _SystemScope | None = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return "SYSTEM_SCOPE"

    def __reduce__(self):  # keep the singleton through copy/pickle
        return (_SystemScope, ())


SYSTEM_SCOPE: frozenset[int] = _SystemScope()


class TenantAccessDenied(LookupError):
    """Raised when a row exists but is outside the caller's tenant scope.

    Callers that mirror SQL ``LookupError`` "not found" semantics should treat
    this the same as missing (do not leak cross-tenant existence).
    """


def is_system_scope(allowed: object) -> bool:
    return allowed is SYSTEM_SCOPE


def strict_enabled() -> bool:
    """``config.TENANT_STRICT`` when INT has wired it, else ``ATTESTRA_TENANT_STRICT`` (default off)."""
    try:
        from attestra import config

        val = getattr(config, "TENANT_STRICT", None)
    except Exception:  # noqa: BLE001 - config import must never break scoping
        val = None
    if val is not None:
        return bool(val)
    return os.environ.get("ATTESTRA_TENANT_STRICT", "").strip().lower() in _TRUE


def effective_scope(allowed: Iterable[int] | None, *, where: str = "") -> TenantIds:
    """Resolve what a scope value means right now.

    * ``SYSTEM_SCOPE`` → ``None`` (unrestricted, explicitly requested).
    * ``None`` → ``None`` when strict mode is off (legacy behaviour), or an empty
      frozenset (deny everything) plus a warning when strict mode is on.
    * anything else → normalized frozenset.
    """
    if allowed is SYSTEM_SCOPE:
        return None
    if allowed is None:
        if strict_enabled():
            log.warning("tenant scope missing%s; denying (ATTESTRA_TENANT_STRICT=1)", f" in {where}" if where else "")
            return frozenset()
        return None
    return frozenset(int(t) for t in allowed)


def normalize_tenant_ids(tenant_ids: Iterable[int] | None) -> TenantIds:
    if tenant_ids is None:
        return None
    if tenant_ids is SYSTEM_SCOPE:
        return SYSTEM_SCOPE
    return frozenset(int(t) for t in tenant_ids)


def require_tenant_access(tenant_id: int, allowed: TenantIds) -> None:
    allowed = effective_scope(allowed, where="require_tenant_access")
    if allowed is None:
        return
    if int(tenant_id) not in allowed:
        raise TenantAccessDenied("not found")


def tenant_filter(field: str, allowed: TenantIds) -> dict[str, Any]:
    """Mongo filter fragment for a direct tenant_id (or tenants.id) column."""
    allowed = effective_scope(allowed, where="tenant_filter")
    if allowed is None:
        return {}
    if not allowed:
        return {field: {"$in": []}}
    return {field: {"$in": sorted(allowed)}}


def engagement_ids_for_tenants(db: Database, allowed: TenantIds) -> list[int] | None:
    """Return engagement ids visible to ``allowed``, or None if unrestricted."""
    allowed = effective_scope(allowed, where="engagement_ids_for_tenants")
    if allowed is None:
        return None
    if not allowed:
        return []
    cur = db[C.ENGAGEMENTS].find({"tenant_id": {"$in": sorted(allowed)}}, {"_id": 1})
    return [int(doc["_id"]) for doc in cur]


def via_engagement_filter(db: Database, allowed: TenantIds, engagement_field: str = "engagement_id") -> dict[str, Any]:
    ids = engagement_ids_for_tenants(db, allowed)
    if ids is None:
        return {}
    return {engagement_field: {"$in": ids}}
