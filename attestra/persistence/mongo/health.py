"""MongoDB health and capability checks."""

from __future__ import annotations

from typing import Any

from pymongo.errors import PyMongoError

from attestra.persistence.mongo.client import get_client, get_db


def ping() -> dict[str, Any]:
    """Return server status suitable for /api/health extensions (no secrets)."""
    client = get_client()
    db = get_db()
    hello = client.admin.command("hello")
    return {
        "ok": True,
        "db": db.name,
        "replica_set": hello.get("setName"),
        "is_writable_primary": bool(hello.get("isWritablePrimary") or hello.get("ismaster")),
        "max_wire_version": hello.get("maxWireVersion"),
    }


def require_transactions_capable() -> None:
    """Raise if the deployment cannot run multi-document transactions."""
    try:
        info = ping()
    except PyMongoError as exc:
        raise RuntimeError(f"mongodb unavailable: {exc}") from exc
    if not info.get("replica_set") and not info.get("is_writable_primary"):
        # Standalone without replica set cannot do multi-doc transactions.
        hello = get_client().admin.command("hello")
        if not hello.get("setName"):
            raise RuntimeError(
                "MongoDB multi-document transactions require a replica set "
                "(or a compatible transactional deployment); standalone is not supported"
            )
