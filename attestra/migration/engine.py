"""Mongo post-cutover helpers: migration checkpoint status and audit-chain verify.

SQL assess/plan/import lived here during cutover; the SQL source reader is archived under
``.migration_backups/sql_removal/attestra/migration/``.
"""

from __future__ import annotations

from typing import Any

from attestra.migration import checkpoint as cp
from attestra.persistence.mongo.client import init_mongo


def _ensure_target(uri: str | None, db_name: str | None) -> Any:
    return init_mongo(uri, db_name=db_name, apply_migrations=True)


def validate(*, mongo_uri: str | None = None, mongo_db: str | None = None) -> dict[str, Any]:
    """Verify the Mongo audit hash chain (no SQL source comparison)."""
    db = _ensure_target(mongo_uri, mongo_db)
    from attestra.persistence.mongo.repositories.ops import AuditRepository

    ok, bad = AuditRepository(db).verify()
    return {"ok": ok, "audit_chain_ok": ok, "audit_first_bad_id": bad}


def status(run_id: str, *, mongo_uri: str | None = None, mongo_db: str | None = None) -> dict[str, Any]:
    db = _ensure_target(mongo_uri, mongo_db)
    rows = cp.list_for_run(db, run_id)
    return {"run_id": run_id, "checkpoints": rows}
