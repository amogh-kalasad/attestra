"""Source→Mongo migration engine: assess / plan / import / validate / status / resume."""

from __future__ import annotations

import hashlib
import logging
import uuid
from pathlib import Path
from typing import Any

from attestra.migration import checkpoint as cp
from attestra.migration.sql_source import TABLE_ORDER, iter_rows, readonly_connection, row_count
from attestra.migration.sql_source import assess as sql_assess
from attestra.migration.transform import pk_of, row_to_document
from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo.client import init_mongo
from attestra.persistence.mongo.sequences import seed_sequence

log = logging.getLogger("attestra.migration")

ARTIFACT_SUBDIRS = ("evidence", "imports", "reports", "raw", "tenants", "feeds", "packs")


def assess(source_url: str, *, data_dir: Path | None = None) -> dict[str, Any]:
    report = sql_assess(source_url)
    artifacts: dict[str, Any] = {}
    if data_dir and data_dir.exists():
        for sub in ARTIFACT_SUBDIRS:
            root = data_dir / sub
            if not root.exists():
                artifacts[sub] = {"files": 0, "bytes": 0}
                continue
            files = [p for p in root.rglob("*") if p.is_file()]
            artifacts[sub] = {"files": len(files), "bytes": sum(p.stat().st_size for p in files)}
    report["artifacts"] = artifacts
    report["ordered_tables"] = [t for t in TABLE_ORDER if t in report.get("table_list", [])]
    return report


def plan(source_url: str) -> dict[str, Any]:
    a = assess(source_url)
    steps = []
    for table in a["ordered_tables"]:
        info = a["tables"].get(table, {})
        steps.append(
            {
                "table": table,
                "collection": table,
                "source_count": info.get("count"),
                "action": "upsert_by_id",
            }
        )
    steps.append({"table": "_artifacts", "collection": "GridFS", "action": "copy_if_present"})
    steps.append({"table": "_sequences", "collection": C.ID_SEQUENCES, "action": "seed_max_id"})
    return {"source": a["url_scheme"], "steps": steps, "run_hint": "attestra mongo-migrate import --source URL"}


def _ensure_target(uri: str | None, db_name: str | None) -> Any:
    return init_mongo(uri, db_name=db_name, apply_migrations=True)


def import_data(
    source_url: str,
    *,
    mongo_uri: str | None = None,
    mongo_db: str | None = None,
    run_id: str | None = None,
    resume: bool = False,
    dry_run: bool = False,
    batch_size: int = 500,
    tables: list[str] | None = None,
) -> dict[str, Any]:
    """Copy SQL rows into MongoDB. Never writes to the source database."""
    run_id = run_id or uuid.uuid4().hex[:12]
    db = _ensure_target(mongo_uri, mongo_db)
    selected = tables or list(TABLE_ORDER)
    summary: dict[str, Any] = {"run_id": run_id, "dry_run": dry_run, "tables": {}}

    with readonly_connection(source_url) as conn:
        from sqlalchemy import inspect

        existing = set(inspect(conn).get_table_names())
        for table in selected:
            if table not in existing:
                continue
            if table not in TABLE_ORDER and table != "alembic_version":
                continue
            start_after = 0
            if resume:
                prev = cp.load(db, run_id, table)
                if prev and prev.get("status") == "done":
                    summary["tables"][table] = {"skipped": True, "reason": "already done"}
                    continue
                if prev:
                    start_after = int(prev.get("last_id") or 0)
            imported = 0
            max_id = start_after
            if dry_run:
                summary["tables"][table] = {"would_import": row_count(conn, table), "after_id": start_after}
                continue
            for batch in iter_rows(conn, table, after_id=start_after, batch=batch_size):
                docs = [row_to_document(table, row) for row in batch]
                if not docs:
                    continue
                ops = []
                from pymongo import ReplaceOne

                for doc in docs:
                    ops.append(ReplaceOne({"_id": doc["_id"]}, doc, upsert=True))
                    max_id = max(max_id, pk_of(table, doc))
                db[table].bulk_write(ops, ordered=True)
                imported += len(docs)
                cp.save(db, run_id, table, last_id=max_id, status="in_progress", extra={"imported": imported})
            seed_sequence(db, table, max_id)
            cp.save(db, run_id, table, last_id=max_id, status="done", extra={"imported": imported})
            summary["tables"][table] = {"imported": imported, "max_id": max_id}
            log.info("migrated table=%s imported=%s max_id=%s", table, imported, max_id)

    # Preserve audit chain head from last event if present
    if not dry_run:
        last = db[C.AUDIT_EVENTS].find_one(sort=[("_id", -1)])
        if last:
            db[C.AUDIT_CHAIN_HEAD].update_one(
                {"_id": "head"},
                {"$set": {"last_id": last["_id"], "last_hash": last.get("hash"), "migrated": True}},
                upsert=True,
            )
            seed_sequence(db, C.AUDIT_EVENTS, int(last["_id"]))

    summary["status"] = "ok"
    return summary


def validate(source_url: str, *, mongo_uri: str | None = None, mongo_db: str | None = None) -> dict[str, Any]:
    db = _ensure_target(mongo_uri, mongo_db)
    report: dict[str, Any] = {"collections": {}, "ok": True}
    with readonly_connection(source_url) as conn:
        from sqlalchemy import inspect

        existing = set(inspect(conn).get_table_names())
        for table in TABLE_ORDER:
            if table not in existing:
                continue
            src = row_count(conn, table)
            dst = db[table].count_documents({})
            match = src == dst
            entry = {"source": src, "target": dst, "match": match}
            if not match:
                report["ok"] = False
            # Spot-check: compare ids set size
            if src and dst and match:
                # sample max id
                pk = "tenant_id" if table == "tenant_credit_accounts" else "id"
                from sqlalchemy import text

                src_max = conn.execute(text(f'SELECT MAX("{pk}") FROM "{table}"')).scalar()
                dst_max_doc = db[table].find_one(sort=[("_id", -1)], projection={"_id": 1})
                dst_max = dst_max_doc["_id"] if dst_max_doc else None
                entry["source_max_id"] = src_max
                entry["target_max_id"] = dst_max
                if src_max != dst_max:
                    entry["max_id_match"] = False
                    report["ok"] = False
                else:
                    entry["max_id_match"] = True
            report["collections"][table] = entry
    # Audit verify on target (historical breaks preserved)
    from attestra.persistence.mongo.repositories.ops import AuditRepository

    ok, bad = AuditRepository(db).verify()
    report["audit_chain_ok"] = ok
    report["audit_first_bad_id"] = bad
    return report


def status(run_id: str, *, mongo_uri: str | None = None, mongo_db: str | None = None) -> dict[str, Any]:
    db = _ensure_target(mongo_uri, mongo_db)
    rows = cp.list_for_run(db, run_id)
    return {"run_id": run_id, "checkpoints": rows}


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(1024 * 1024)
            if not block:
                break
            h.update(block)
    return h.hexdigest()
