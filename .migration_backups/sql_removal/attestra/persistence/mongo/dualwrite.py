"""Dual-write: mirror committed SQL domain rows into MongoDB while ``ATTESTRA_PERSISTENCE=mongo``.

Migration phase 2 of the scan/engagement/finding/report/checklist port. SQL is still the
read path for these tables; every committed insert/update/delete on a mirrored table is
replayed into the Mongo collection of the same name (same integer ``_id``), so Mongo holds
a live, complete copy that reads can be cut over to module by module. Tables Mongo already
owns (jobs, audit_events, credits) and tables owned by other port tracks (users, settings,
webhooks) are deliberately not mirrored.

Writes happen only after the SQL transaction commits (a rollback mirrors nothing). A
failed mirror write is logged and counted in ``mirror_failures``; run
``attestra mongo-migrate import --resume`` / ``validate`` to reconcile.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import event, inspect

log = logging.getLogger("attestra.persistence.dualwrite")

MIRRORED_TABLES: frozenset[str] = frozenset(
    {
        "engagements",
        "authorizations",
        "assets",
        "scope_rules",
        "import_runs",
        "scan_runs",
        "findings",
        "finding_observations",
        "finding_comments",
        "evidence",
        "retests",
        "reports",
        "auth_route_inventory",
        "auth_element_inventory",
        "auth_checklist_items",
    }
)

_KEY = "_attestra_mongo_mirror"
_stats = {"writes": 0, "failures": 0}


def stats() -> dict[str, int]:
    return dict(_stats)


def _table_of(obj: Any) -> str | None:
    table = getattr(obj, "__table__", None)
    name = getattr(table, "name", None)
    return name if name in MIRRORED_TABLES else None


def _row(obj: Any) -> dict[str, Any]:
    mapper = inspect(obj).mapper
    out: dict[str, Any] = {}
    for prop in mapper.column_attrs:
        out[prop.columns[0].name] = getattr(obj, prop.key)
    return out


def _after_flush(session, _ctx) -> None:
    from attestra.persistence import using_mongo

    if not using_mongo():
        return
    pending: dict = session.info.setdefault(_KEY, {})
    for obj in list(session.new) + list(session.dirty):
        tbl = _table_of(obj)
        ident = getattr(obj, "id", None)
        if tbl and ident is not None:
            pending[(tbl, int(ident))] = obj
    for obj in session.deleted:
        tbl = _table_of(obj)
        ident = getattr(obj, "id", None)
        if tbl and ident is not None:
            pending[(tbl, int(ident))] = None


def _after_commit(session) -> None:
    pending: dict = session.info.pop(_KEY, None) or {}
    if not pending:
        return
    from pymongo import DeleteOne, ReplaceOne

    from attestra.migration.transform import row_to_document
    from attestra.persistence.mongo.adapters import _db

    by_table: dict[str, list] = {}
    for (tbl, ident), obj in pending.items():
        try:
            if obj is None:
                by_table.setdefault(tbl, []).append(DeleteOne({"_id": ident}))
            else:
                doc = row_to_document(tbl, _row(obj))
                by_table.setdefault(tbl, []).append(ReplaceOne({"_id": ident}, doc, upsert=True))
        except Exception:  # noqa: BLE001
            _stats["failures"] += 1
            log.exception("mirror: could not serialise %s/%s", tbl, ident)
    try:
        db = _db()
    except Exception:  # noqa: BLE001
        _stats["failures"] += sum(len(v) for v in by_table.values())
        log.exception("mirror: MongoDB unavailable; %d rows not mirrored", len(pending))
        return
    for tbl, ops in by_table.items():
        try:
            db[tbl].bulk_write(ops, ordered=False)
            _stats["writes"] += len(ops)
        except Exception:  # noqa: BLE001
            _stats["failures"] += len(ops)
            log.exception("mirror: bulk write to %s failed (%d ops)", tbl, len(ops))
            try:
                db["mirror_failures"].insert_one({"table": tbl, "ids": [o._filter["_id"] for o in ops]})
            except Exception:  # noqa: BLE001
                pass


def _after_rollback(session) -> None:
    session.info.pop(_KEY, None)


def install(session_factory) -> None:
    """Attach the mirror to a sessionmaker (idempotent)."""
    if event.contains(session_factory, "after_flush", _after_flush):
        return
    event.listen(session_factory, "after_flush", _after_flush)
    event.listen(session_factory, "after_commit", _after_commit)
    event.listen(session_factory, "after_soft_rollback", lambda s, _t: _after_rollback(s) if not s.in_transaction() else None)
    event.listen(session_factory, "after_rollback", _after_rollback)
