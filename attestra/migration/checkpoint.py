"""Migration checkpoint store in the target MongoDB database."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pymongo.database import Database

CHECKPOINT = "_migration_checkpoints"


def save(db: Database, run_id: str, table: str, *, last_id: int, status: str, extra: dict | None = None) -> None:
    payload: dict[str, Any] = {
        "run_id": run_id,
        "table": table,
        "last_id": int(last_id),
        "status": status,
        "updated_at": datetime.now(UTC),
    }
    if extra:
        payload.update(extra)
    db[CHECKPOINT].update_one({"_id": f"{run_id}:{table}"}, {"$set": payload}, upsert=True)


def load(db: Database, run_id: str, table: str) -> dict[str, Any] | None:
    return db[CHECKPOINT].find_one({"_id": f"{run_id}:{table}"})


def list_for_run(db: Database, run_id: str) -> list[dict[str, Any]]:
    return list(db[CHECKPOINT].find({"run_id": run_id}).sort("table", 1))
