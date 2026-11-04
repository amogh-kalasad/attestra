"""Concurrency-safe integer ID allocation (preserves public integer IDs)."""

from __future__ import annotations

from pymongo import ReturnDocument
from pymongo.database import Database

from attestra.persistence.mongo import collections as C


def next_id(db: Database, entity: str) -> int:
    """Atomically allocate the next integer id for ``entity`` (collection logical name)."""
    doc = db[C.ID_SEQUENCES].find_one_and_update(
        {"_id": entity},
        {"$inc": {"value": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return int(doc["value"])


def seed_sequence(db: Database, entity: str, minimum: int) -> None:
    """Ensure the sequence is at least ``minimum`` (used after legacy import)."""
    minimum = int(minimum)
    current = peek_sequence(db, entity)
    if current >= minimum:
        return
    db[C.ID_SEQUENCES].update_one(
        {"_id": entity},
        {"$set": {"value": minimum}},
        upsert=True,
    )
    # Race-safe: if another writer advanced past minimum, keep the higher value.
    again = peek_sequence(db, entity)
    if again < minimum:
        db[C.ID_SEQUENCES].update_one({"_id": entity}, {"$set": {"value": minimum}})


def peek_sequence(db: Database, entity: str) -> int:
    doc = db[C.ID_SEQUENCES].find_one({"_id": entity})
    return int(doc["value"]) if doc else 0
