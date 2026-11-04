"""Versioned MongoDB schema migrations."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime

from pymongo.database import Database

from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo.indexes import ensure_indexes

log = logging.getLogger("attestra.persistence.mongo")

# Ordered list of (revision_id, description, apply_fn)
MIGRATIONS: list[tuple[str, str, Callable[[Database], None]]] = []


def _m0001_baseline(db: Database) -> None:
    for name in C.DOMAIN_COLLECTIONS:
        db[name]  # touch / create empty
    db[C.ID_SEQUENCES]
    db[C.AUDIT_CHAIN_HEAD]
    db[C.SCHEMA_MIGRATIONS]
    ensure_indexes(db)
    # Genesis head for audit chain (mirrors SQL GENESIS semantics for new DBs).
    db[C.AUDIT_CHAIN_HEAD].update_one(
        {"_id": "head"},
        {"$setOnInsert": {"last_id": 0, "last_hash": "0" * 64, "updated_at": datetime.now(UTC)}},
        upsert=True,
    )


MIGRATIONS.append(("0001_mongo_baseline", "Create collections, indexes, audit head", _m0001_baseline))


def _m0002_identity_webhooks(db: Database) -> None:
    """Indexes for identity/settings/webhook repositories; encrypt any plaintext webhook secrets."""
    from pymongo import ASCENDING

    from attestra.persistence.mongo.secrets_codec import protect_webhook_endpoint

    db[C.USER_INVITES].create_index("user_id")
    db[C.USER_INVITES].create_index([("tenant_id", ASCENDING), ("used_at", ASCENDING), ("revoked_at", ASCENDING)])
    db[C.WEBHOOK_ENDPOINTS].create_index([("tenant_id", ASCENDING), ("active", ASCENDING)])
    db[C.WEBHOOK_DELIVERIES].create_index([("endpoint_id", ASCENDING), ("_id", ASCENDING)])
    db[C.WEBHOOK_DELIVERIES].create_index([("status", ASCENDING), ("lease_until", ASCENDING)])
    db[C.WORKFLOW_RULES].create_index([("tenant_id", ASCENDING), ("active", ASCENDING)])
    db[C.FINDING_ASSIGNMENTS].create_index("finding_id")
    for doc in db[C.WEBHOOK_ENDPOINTS].find({"secret": {"$exists": True}}):
        fixed = protect_webhook_endpoint(dict(doc))
        db[C.WEBHOOK_ENDPOINTS].replace_one({"_id": doc["_id"]}, fixed)


MIGRATIONS.append(("0002_identity_webhooks", "Identity/webhook indexes; encrypt webhook secrets", _m0002_identity_webhooks))


def _m0003_credit_idempotency_partial(db: Database) -> None:
    """Replace sparse unique idempotency indexes with partial string filters."""
    from attestra.persistence.mongo.indexes import _unique_optional_string

    _unique_optional_string(db, C.CREDIT_TRANSACTIONS, "idempotency_key")
    _unique_optional_string(db, C.CREDIT_RENEWAL_REQUESTS, "idempotency_key")


MIGRATIONS.append(
    (
        "0003_credit_idempotency_partial",
        "Partial unique indexes for optional credit idempotency keys",
        _m0003_credit_idempotency_partial,
    )
)


def applied_revisions(db: Database) -> set[str]:
    return {doc["_id"] for doc in db[C.SCHEMA_MIGRATIONS].find({}, {"_id": 1})}


def apply_pending(db: Database) -> list[str]:
    done = applied_revisions(db)
    applied: list[str] = []
    for rev, description, fn in MIGRATIONS:
        if rev in done:
            continue
        log.info("mongo_migration_apply %s %s", rev, description)
        fn(db)
        db[C.SCHEMA_MIGRATIONS].insert_one(
            {"_id": rev, "description": description, "applied_at": datetime.now(UTC)}
        )
        applied.append(rev)
    return applied
