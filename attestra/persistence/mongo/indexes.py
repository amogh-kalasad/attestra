"""Idempotent index creation for Attestra Mongo collections."""

from __future__ import annotations

from pymongo import ASCENDING, DESCENDING
from pymongo.database import Database
from pymongo.errors import OperationFailure

from attestra.persistence.mongo import collections as C


def _unique_optional_string(db: Database, collection: str, field: str) -> None:
    """Unique index that ignores missing/null keys (partial filter, not sparse).

    Mongo sparse unique indexes still index explicit ``null`` values, so several
    migrated rows with ``idempotency_key: null`` collide. A partial filter on
    string values matches SQL UNIQUE NULL semantics.
    """
    name = f"{field}_1"
    partial = {field: {"$type": "string"}}
    existing = {idx["name"]: idx for idx in db[collection].list_indexes()}
    cur = existing.get(name)
    if cur is not None and (
        cur.get("sparse")
        or cur.get("partialFilterExpression") != partial
        or not cur.get("unique")
    ):
        db[collection].drop_index(name)
    try:
        db[collection].create_index(field, unique=True, name=name, partialFilterExpression=partial)
    except OperationFailure:
        db[collection].drop_index(name)
        db[collection].create_index(field, unique=True, name=name, partialFilterExpression=partial)


def ensure_indexes(db: Database) -> None:
    db[C.TENANTS].create_index("name", unique=True)
    db[C.USERS].create_index("username", unique=True)
    db[C.USERS].create_index("tenant_id")
    db[C.API_KEYS].create_index("key_hash", unique=True)
    db[C.API_KEYS].create_index("user_id")
    db[C.TENANT_MEMBERSHIPS].create_index([("user_id", ASCENDING), ("tenant_id", ASCENDING)], unique=True)
    db[C.TENANT_MEMBERSHIPS].create_index("tenant_id")
    db[C.USER_INVITES].create_index("token_hash", unique=True)
    db[C.ENGAGEMENTS].create_index("tenant_id")
    db[C.ENGAGEMENTS].create_index([("tenant_id", ASCENDING), ("status", ASCENDING)])
    db[C.ASSETS].create_index("engagement_id")
    db[C.AUTHORIZATIONS].create_index("engagement_id")
    db[C.SCOPE_RULES].create_index("engagement_id")
    db[C.FINDINGS].create_index([("engagement_id", ASCENDING), ("fingerprint", ASCENDING)], unique=True)
    db[C.FINDINGS].create_index("asset_id")
    db[C.FINDING_OBSERVATIONS].create_index("engagement_id")
    db[C.FINDING_OBSERVATIONS].create_index("finding_id")
    db[C.FINDING_OBSERVATIONS].create_index("import_run_id")
    db[C.EVIDENCE].create_index("finding_id")
    db[C.EVIDENCE].create_index("sha256")
    db[C.JOBS].create_index("scan_run_id", unique=True)
    db[C.JOBS].create_index([("status", ASCENDING), ("_id", ASCENDING)])
    db[C.JOBS].create_index([("status", ASCENDING), ("heartbeat_at", ASCENDING)])
    db[C.SCAN_RUNS].create_index("engagement_id")
    db[C.IMPORT_RUNS].create_index("engagement_id")
    db[C.AUDIT_EVENTS].create_index([("ts", ASCENDING)])
    db[C.AUDIT_EVENTS].create_index([("entity", ASCENDING), ("entity_id", ASCENDING)])
    _unique_optional_string(db, C.CREDIT_TRANSACTIONS, "idempotency_key")
    db[C.CREDIT_TRANSACTIONS].create_index("tenant_id")
    _unique_optional_string(db, C.CREDIT_RENEWAL_REQUESTS, "idempotency_key")
    db[C.SHARE_LINKS].create_index("token_hash", unique=True)
    db[C.SHARE_LINKS].create_index("tenant_id")
    db[C.TRUST_CENTERS].create_index("tenant_id", unique=True)
    db[C.TRUST_CENTERS].create_index("slug", unique=True)
    db[C.WEBHOOK_DELIVERIES].create_index([("status", ASCENDING), ("next_attempt_at", ASCENDING)])
    db[C.AUTH_ROUTE_INVENTORY].create_index(
        [
            ("engagement_id", ASCENDING),
            ("asset_id", ASCENDING),
            ("url", ASCENDING),
            ("role_name", ASCENDING),
            ("http_method", ASCENDING),
        ],
        unique=True,
    )
    db[C.AUTH_CHECKLIST_ITEMS].create_index([("engagement_id", ASCENDING), ("ref", ASCENDING)], unique=True)
    db[C.CONTROL_ASSESSMENTS].create_index(
        [("engagement_id", ASCENDING), ("framework", ASCENDING), ("control_ref", ASCENDING)],
        unique=True,
    )
    db[C.LIBRARY_ENTRIES].create_index([("tenant_id", ASCENDING), ("title", ASCENDING)], unique=True)
    db[C.REPORT_TEMPLATES].create_index([("tenant_id", ASCENDING), ("kind", ASCENDING)], unique=True)
    db[C.RETENTION_POLICIES].create_index([("tenant_id", ASCENDING), ("framework", ASCENDING)], unique=True)
    db[C.TENANT_OWNERSHIP_HOSTS].create_index([("tenant_id", ASCENDING), ("hostname", ASCENDING)], unique=True)
    db[C.EMAIL_ALERT_SENT].create_index(
        [("event_type", ASCENDING), ("entity_type", ASCENDING), ("entity_id", ASCENDING)],
        unique=True,
    )
    db[C.EMAIL_ALERT_SETTINGS].create_index("tenant_id", unique=True)
    db[C.ARTIFACTS].create_index("uri", unique=True)
    db[C.ARTIFACTS].create_index("sha256")
    db[C.ARTIFACTS].create_index("tenant_id")
    db[C.AUTOMATED_TEST_EXECUTIONS].create_index("tenant_id")
    db[C.AUTOMATED_TEST_EXECUTIONS].create_index([("status", ASCENDING), ("_id", ASCENDING)])
    db[C.REPORTS].create_index("engagement_id")
    db[C.REPORTS].create_index([("engagement_id", ASCENDING), ("kind", ASCENDING), ("version", DESCENDING)])
