"""Upgrade INT: migration 0004 adds the WP2/WP4 collections + indexes to an existing database."""

from __future__ import annotations

import os
import uuid

import pytest

pytest.importorskip("pymongo")


def _mongo_uri() -> str:
    return os.environ.get("ATTESTRA_TEST_MONGODB_URI") or os.environ.get(
        "ATTESTRA_MONGODB_URI", "mongodb://127.0.0.1:27017/?replicaSet=rs0"
    )


def _client():
    from pymongo import MongoClient

    try:
        c = MongoClient(_mongo_uri(), serverSelectionTimeoutMS=1500)
        c.admin.command("ping")
        return c
    except Exception:
        return None


@pytest.fixture
def legacy_db():
    c = _client()
    if c is None:
        pytest.skip("MongoDB replica set not available")
    from attestra.persistence.mongo import collections as C
    from attestra.persistence.mongo.migrations import MIGRATIONS

    name = f"attestra_test_mig_{uuid.uuid4().hex[:10]}"
    db = c[name]
    # An existing deployment: 0001-0003 applied, none of the new collections/indexes present.
    for rev, desc, _fn in MIGRATIONS:
        if rev.startswith(("0001", "0002", "0003")):
            db[C.SCHEMA_MIGRATIONS].insert_one({"_id": rev, "description": desc})
    db[C.AUTOMATED_TEST_EXECUTIONS].insert_one({"_id": 1, "tenant_id": 1})
    yield db
    c.drop_database(name)
    c.close()


def test_0004_applies_once_and_is_additive(legacy_db):
    from attestra.persistence.mongo import collections as C
    from attestra.persistence.mongo.migrations import apply_pending

    assert apply_pending(legacy_db) == ["0004_upgrade_int_indexes"]
    assert apply_pending(legacy_db) == []
    names = set(legacy_db.list_collection_names())
    assert {C.API_INVENTORIES, C.DISCOVERY_CANDIDATES, C.ASSET_SNAPSHOTS, C.ASSET_CHANGE_EVENTS} <= names
    inv = {i["name"]: i for i in legacy_db[C.API_INVENTORIES].list_indexes()}
    assert inv["tenant_id_1_engagement_id_1_asset_id_1_sha256_1"]["unique"] is True
    ex = {i["name"] for i in legacy_db[C.AUTOMATED_TEST_EXECUTIONS].list_indexes()}
    assert "tenant_id_1_run_validity_1" in ex
    assert legacy_db[C.AUTOMATED_TEST_EXECUTIONS].count_documents({}) == 1  # nothing dropped
