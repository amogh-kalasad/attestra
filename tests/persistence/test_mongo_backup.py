"""Phase 9: Mongo logical backup/restore with manifest integrity."""
# @lat: [[architecture#Evidence integrity]]
# @lat: [[architecture#MongoDB migration (in progress)]]

from __future__ import annotations

import os
import uuid

import pytest

pytest.importorskip("pymongo")


def _mongo_uri() -> str:
    return os.environ.get("ATTESTRA_TEST_MONGODB_URI") or os.environ.get(
        "ATTESTRA_MONGODB_URI", "mongodb://127.0.0.1:27017/?replicaSet=rs0"
    )


def _mongo_available() -> bool:
    from pymongo import MongoClient

    try:
        client = MongoClient(_mongo_uri(), serverSelectionTimeoutMS=1500)
        client.admin.command("ping")
        client.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _mongo_available(), reason="MongoDB replica set not available")


@pytest.fixture
def mongo_db(monkeypatch):
    import attestra.persistence.mongo.config as mc
    from attestra.persistence.mongo import client as mongo_client
    from attestra.persistence.mongo.client import close_client, init_mongo

    db_name = f"attestra_test_bak_{uuid.uuid4().hex[:10]}"
    monkeypatch.setattr(mc, "MONGODB_URI", _mongo_uri())
    monkeypatch.setattr(mc, "MONGODB_DB", db_name)
    close_client()
    db = init_mongo(_mongo_uri(), db_name=db_name, apply_migrations=True)
    yield db
    close_client()
    client = mongo_client._build_client(_mongo_uri())
    client.drop_database(db_name)
    client.close()


def test_mongo_backup_restore_roundtrip(mongo_db, tmp_path, monkeypatch):
    import attestra.config as cfg
    import attestra.persistence.mongo.config as mc
    from attestra.ops.backup import BackupError, backup, restore, verify_manifest
    from attestra.persistence.mongo.client import close_client, init_mongo
    from attestra.persistence.mongo.repositories.core import TenantRepository
    from attestra.storage.mongo import MongoStorage

    monkeypatch.setattr(cfg, "PERSISTENCE_BACKEND", "mongo")
    monkeypatch.setattr(cfg, "STORAGE_BACKEND", "mongo")
    monkeypatch.setattr(cfg, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(mc, "MONGODB_URI", _mongo_uri())
    monkeypatch.setattr(mc, "MONGODB_DB", mongo_db.name)
    close_client()
    db = init_mongo(_mongo_uri(), db_name=mongo_db.name, apply_migrations=False)

    TenantRepository(db).create("BackupCo")
    store = MongoStorage(db)
    uri = store.put("tenants/1/evidence/a.bin", b"artifact-bytes")

    dest = tmp_path / "bak"
    result = backup(dest)
    assert result["backend"] == "mongo"
    ok, errors = verify_manifest(dest)
    assert ok and not errors

    # Tamper refusal
    (dest / "backup_meta.json").write_text("tampered", encoding="utf-8")
    with pytest.raises(BackupError):
        restore(dest)
    # Fix manifest by rewriting from a fresh backup
    dest2 = tmp_path / "bak2"
    backup(dest2)

    # Restore into a fresh DB name
    restore_db = f"attestra_test_restore_{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(mc, "MONGODB_DB", restore_db)
    close_client()
    init_mongo(_mongo_uri(), db_name=restore_db, apply_migrations=True)
    out = restore(dest2)
    assert out["backend"] == "mongo"
    db = init_mongo(_mongo_uri(), db_name=restore_db, apply_migrations=False)
    assert db["tenants"].count_documents({}) >= 1
    assert MongoStorage(db).get(uri) == b"artifact-bytes"

    close_client()
    from attestra.persistence.mongo import client as mongo_client

    client = mongo_client._build_client(_mongo_uri())
    client.drop_database(restore_db)
    client.close()
