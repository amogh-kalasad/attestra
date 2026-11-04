"""MongoDB foundation, repositories, GridFS, and tenant isolation tests."""
# @lat: [[architecture#MongoDB migration (in progress)]]

from __future__ import annotations

import os
import uuid
from datetime import date

import pytest

pytest.importorskip("pymongo")

from pymongo.errors import ServerSelectionTimeoutError


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
    from attestra.persistence.mongo import client as mongo_client
    from attestra.persistence.mongo.client import close_client, init_mongo

    db_name = f"attestra_test_{uuid.uuid4().hex[:12]}"
    monkeypatch.setenv("ATTESTRA_MONGODB_URI", _mongo_uri())
    monkeypatch.setenv("ATTESTRA_MONGODB_DB", db_name)
    import attestra.persistence.mongo.config as mc

    monkeypatch.setattr(mc, "MONGODB_URI", _mongo_uri())
    monkeypatch.setattr(mc, "MONGODB_DB", db_name)
    close_client()
    db = init_mongo(_mongo_uri(), db_name=db_name, apply_migrations=True)
    yield db
    close_client()
    try:
        client = mongo_client._build_client(_mongo_uri())
        client.drop_database(db_name)
        client.close()
    except ServerSelectionTimeoutError:
        pass


def test_init_creates_schema_migration(mongo_db):
    from attestra.persistence.mongo import collections as C

    revs = list(mongo_db[C.SCHEMA_MIGRATIONS].find())
    assert any(r["_id"] == "0001_mongo_baseline" for r in revs)
    head = mongo_db[C.AUDIT_CHAIN_HEAD].find_one({"_id": "head"})
    assert head is not None
    assert head["last_hash"] == "0" * 64


def test_tenant_user_engagement_roundtrip(mongo_db):
    from attestra.persistence.mongo.repositories.core import (
        EngagementRepository,
        TenantRepository,
        UserRepository,
    )

    tenants = TenantRepository(mongo_db, tenant_ids=None)
    t = tenants.create("Acme Corp")
    assert t["id"] == 1
    users = UserRepository(mongo_db, tenant_ids=None)
    u = users.create("lead1", role="lead", tenant_id=t["id"], password_hash="x")
    assert u["username"] == "lead1"
    engs = EngagementRepository(mongo_db, tenant_ids=None)
    e = engs.create(t["id"], "Q1 VAPT", "vapt", frameworks=["pci_dss"])
    assert e["tenant_id"] == t["id"]
    assert engs.get(e["id"])["name"] == "Q1 VAPT"


def test_cross_tenant_isolation(mongo_db):
    from attestra.persistence.mongo.repositories.core import EngagementRepository, TenantRepository
    from attestra.persistence.mongo.tenant import TenantAccessDenied

    tenants = TenantRepository(mongo_db, tenant_ids=None)
    a = tenants.create("Tenant A")
    b = tenants.create("Tenant B")
    EngagementRepository(mongo_db, tenant_ids=None).create(a["id"], "A eng", "va")
    eng_b = EngagementRepository(mongo_db, tenant_ids=None).create(b["id"], "B eng", "va")

    scoped = EngagementRepository(mongo_db, tenant_ids=frozenset({a["id"]}))
    names = [e["name"] for e in scoped.list()]
    assert names == ["A eng"]
    with pytest.raises(TenantAccessDenied):
        scoped.get(eng_b["id"])
    with pytest.raises(LookupError):
        scoped.assert_access(eng_b["id"])


def test_asset_authorization_finding_scoped(mongo_db):
    from attestra.persistence.mongo.repositories.core import (
        AssetRepository,
        AuthorizationRepository,
        EngagementRepository,
        FindingRepository,
        TenantRepository,
    )

    t = TenantRepository(mongo_db, tenant_ids=None).create("ScopeCo")
    e = EngagementRepository(mongo_db, tenant_ids=None).create(t["id"], "Eng", "pt")
    assets = AssetRepository(mongo_db, tenant_ids=frozenset({t["id"]}))
    asset = assets.create(e["id"], "web_app", "https://app.example")
    AuthorizationRepository(mongo_db, tenant_ids=frozenset({t["id"]})).create(
        e["id"],
        "RoE.pdf",
        "mongo://auth/roe",
        "a" * 64,
        "Client CISO",
        date.today(),
        date.today(),
    )
    finding = FindingRepository(mongo_db, tenant_ids=frozenset({t["id"]})).create(
        e["id"], "fp-1", "XSS", asset_id=asset["id"], severity="high"
    )
    assert finding["fingerprint"] == "fp-1"
    other = TenantRepository(mongo_db, tenant_ids=None).create("Other")
    with pytest.raises((LookupError, Exception)):
        AssetRepository(mongo_db, tenant_ids=frozenset({other["id"]})).list_for_engagement(e["id"])


def test_audit_chain_and_job_claim(mongo_db):
    from attestra.persistence.mongo.repositories.ops import AuditRepository, JobRepository

    audit = AuditRepository(mongo_db, tenant_ids=None)
    e1 = audit.record("alice", "tenant.create", "tenant", 1, name="x")
    e2 = audit.record("alice", "engagement.create", "engagement", 2)
    assert e1["hash"]
    assert e2["prev_hash"] == e1["hash"]
    ok, bad = audit.verify()
    assert ok and bad is None

    jobs = JobRepository(mongo_db, tenant_ids=None)
    jobs.enqueue(scan_run_id=10)
    jobs.enqueue(scan_run_id=11)
    claimed = jobs.claim("worker-1")
    assert claimed is not None
    assert claimed["status"] == "running"
    assert claimed["worker_id"] == "worker-1"
    second = jobs.claim("worker-1")
    assert second is not None
    assert second["id"] != claimed["id"]
    assert jobs.claim("worker-1") is None


def test_credit_ledger_idempotent(mongo_db):
    from attestra.persistence.mongo.repositories.ops import CreditRepository

    credits = CreditRepository(mongo_db, tenant_ids=None)
    credits.ensure_account(1, initial_balance=3)
    tx1 = credits.apply_ledger(1, -1, "scan_admit", actor="system", idempotency_key="scan-1")
    tx2 = credits.apply_ledger(1, -1, "scan_admit", actor="system", idempotency_key="scan-1")
    assert tx1["id"] == tx2["id"]
    assert credits.get_account(1)["balance"] == 2
    with pytest.raises(ValueError):
        credits.apply_ledger(1, -5, "scan_admit", actor="system", idempotency_key="too-much")


def test_gridfs_write_once(mongo_db, monkeypatch):
    from attestra.storage.local import StorageError
    from attestra.storage.mongo import MongoStorage

    store = MongoStorage(mongo_db)
    uri = store.put("tenants/1/evidence/abc_file.bin", b"hello-evidence")
    assert uri.startswith("mongo://")
    assert store.get(uri) == b"hello-evidence"
    assert store.exists(uri)
    # idempotent identical put
    assert store.put("tenants/1/evidence/abc_file.bin", b"hello-evidence") == uri
    with pytest.raises(StorageError):
        store.put("tenants/1/evidence/abc_file.bin", b"different-bytes")


def test_get_storage_mongo_backend(mongo_db, monkeypatch):
    import attestra.config as cfg
    from attestra.persistence.mongo.client import init_mongo
    from attestra.storage import get_storage
    from attestra.storage.mongo import MongoStorage

    monkeypatch.setattr(cfg, "STORAGE_BACKEND", "mongo")
    init_mongo(_mongo_uri(), db_name=mongo_db.name, apply_migrations=False)
    store = get_storage()
    assert isinstance(store, MongoStorage)
