"""Phase 6â€“8: concurrency, migration engine, report workflow."""
# @lat: [[architecture#MongoDB migration (in progress)]]

from __future__ import annotations

import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

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

    db_name = f"attestra_test_p68_{uuid.uuid4().hex[:10]}"
    monkeypatch.setattr(mc, "MONGODB_URI", _mongo_uri())
    monkeypatch.setattr(mc, "MONGODB_DB", db_name)
    close_client()
    db = init_mongo(_mongo_uri(), db_name=db_name, apply_migrations=True)
    yield db
    close_client()
    client = mongo_client._build_client(_mongo_uri())
    client.drop_database(db_name)
    client.close()


def test_concurrent_job_claims(mongo_db):
    from attestra.persistence.mongo.repositories.ops import JobRepository

    jobs = JobRepository(mongo_db)
    for i in range(20):
        jobs.enqueue(scan_run_id=1000 + i)

    claimed_ids: list[int] = []
    lock = threading.Lock()

    def worker(wid: str):
        local = []
        while True:
            doc = JobRepository(mongo_db).claim(wid)
            if not doc:
                break
            local.append(doc["id"])
        with lock:
            claimed_ids.extend(local)

    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = [pool.submit(worker, f"w{i}") for i in range(4)]
        for f in futs:
            f.result()

    assert len(claimed_ids) == 20
    assert len(set(claimed_ids)) == 20


def test_concurrent_credit_idempotency(mongo_db):
    from attestra.persistence.mongo.repositories.ops import CreditRepository

    credits = CreditRepository(mongo_db)
    credits.ensure_account(42, initial_balance=10)

    def consume():
        return CreditRepository(mongo_db).consume_for_scan_admit(
            42, actor="t", engagement_id=1, idempotency_key="same-key", enforce=True
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: consume(), range(8)))

    ids = {r["id"] for r in results if r}
    assert len(ids) == 1
    assert credits.get_account(42)["balance"] == 9


def test_report_four_eyes(mongo_db):
    from attestra.persistence.mongo.repositories.core import EngagementRepository, TenantRepository
    from attestra.persistence.mongo.repositories.reports import ReportRepository

    t = TenantRepository(mongo_db).create("RCo")
    e = EngagementRepository(mongo_db).create(t["id"], "Eng", "vapt")
    reports = ReportRepository(mongo_db)
    r = reports.create(e["id"], "technical", path="mongo://r.html", sha256="ab" * 32, generated_by_user_id=1)
    reports.transition(r["id"], "submitted", actor="author", actor_user_id=1, author_user_id=1)
    with pytest.raises(ValueError, match="QA approver"):
        reports.transition(
            r["id"], "qa_approved", actor="author", actor_user_id=1, author_user_id=1, expected_sha256="ab" * 32
        )
    reports.transition(
        r["id"], "qa_approved", actor="qa", actor_user_id=2, author_user_id=1, expected_sha256="ab" * 32
    )
    with pytest.raises(ValueError, match="signer must differ from QA"):
        reports.transition(
            r["id"],
            "signed",
            actor="qa",
            actor_user_id=2,
            author_user_id=1,
            qa_user_id=2,
            expected_sha256="ab" * 32,
            signature="ed25519:x",
        )
    signed = reports.transition(
        r["id"],
        "signed",
        actor="lead",
        actor_user_id=3,
        author_user_id=1,
        qa_user_id=2,
        expected_sha256="ab" * 32,
        signature="ed25519:x",
    )
    assert signed["status"] == "signed"


def test_mongo_validate_audit_helper(mongo_db, monkeypatch):
    """Post-cutover validate() checks the Mongo audit chain only."""
    import attestra.config as cfg
    import attestra.persistence.mongo.config as mc
    from attestra.migration.engine import validate
    from attestra.persistence.mongo.adapters import mongo_audit_record
    from attestra.persistence.mongo.client import close_client, init_mongo

    monkeypatch.setattr(cfg, "PERSISTENCE_BACKEND", "mongo")
    monkeypatch.setattr(mc, "MONGODB_URI", _mongo_uri())
    monkeypatch.setattr(mc, "MONGODB_DB", mongo_db.name)
    close_client()
    init_mongo(_mongo_uri(), db_name=mongo_db.name, apply_migrations=False)
    mongo_audit_record("w", "test.action", "job", 1)
    report = validate(mongo_uri=_mongo_uri(), mongo_db=mongo_db.name)
    assert report["ok"] is True and report["audit_chain_ok"] is True


def test_adapters_dispatch_when_mongo_mode(mongo_db, monkeypatch):
    monkeypatch.setenv("ATTESTRA_PERSISTENCE", "mongo")
    import attestra.config as cfg
    import attestra.persistence.mongo.config as mc
    from attestra.persistence.mongo.adapters import (
        mongo_audit_record,
        mongo_audit_verify,
        mongo_claim_job,
        mongo_enqueue_job,
    )
    from attestra.persistence.mongo.client import close_client, init_mongo

    monkeypatch.setattr(cfg, "PERSISTENCE_BACKEND", "mongo")
    monkeypatch.setattr(mc, "MONGODB_URI", _mongo_uri())
    monkeypatch.setattr(mc, "MONGODB_DB", mongo_db.name)
    close_client()
    init_mongo(_mongo_uri(), db_name=mongo_db.name, apply_migrations=False)
    mongo_audit_record("w", "test.action", "job", 1)
    ok, bad = mongo_audit_verify()
    assert ok and bad is None
    job = mongo_enqueue_job(55)
    claimed = mongo_claim_job("worker-z")
    assert claimed["id"] == job["id"]
