"""Mongo-mode job flow, reports race/four-eyes, tenant scope, credits, audit (mongofull M1).

Runs against a throwaway ``attestra_test_*`` database on the local replica set and
drops it afterwards. Never touches the live ``attestra`` database.
"""
from __future__ import annotations

import os
import threading
import uuid
from types import SimpleNamespace

import pytest

pytest.importorskip("pymongo")


def _mongo_uri() -> str:
    return os.environ.get("ATTESTRA_TEST_MONGODB_URI") or "mongodb://127.0.0.1:27017/?replicaSet=rs0"


def _mongo_available() -> bool:
    from pymongo import MongoClient

    try:
        c = MongoClient(_mongo_uri(), serverSelectionTimeoutMS=1500)
        c.admin.command("ping")
        c.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _mongo_available(), reason="MongoDB replica set not available")


@pytest.fixture
def mdb(mongo_test_db):
    """Throwaway ``attestra_test_*`` database (shared with ``fresh_db`` so services and raw reads agree)."""
    return mongo_test_db


@pytest.fixture
def mongo_mode(engagement, mdb):
    """Engagement id (created through MongoSession by the conftest ``engagement`` fixture)."""
    return engagement

def _runs(engagement, n, tool="trivy"):
    from sqlalchemy import select

    from attestra import db
    from attestra.jobs import durable
    from attestra.models import Asset, ScanRun

    out = []
    with db.session() as s:
        asset = s.scalars(select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "repo")).first()
        for _ in range(n):
            run = ScanRun(engagement_id=engagement, asset_id=asset.id, tool=tool, profile="baseline",
                          status="queued", requested_by="tester")
            s.add(run)
            s.flush()
            out.append((run.id, durable.enqueue(s, run.id).id))
    return out


def test_enqueue_writes_mongo_jobs_collection(mongo_mode, mdb):
    [(run_id, job_id)] = _runs(mongo_mode, 1, tool="nuclei")
    doc = mdb["jobs"].find_one({"_id": job_id})
    assert doc["scan_run_id"] == run_id and doc["tool"] == "nuclei" and doc["status"] == "queued"
    assert mdb["jobs"].count_documents({}) == 1

def test_worker_pool_end_to_end_run_one_job(mongo_mode, mdb, monkeypatch, tmp_path):
    """enqueue -> pool claim -> real durable.run_one_job (fake scanner/import) -> done."""
    from attestra import audit, db
    from attestra.jobs import durable
    from attestra.jobs.pool import WorkerPool
    from attestra.models import ScanRun

    raw = tmp_path / "out.json"
    raw.write_text("{}", encoding="utf-8")
    fake_result = SimpleNamespace(extra={}, error="", quarantine=False, quarantine_reason="", raw_path=raw,
                                  tool_version="1", image_digest="sha256:x", import_tool="trivy")
    monkeypatch.setattr(durable, "check", lambda *a, **k: "target")
    monkeypatch.setattr(durable, "get_adapter", lambda tool: SimpleNamespace(scan=lambda *a, **k: fake_result))
    monkeypatch.setattr(durable.services, "import_results", lambda *a, **k: SimpleNamespace(id=None, notes_json=""))
    import attestra.webhooks.service as wh

    monkeypatch.setattr(wh, "safe_emit_scan", lambda *a, **k: None)

    [(run_id, job_id)] = _runs(mongo_mode, 1)
    pool = WorkerPool(worker_id="m-pool", concurrency=1, housekeeping=False, log=lambda m: None)
    assert pool.tick() == 1
    assert pool.wait_idle(20)
    assert mdb["jobs"].find_one({"_id": job_id})["status"] == "done"
    with db.session() as s:
        assert s.get(ScanRun, run_id).status == "done"
    assert mdb["audit_events"].count_documents({"action": "job.complete", "entity_id": job_id}) == 1
    assert audit.verify(None) == (True, None)


def test_nuclei_serial_and_heartbeats(mongo_mode, mdb):
    from attestra import db
    from attestra.jobs import durable

    _runs(mongo_mode, 2, tool="nuclei")
    [(_, trivy_job)] = _runs(mongo_mode, 1, tool="trivy")
    with db.session() as s:
        first = durable.claim_job(s, "w1", exclude_tools=["nuclei"])
        assert first.id == trivy_job  # nuclei skipped while one is "busy"
        assert durable.touch_heartbeats(s, [first.id], "w1") == 1
        assert durable.touch_heartbeats(s, [first.id], "other") == 0


def test_cancel_and_halt(mongo_mode, mdb):
    from attestra import db, services
    from attestra.jobs import durable

    [(run_id, job_id), (_, job2)] = _runs(mongo_mode, 2)
    with db.session() as s:
        services.cancel_scan(s, run_id, actor="tester")
    doc = mdb["jobs"].find_one({"_id": job_id})
    assert doc["cancel_requested"] is True and doc["status"] == "cancelled"
    with db.session() as s:
        services.halt_engagement(s, mongo_mode, actor="tester")
    assert mdb["jobs"].find_one({"_id": job2})["cancel_requested"] is True
    with pytest.raises(LookupError):
        with db.session() as s:
            durable.request_cancel(s, 999999)
    durable.clear_engagement_cancel(mongo_mode)


def test_mongojob_write_through_and_lookup(mongo_mode, mdb):
    from attestra import db
    from attestra.jobs import durable

    [(run_id, job_id)] = _runs(mongo_mode, 1)
    with db.session() as s:
        job = durable.get_job(s, job_id)
        job.status = "cancelled"
        job.error = "x" * 5000
        assert durable.job_for_scan_run(s, run_id).id == job_id
        assert durable.get_job(s, 424242) is None
    doc = mdb["jobs"].find_one({"_id": job_id})
    assert doc["status"] == "cancelled" and len(doc["error"]) == 2000


def _report_setup(mdb):
    from attestra.persistence.mongo.repositories.core import EngagementRepository, TenantRepository
    from attestra.persistence.mongo.repositories.reports import ReportRepository

    t = TenantRepository(mdb).create("acme")
    e = EngagementRepository(mdb).create(t["id"], "e1", "web")
    repo = ReportRepository(mdb)
    r = repo.create(e["id"], "technical", path="x.pdf", sha256="a" * 64, generated_by="author", generated_by_user_id=1)
    return repo, r


def test_report_four_eyes_uses_stored_ids(mdb):
    repo, r = _report_setup(mdb)
    repo.transition(r["id"], "submitted", actor="author", actor_user_id=1)
    with pytest.raises(ValueError, match="differ"):
        repo.transition(r["id"], "qa_approved", actor="author", actor_user_id=1)  # author_user_id not passed
    with pytest.raises(ValueError, match="identified"):
        repo.transition(r["id"], "qa_approved", actor="anon")
    repo.transition(r["id"], "qa_approved", actor="qa", actor_user_id=2)
    with pytest.raises(ValueError, match="differ"):
        repo.transition(r["id"], "signed", actor="qa", actor_user_id=2)
    with pytest.raises(ValueError, match="hash"):
        repo.transition(r["id"], "signed", actor="signer", actor_user_id=3, expected_sha256="b" * 64)
    out = repo.transition(r["id"], "signed", actor="signer", actor_user_id=3, expected_sha256="a" * 64)
    assert out["status"] == "signed"
    from attestra.persistence.mongo.repositories.ops import AuditRepository

    assert AuditRepository(mdb).verify() == (True, None)


def test_report_concurrent_sign_only_one_wins(mdb):
    repo, r = _report_setup(mdb)
    repo.transition(r["id"], "submitted", actor="author", actor_user_id=1)
    repo.transition(r["id"], "qa_approved", actor="qa", actor_user_id=2)
    barrier = threading.Barrier(6)
    ok, bad = [], []

    def sign(i):
        barrier.wait()
        try:
            repo.transition(r["id"], "signed", actor=f"s{i}", actor_user_id=10 + i)
            ok.append(i)
        except ValueError:
            bad.append(i)

    ts = [threading.Thread(target=sign, args=(i,)) for i in range(6)]
    [t.start() for t in ts]
    [t.join(30) for t in ts]
    assert len(ok) == 1 and len(bad) == 5
    assert mdb["audit_events"].count_documents({"action": "report.signed"}) == 1


def test_tenant_scope_on_base_and_apikey_revoke(mdb):
    from attestra.persistence.mongo.repositories.core import (
        ApiKeyRepository,
        EngagementRepository,
        TenantRepository,
        UserRepository,
    )

    from attestra.persistence.mongo.tenant import TenantAccessDenied

    a = TenantRepository(mdb).create("ta")
    b = TenantRepository(mdb).create("tb")
    eb = EngagementRepository(mdb).create(b["id"], "eb", "web")
    ub = UserRepository(mdb).create("ub", tenant_id=b["id"])
    kb = ApiKeyRepository(mdb).create(ub["id"], "hash-b", "pfx")
    scoped_eng = EngagementRepository(mdb, tenant_ids={a["id"]})
    with pytest.raises(TenantAccessDenied):
        scoped_eng.get_raw(eb["id"])
    assert scoped_eng.replace(eb["id"], {"tenant_id": b["id"], "name": "pwn"}) is None
    assert scoped_eng.delete(eb["id"]) is False
    assert mdb["engagements"].find_one({"_id": eb["id"]})["name"] == "eb"
    assert ApiKeyRepository(mdb, tenant_ids={a["id"]}).revoke(kb["id"]) is None
    assert mdb["api_keys"].find_one({"_id": kb["id"]})["revoked_at"] is None
    assert ApiKeyRepository(mdb, tenant_ids={b["id"]}).revoke(kb["id"]) is not None


def test_credits_initial_grant_and_refund(mdb, monkeypatch):
    from attestra import config as cfg
    from attestra.persistence.mongo.repositories.ops import CreditRepository

    monkeypatch.setattr(cfg, "INITIAL_TEST_RUN_CREDITS", 3, raising=False)
    repo = CreditRepository(mdb)
    tx = repo.consume_for_scan_admit(7, actor="t", engagement_id=1, idempotency_key="k1")
    assert tx["balance_after"] == 2
    again = repo.refund(7, actor="t", debit_tx_id=tx["id"], reason="refund_pre_start")
    dup = repo.refund(7, actor="t", debit_tx_id=tx["id"], reason="refund_pre_start")
    assert again["id"] == dup["id"] and repo.get_account(7)["balance"] == 3
