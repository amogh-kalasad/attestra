"""Mongo-mode end-to-end (enqueue -> worker -> scan run -> report sign) and single audit chain.

Uses throwaway ``attestra_test_*`` databases only (dropped afterwards).
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from tests.persistence.test_mongo_jobflow import _mongo_available, _runs, mdb, mongo_mode  # noqa: F401

pytestmark = pytest.mark.skipif(not _mongo_available(), reason="MongoDB replica set not available")


def _fake_scanner(monkeypatch, tmp_path):
    from attestra.jobs import durable

    raw = tmp_path / "out.json"
    raw.write_text("{}", encoding="utf-8")
    res = SimpleNamespace(extra={}, error="", quarantine=False, quarantine_reason="", raw_path=raw,
                          tool_version="1", image_digest="sha256:x", import_tool="trivy")
    monkeypatch.setattr(durable, "check", lambda *a, **k: "target")
    monkeypatch.setattr(durable, "get_adapter", lambda tool: SimpleNamespace(scan=lambda *a, **k: res))
    monkeypatch.setattr(durable.services, "import_results", lambda *a, **k: SimpleNamespace(id=None, notes_json=""))
    import attestra.webhooks.service as wh

    monkeypatch.setattr(wh, "safe_emit_scan", lambda *a, **k: None)


def test_e2e_enqueue_worker_scan_report_signed(mongo_mode, mdb, monkeypatch, tmp_path):
    from attestra import audit, db
    from attestra.jobs.pool import WorkerPool
    from attestra.models import ScanRun
    from attestra.reports import render

    _fake_scanner(monkeypatch, tmp_path)
    monkeypatch.setattr(render, "_assert_not_before_window", lambda *a, **k: None)
    [(run_id, job_id)] = _runs(mongo_mode, 1)
    pool = WorkerPool(worker_id="e2e", concurrency=1, housekeeping=False, log=lambda m: None)
    assert pool.tick() == 1 and pool.wait_idle(20)
    assert mdb["jobs"].find_one({"_id": job_id})["status"] == "done"

    with db.session() as s:
        assert s.get(ScanRun, run_id).status == "done"
        rep = render.generate_report(s, mongo_mode, kind="technical", actor="author")
        rid = rep.id
    with db.session() as s:
        render.submit_report(s, rid, actor="author", user_id=1)
    with db.session() as s:
        render.qa_approve(s, rid, actor="qa", user_id=2)

    errors, ok = [], []

    def sign(i):
        try:
            with db.session() as s:
                render.sign_report(s, rid, actor=f"lead{i}", user_id=10 + i, role="lead")
            ok.append(i)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    ts = [threading.Thread(target=sign, args=(i,)) for i in range(4)]
    [t.start() for t in ts]
    [t.join(60) for t in ts]
    assert len(ok) == 1, (ok, errors)
    assert mdb["audit_events"].count_documents({"action": "report.sign", "entity_id": rid}) == 1
    actions = {d["action"] for d in mdb["audit_events"].find({}, {"action": 1})}
    assert {"job.complete", "report.submit", "report.qa_approve", "report.sign"} <= actions
    assert audit.verify(None) == (True, None)


def test_evidence_read_resolves_gridfs_with_tenant_check(mongo_mode, mdb, monkeypatch):
    from attestra import config as cfg
    from attestra import services

    monkeypatch.setattr(cfg, "STORAGE_BACKEND", "mongo")
    path = services._store(5, "evidence", "ab" * 32, "shot.txt", b"BODY-123")
    assert path.read_bytes().startswith(b"mongo://")
    assert services.read_evidence_bytes(path, 5) == b"BODY-123"
    with pytest.raises(LookupError):
        services.read_evidence_bytes(path, 6)


def test_tenant_ids_and_scoped_getters_use_mongo_memberships(mongo_mode, mdb):
    from sqlalchemy import select

    from attestra import db, services
    from attestra.models import Asset, Engagement

    with db.session() as s:
        tid = s.get(Engagement, mongo_mode).tenant_id
        aid = s.scalars(select(Asset).where(Asset.engagement_id == mongo_mode)).first().id
    member = SimpleNamespace(role="tester", tenant_id=None, user_id=9001)
    outsider = SimpleNamespace(role="tester", tenant_id=tid + 1000, user_id=9002)
    viewer = SimpleNamespace(role="client_viewer", tenant_id=None, user_id=9003)
    mdb["tenant_memberships"].insert_one({"_id": 777001, "user_id": 9001, "tenant_id": tid})
    with db.session() as s:
        assert services.tenant_ids_for(s, member) == {tid}
        assert services.tenant_ids_for(s, viewer) == set()
        assert services.tenant_ids_for(s, SimpleNamespace(role="admin", tenant_id=None, user_id=1)) is None
        assert [e.id for e in services.list_engagements(s, member)] == [mongo_mode]
        assert services.list_engagements(s, outsider) == []
        assert services.get_asset(s, aid, member).id == aid
        with pytest.raises(LookupError):
            services.get_asset(s, aid, outsider)
        with pytest.raises(LookupError):
            services.get_finding(s, 987654, member)
        with pytest.raises(LookupError):
            services.get_report(s, 987654, member)
