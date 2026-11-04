"""Reports track (mongofull): reports render from MongoDB and the sign-off workflow writes to it.

MongoDB is the only backend, so these run in mongo mode only:
``pytest tests/persistence/test_mongo_reports.py --persistence=mongo``. ``loaded`` builds the
engagement straight into a throwaway ``attestra_test_*`` database (MongoSession).
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime

import pytest

pytestmark = pytest.mark.mongo

FIXED_AT = datetime(2026, 11, 4, 6, 0, 0)
KINDS = [
    ("technical", ""),
    ("executive", ""),
    ("retest", ""),
    ("ageing", ""),
    ("owasp_top10", ""),
    ("compliance", "pci_dss_4"),
    ("iso_soa", "iso_27001_2022"),
]


def _m():
    from attestra.persistence.mongo.adapters import _db

    return _db()


@pytest.fixture
def eng(loaded, monkeypatch):
    """Mongo-mode ``loaded`` engagement with one validated finding under retest."""
    from attestra import config as cfg
    from attestra import db, services
    from attestra.models import Finding
    from attestra.reports import render
    from attestra.retest import request_retest

    if cfg.PERSISTENCE_BACKEND != "mongo":
        pytest.skip("MongoDB-only test: run with --persistence=mongo")
    monkeypatch.setattr(render, "_assert_not_before_window", lambda *a, **k: None)
    with db.session() as s:
        f = s.get(Finding, services.list_findings(s, loaded)[0].id)  # list_findings returns read-only views
        f.status = "validated"
        s.flush()
        request_retest(s, f.id, actor="tester", note="mongo retest")
    return loaded


def _render(eid, kind, framework):
    from attestra import db
    from attestra.reports import render

    with db.session() as s:
        return render.render_html(s, eid, kind=kind, framework=framework, version=3, actor="author",
                                  generated_at=FIXED_AT)


@pytest.mark.parametrize("kind,framework", KINDS)
def test_report_html_renders_and_is_deterministic(eng, kind, framework):
    one, two = _render(eng, kind, framework), _render(eng, kind, framework)
    assert one and one.startswith(b"<!doctype html>")
    assert hashlib.sha256(one).hexdigest() == hashlib.sha256(two).hexdigest()


def test_technical_numbering_consolidation_and_mongo_source(eng):
    html = _render(eng, "technical", "").decode("utf-8")
    labels = re.findall(r"\bF-(\d+)\b", html)
    assert labels and "1" in labels
    nums = sorted({int(n) for n in labels})
    assert nums == list(range(1, max(nums) + 1))  # contiguous F-1..F-n
    doc = _m()["findings"].find_one({"engagement_id": eng, "status": {"$ne": "false_positive"}},
                                    sort=[("risk_score", -1)])
    _m()["findings"].update_one({"_id": doc["_id"]}, {"$set": {"title": "MONGO-ONLY-TITLE-XYZ"}})
    _m()["import_runs"].update_many({"engagement_id": eng}, {"$set": {"filename": "mongo-only.json"}})
    html = _render(eng, "technical", "")
    assert b"MONGO-ONLY-TITLE-XYZ" in html and b"mongo-only.json" in html


def test_generate_sign_verify_and_audit(eng):
    from attestra import db
    from attestra.reports import render

    with db.session() as s:
        v1 = render.generate_report(s, eng, kind="technical", actor="author", user_id=1)
        r = render.generate_report(s, eng, kind="technical", actor="author", user_id=1)
        rid, sha = r.id, r.sha256
    assert (v1.version, r.version) == (1, 2)
    assert _m()["reports"].find_one({"_id": rid})["status"] == "draft"
    with db.session() as s:
        render.submit_report(s, rid, actor="author", user_id=1)
    with db.session() as s:
        with pytest.raises(Exception, match="four-eyes"):
            render.qa_approve(s, rid, actor="author", user_id=1)
        render.qa_approve(s, rid, actor="qa", user_id=2)
    with db.session() as s:
        with pytest.raises(Exception, match="four-eyes"):
            render.sign_report(s, rid, actor="qa", user_id=2, role="lead")
        signed = render.sign_report(s, rid, actor="lead", user_id=3, role="lead")
    assert signed.status == "signed" and signed.approved_by == "lead" and signed.algorithm and signed.signed_at
    with db.session() as s:
        v = render.verify_report(s, rid)
    assert v["status"] == "signed" and v["hash_matches"] and v["signature_valid"] and v["sha256"] == sha
    actions = {a["action"] for a in _m()["audit_events"].find({"entity": "report", "entity_id": rid})}
    assert {"report.generate", "report.submit", "report.qa_approve", "report.sign"} <= actions


def test_reject_loop_and_freeze_guard(eng):
    from attestra import db, services
    from attestra.persistence.mongo import report_store
    from attestra.reports import render

    with db.session() as s:
        rid = render.generate_report(s, eng, kind="executive", actor="author", user_id=1).id
        render.submit_report(s, rid, actor="author", user_id=1)
        r = render.qa_reject(s, rid, actor="qa", note="fix wording", user_id=2)
    assert r.status == "rejected" and r.rejection_note == "fix wording"
    with db.session() as s:
        render.submit_report(s, rid, actor="author", user_id=1)
        render.qa_approve(s, rid, actor="qa", user_id=2)
    # Freeze: a hash change between read and write must not be signed.
    _m()["reports"].update_one({"_id": rid}, {"$set": {"sha256": "0" * 64}})
    with db.session() as s:
        with pytest.raises((services.ServiceError, Exception)):
            render.sign_report(s, rid, actor="lead", user_id=3, role="lead")
    assert _m()["reports"].find_one({"_id": rid})["status"] == "qa_approved"
    with pytest.raises(ValueError):
        report_store.set_fields(rid, {"status": "signed"})


def test_report_reads_are_tenant_scoped(eng):
    from attestra import db
    from attestra.persistence.mongo import report_reads
    from attestra.reports import render

    tenant = _m()["engagements"].find_one({"_id": eng})["tenant_id"]
    with db.session() as s:
        rid = render.generate_report(s, eng, kind="technical", actor="author", user_id=1).id
    report_reads.engagement_doc(eng, tenant)
    with pytest.raises(LookupError):
        report_reads.engagement_doc(eng, int(tenant) + 999)
    assert report_reads.report(rid, tenant_ids=[tenant]) is not None
    assert report_reads.report(rid, tenant_ids=[int(tenant) + 999]) is None
    assert report_reads.report(rid, tenant_ids=[]) is None
    with pytest.raises(LookupError):
        report_reads.findings(eng, int(tenant) + 999)