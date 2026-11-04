"""Reports track (mongofull): remaining Report readers on MongoSession, incl. cross-tenant checks.

Covers integrations.grc, trust.service, verify.service, ops.retention and the webhook emitted on
sign. MongoSession has no Postgres RLS, so these readers go through
``attestra.reports.report_access`` (session / explicit tenant scope). Runs in mongo mode only:
``pytest tests/persistence/test_mongo_report_readers.py --persistence=mongo``.
"""
from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.mongo

ADMIN = SimpleNamespace(role="admin", actor="admin", username="admin", user_id=None, tenant_id=None)


def _m():
    from attestra.persistence.mongo.adapters import _db

    return _db()


@pytest.fixture
def signed(loaded, monkeypatch):
    """Tenant A engagement with one signed report (Mongo-owned) and an empty tenant B."""
    from attestra import config as cfg
    from attestra import db, services
    from attestra.models import Tenant
    from attestra.reports import render

    if cfg.PERSISTENCE_BACKEND != "mongo":
        pytest.skip("mongo-mode test: run with --persistence=mongo")
    monkeypatch.setenv("ATTESTRA_MONGO_READS", "domain")
    monkeypatch.setattr(render, "_assert_not_before_window", lambda *a, **k: None)
    emitted: list[dict] = []
    import attestra.webhooks.service as wh

    monkeypatch.setattr(wh, "emit", lambda s, event, **kw: emitted.append({"event": event, **kw}) or [])
    with db.session() as s:
        tenant_a = services.get_engagement(s, loaded).tenant_id
        b = Tenant(name="Other Tenant B")
        s.add(b)
        s.flush()
        tenant_b = b.id
        r = render.generate_report(s, loaded, kind="technical", actor="author", user_id=1)
        rid = r.id
    with db.session() as s:
        render.submit_report(s, rid, actor="author", user_id=1)
    with db.session() as s:
        render.qa_approve(s, rid, actor="qa", user_id=2)
    with db.session() as s:
        render.sign_report(s, rid, actor="lead", user_id=3, role="lead")
    assert tenant_a != tenant_b
    return SimpleNamespace(eid=loaded, rid=rid, a=tenant_a, b=tenant_b, emitted=emitted)


def test_session_is_mongo_and_report_is_mongo_owned(signed):
    from attestra import db

    doc = _m()["reports"].find_one({"_id": signed.rid})
    assert doc and doc["status"] == "signed" and doc["signature"]
    with db.session() as s:
        assert type(s).__name__ == "MongoSession"


def test_report_access_scoping(signed):
    from attestra import db
    from attestra.reports import render
    from attestra.reports.report_access import get_report_row, scoped_reports
    from attestra.models import Report
    from sqlalchemy import select

    with db.session() as s:
        assert get_report_row(s, signed.rid).id == signed.rid
        assert get_report_row(s, signed.rid, [signed.a]) is not None
        assert get_report_row(s, signed.rid, [signed.b]) is None
        assert render.get_report(s, signed.rid, tenant_ids=[signed.a]).id == signed.rid
        with pytest.raises(LookupError):
            render.get_report(s, signed.rid, tenant_ids=[signed.b])
    with db.session(tenant_ids=[signed.b]) as s:
        assert get_report_row(s, signed.rid) is None
        assert scoped_reports(s, s.scalars(select(Report))) == []
    with db.session(tenant_ids=[signed.a]) as s:
        assert [r.id for r in scoped_reports(s, s.scalars(select(Report)))] == [signed.rid]


def test_webhook_on_sign_uses_report_tenant(signed):
    ev = [e for e in signed.emitted if e["event"] == "report.signed"]
    assert len(ev) == 1
    assert ev[0]["tenant_id"] == signed.a and ev[0]["data"]["report_id"] == signed.rid


def test_grc_push_and_cross_tenant(signed):
    from attestra import db
    from attestra.integrations import grc

    pushed: list[dict] = []
    conn = SimpleNamespace(name="fake", push_signed_report=lambda meta: pushed.append(meta) or {"ok": True})
    with db.session(tenant_ids=[signed.b]) as s:
        with pytest.raises(LookupError):
            grc.push_signed_report(s, signed.rid, actor="t", connector=conn)
    assert pushed == []
    with db.session(tenant_ids=[signed.a]) as s:
        grc.push_signed_report(s, signed.rid, actor="t", connector=conn)
    assert pushed and pushed[0]["report_id"] == signed.rid


def test_verify_public_view(signed):
    from attestra import db
    from attestra.verify import service as verify

    sha = _m()["reports"].find_one({"_id": signed.rid})["sha256"]
    sig = verify.make_sig(signed.rid, sha)
    with db.session() as s:
        view = verify.public_view(s, signed.rid, sig)
    assert view is not None
    with db.session() as s:
        assert verify.public_view(s, signed.rid, "bad" + sig[3:]) is None
    with db.session(tenant_ids=[signed.b]) as s:
        assert verify.public_view(s, signed.rid, sig) is None


def test_trust_publish_status_and_cross_tenant(signed):
    from attestra import db
    from attestra.trust import service as trust

    with db.session() as s:
        with pytest.raises(trust.TrustError):
            trust.publish(s, ADMIN, signed.b, kind="report", title="steal", ref_id=signed.rid)
        item = trust.publish(s, ADMIN, signed.a, kind="report", title="Pentest report", ref_id=signed.rid)
        s.flush()
        st = trust.report_status(s, item)
    assert st["verified"] is True and st["kind"] == "technical"
    # an item in tenant B pointing at tenant A's report must not resolve
    with db.session() as s:
        from attestra.trust.models import TrustItem

        forged = TrustItem(tenant_id=signed.b, kind="report", title="forged", access="public", ref_id=signed.rid,
                           ref_key="", published_by="x")
        s.add(forged)
        s.flush()
        assert trust.report_status(s, forged) == {"verified": False, "reason": "report missing"}


def test_retention_reports_scoped(signed):
    from attestra import db
    from attestra.ops.retention import purge_expired

    _m()["reports"].update_one({"_id": signed.rid}, {"$set": {"generated_at": datetime(2000, 1, 1)}})
    with db.session(tenant_ids=[signed.b]) as s:
        assert purge_expired(s, dry_run=True)["candidates"]["reports"] == 0
    with db.session(tenant_ids=[signed.a]) as s:
        assert purge_expired(s, dry_run=True)["candidates"]["reports"] >= 1
    assert _m()["reports"].find_one({"_id": signed.rid})  # dry run deletes nothing