"""Web UI / REST API routes in ``ATTESTRA_PERSISTENCE=mongo`` (mongofull web/API track).

Routes reach data only through ``attestra.web.data_access``. In mongo mode identity
(cookie user, password sign-in, API keys) and audit come from Mongo; domain list
reads can be cut over with ``ATTESTRA_MONGO_READS=domain``. SQL rows created by the
fixtures reach Mongo through the dual-write mirrors. Runs against a throwaway
``attestra_test_*`` database only (``mongo_test_db``).
"""
from __future__ import annotations

import pytest

pytest.importorskip("pymongo")
pytestmark = pytest.mark.mongo


@pytest.fixture
def mongo_web(fresh_db, mongo_test_db, monkeypatch):
    import attestra.config as cfg

    monkeypatch.setattr(cfg, "PERSISTENCE_BACKEND", "mongo")
    monkeypatch.setenv("ATTESTRA_PERSISTENCE", "mongo")
    monkeypatch.delenv("ATTESTRA_MONGO_READS", raising=False)
    return mongo_test_db


def _app_client():
    from fastapi.testclient import TestClient

    from attestra.api import app

    return TestClient(app)


def _bearer(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def _disable_in_mongo(mdb, user_id: int) -> None:
    from attestra.persistence.mongo import collections as C

    assert mdb[C.USERS].update_one({"_id": int(user_id)}, {"$set": {"active": False}}).matched_count == 1


def test_bearer_auth_uses_mongo_identity(mongo_web, api_credentials):
    h = _bearer(api_credentials["lead_key"])
    with _app_client() as c:
        assert c.get("/api/engagements", headers=h).status_code == 200
        assert c.get("/api/engagements", headers=_bearer("atk_not-a-real-key")).status_code == 401
        # SQL row stays active; only the Mongo copy is disabled -> auth must refuse.
        _disable_in_mongo(mongo_web, api_credentials["lead_user_id"])
        assert c.get("/api/engagements", headers=h).status_code == 401


def test_ui_login_and_session_cookie_use_mongo_identity(mongo_web, api_credentials):
    with _app_client() as c:
        bad = c.post("/login", data={"username": "lead", "password": "wrong", "next": "/"}, follow_redirects=False)
        assert "attestra_session=" not in bad.headers.get("set-cookie", "")
    with _app_client() as c:
        r = c.post("/login", data={"username": "lead", "password": "test-pass-lead", "next": "/"}, follow_redirects=False)
        assert r.status_code == 303
        assert "attestra_session=" in r.headers.get("set-cookie", "")
        assert c.get("/api/engagements").status_code == 200  # cookie path of get_principal
        home = c.get("/", follow_redirects=False)
        assert home.status_code == 200
        _disable_in_mongo(mongo_web, api_credentials["lead_user_id"])
        assert c.get("/api/engagements").status_code == 401
        after = c.get("/", follow_redirects=False)
        assert after.status_code in (302, 303, 307) and "/login" in after.headers.get("location", "")


def test_audit_export_and_verify_read_the_mongo_chain(mongo_web, api_credentials, engagement):
    from attestra.persistence.mongo import collections as C

    h = _bearer(api_credentials["lead_key"])
    with _app_client() as c:
        body = c.get("/api/audit/export", headers=h).json()
        verify = c.get("/api/audit/verify", headers=h).json()
        csv_body = c.get("/api/audit/export?format=csv", headers=h).text
    mongo_ids = [d["_id"] for d in mongo_web[C.AUDIT_EVENTS].find({}, {"_id": 1}).sort("_id", 1)]
    assert mongo_ids, "engagement fixture should have written audit events to Mongo"
    assert [e["id"] for e in body["events"]] == mongo_ids
    assert body["proof"]["chain_ok"] is True and body["proof"]["count"] == len(mongo_ids)
    assert verify == {"ok": True, "first_bad_event": None}
    assert f"count={len(mongo_ids)}" in csv_body


def test_auditor_page_lists_mongo_audit_events(mongo_web, engagement):
    from attestra import db
    from attestra.auth.keys import create_user
    from attestra.persistence.mongo import collections as C

    with db.session() as s:
        create_user(s, username="aud", role="auditor", password="test-pass-aud")
    ev = mongo_web[C.AUDIT_EVENTS].find_one({"entity": "engagement", "entity_id": engagement})
    assert ev is not None
    with _app_client() as c:
        r = c.post("/login", data={"username": "aud", "password": "test-pass-aud", "next": "/"}, follow_redirects=False)
        assert r.status_code == 303
        page = c.get(f"/auditor/engagements/{engagement}")
    assert page.status_code == 200
    assert ev["action"] in page.text


def test_domain_list_reads_come_from_mongo(mongo_web, loaded):
    from attestra import db
    from attestra.web import data_access as da

    eid = loaded
    with db.session() as s:
        rows = da.import_runs_for_engagement(s, eid)
        assert rows and rows[0].engagement_id == eid and rows[0].tool  # attribute view of the document
        assert rows[0].no_such_field is None
        assert [r.id for r in rows] == sorted((r.id for r in rows), reverse=True)
        fids = [f.id for f in da.findings_for_engagement(s, eid)]
        assert fids
        for fid in fids:
            assert all(o.finding_id == fid for o in da.observations_for_finding(s, fid))
            assert all(p.finding_id == fid for p in da.proof_replays_for_finding(s, fid))
        assert all(r.engagement_id == eid for r in da.reports_for_engagement(s, eid))


def test_cutover_routes_keep_tenant_isolation(mongo_web, api_credentials, loaded, monkeypatch):
    from datetime import date, timedelta

    from attestra import db, services
    from attestra.auth.keys import create_api_key, create_user

    eid = loaded
    with db.session() as s:
        other = services.create_engagement(
            s, tenant="Other Client", name="Other", type="vapt", frameworks=["pci_dss_4"],
            window_start=date.today(), window_end=date.today() + timedelta(days=3), actor="tester",
        )
        outsider = create_user(s, username="outsider", role="tester", password="test-pass-out", tenant_id=other.tenant_id)
        _, out_key = create_api_key(s, outsider)
        fid = services.list_findings(s, eid)[0].id
    with _app_client() as c:
        mine = c.get(f"/api/findings/{fid}/observations", headers=_bearer(api_credentials["lead_key"]))
        assert mine.status_code == 200 and mine.json()["finding_id"] == fid
        theirs = c.get(f"/api/findings/{fid}/observations", headers=_bearer(out_key))
        assert theirs.status_code == 404
        listed = c.get("/api/engagements", headers=_bearer(out_key)).json()
        assert [e["id"] for e in listed] == [other.id]


def test_identity_helpers_on_mongo_session(fresh_db, api_credentials, engagement):
    from attestra import db
    from attestra.web import data_access as da

    with db.session() as s:
        assert len(da.audit_events(s)) > 0
        assert da.principal_for_uid(s, api_credentials["lead_user_id"]).username == "lead"
        assert da.authenticate_bearer(s, api_credentials["lead_key"]).username == "lead"
        assert da.authenticate_password(s, "lead", "nope") is None
