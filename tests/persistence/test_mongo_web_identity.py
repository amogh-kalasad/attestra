"""Users / webhooks / email-alert / Certification Authority routes and evidence download.

Routes write through ``users.mongo_service``, ``webhooks.mongo_service`` and
``attestra.web.settings_store`` into Mongo. Runs against a throwaway
``attestra_test_*`` database only (``mongo_test_db``).
"""
from __future__ import annotations

from datetime import date, timedelta

import pytest

pytest.importorskip("pymongo")
pytestmark = pytest.mark.mongo

PASSWORD = "Correct-Horse-9"


@pytest.fixture
def mongo_web(fresh_db, mongo_test_db, monkeypatch):
    import attestra.config as cfg

    monkeypatch.setattr(cfg, "PERSISTENCE_BACKEND", "mongo")
    monkeypatch.setenv("ATTESTRA_PERSISTENCE", "mongo")
    monkeypatch.delenv("ATTESTRA_MONGO_READS", raising=False)
    return mongo_test_db


@pytest.fixture
def offline_webhooks(monkeypatch):
    """Test-only Fernet key for webhook secrets + deterministic public DNS (no network)."""
    import socket as _socket

    from cryptography.fernet import Fernet

    monkeypatch.setenv("ATTESTRA_CREDENTIAL_FERNET_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL", raising=False)

    def _fake_getaddrinfo(host, *a, **k):
        return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(_socket, "getaddrinfo", _fake_getaddrinfo)


def _client():
    from fastapi.testclient import TestClient

    from attestra.api import app

    return TestClient(app)


def _bearer(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def _sql_user(username: str, role: str, tenant_id: int | None = None) -> tuple[int, str]:
    """Create a user + API key via MongoSession."""
    from attestra import db
    from attestra.auth.keys import create_api_key, create_user

    with db.session() as s:
        u = create_user(s, username=username, role=role, password=PASSWORD, tenant_id=tenant_id)
        _, key = create_api_key(s, u)
        return u.id, key


def _tenant_of(eid: int) -> int:
    from attestra import db, services

    with db.session() as s:
        return services.get_engagement(s, eid).tenant_id


def _other_tenant() -> int:
    from attestra import db, services

    with db.session() as s:
        other = services.create_engagement(
            s, tenant="Other Client", name="Other", type="vapt", frameworks=["pci_dss_4"],
            window_start=date.today(), window_end=date.today() + timedelta(days=3), actor="tester",
        )
        return other.tenant_id


def _login(c, username: str, password: str = PASSWORD) -> None:
    r = c.post("/login", data={"username": username, "password": password, "next": "/"}, follow_redirects=False)
    assert r.status_code == 303 and "attestra_session=" in r.headers.get("set-cookie", "")


def test_user_invite_accept_disable_go_through_mongo(mongo_web, engagement):
    from attestra.persistence.mongo import collections as C

    tid = _tenant_of(engagement)
    _, admin_key = _sql_user("root", "admin")
    h = _bearer(admin_key)
    with _client() as c:
        r = c.post("/api/users/invites", headers=h, json={"email": "New.Tester@example.com", "role": "tester",
                                                          "tenant_id": tid})
        assert r.status_code == 201, r.text
        inv = r.json()
        assert inv["purpose"] == "invite" and inv["tenant_id"] == tid and inv["token"] and inv["expires_at"]
        assert mongo_web[C.USER_INVITES].find_one({"_id": inv["id"]}) is not None
        assert [i["id"] for i in c.get("/api/users/invites", headers=h).json()] == [inv["id"]]

        acc = c.post("/api/invites/accept", json={"token": inv["token"], "username": "newbie", "password": PASSWORD})
        assert acc.status_code == 201, acc.text
        uid = acc.json()["id"]
        assert acc.json() == {"id": uid, "username": "newbie", "role": "tester"}
        assert mongo_web[C.USERS].find_one({"_id": uid, "username": "newbie", "active": True})
        again = c.post("/api/invites/accept", json={"token": inv["token"], "username": "newbie2", "password": PASSWORD})
        assert again.status_code == 400

        assert "newbie" in [u["username"] for u in c.get("/api/users", headers=h).json()]
        assert c.post(f"/api/users/{uid}/role", headers=h, json={"role": "reviewer"}).json() == {"id": uid, "role": "reviewer"}
        assert c.post(f"/api/users/{uid}/disable", headers=h).json() == {"id": uid, "active": False}
        assert mongo_web[C.USERS].find_one({"_id": uid})["active"] is False
        assert c.post(f"/api/users/{uid}/enable", headers=h).json() == {"id": uid, "active": True}
        assert c.post("/api/users/999999/disable", headers=h).status_code == 404

        reset = c.post(f"/api/users/{uid}/reset-password", headers=h)
        assert reset.status_code == 201 or reset.status_code == 200, reset.text
        assert c.get(f"/reset/{reset.json()['token']}").status_code == 200
        done = c.post("/api/password-reset", json={"token": reset.json()["token"], "password": "Another-Horse-77"})
        assert done.json() == {"id": uid, "username": "newbie"}

    with _client() as c:  # new Mongo-only user signs in through the Mongo identity path
        _login(c, "newbie", "Another-Horse-77")
    with _client() as c:
        _login(c, "root")
        page = c.get("/users")
        assert page.status_code == 200 and "newbie" in page.text


def test_ui_invite_and_token_pages_use_mongo(mongo_web, engagement):
    from attestra.persistence.mongo import collections as C

    tid = _tenant_of(engagement)
    _sql_user("root", "admin")
    with _client() as c:
        _login(c, "root")
        r = c.post("/users/invite", data={"email": "ui@example.com", "role": "tester", "tenant_id": str(tid)})
        assert r.status_code == 200 and "/invite/" in r.text
    inv = mongo_web[C.USER_INVITES].find_one({"email": "ui@example.com"})
    assert inv is not None
    with _client() as c:
        assert c.get("/invite/not-a-token").status_code == 200  # renders "invalid" page, no 500


def test_webhook_and_rule_routes_use_mongo(mongo_web, api_credentials, engagement, offline_webhooks):
    from attestra.persistence.mongo import collections as C

    tid = _tenant_of(engagement)
    _, outsider_key = _sql_user("lead-b", "lead", tenant_id=_other_tenant())
    h = _bearer(api_credentials["lead_key"])
    with _client() as c:
        r = c.post("/api/webhooks", headers=h, json={"tenant_id": tid, "url": "https://hooks.example.com/in",
                                                      "name": "siem", "events": ["finding.created"]})
        assert r.status_code == 201, r.text
        ep = r.json()
        assert ep["secret"] and ep["tenant_id"] == tid and ep["active"] is True
        doc = mongo_web[C.WEBHOOK_ENDPOINTS].find_one({"_id": ep["id"]})
        assert doc is not None and "secret" not in doc and doc.get("secret_enc")
        assert [e["id"] for e in c.get("/api/webhooks", headers=h).json()] == [ep["id"]]
        assert c.post("/api/webhooks", headers=h, json={"tenant_id": 999999, "url": "https://hooks.example.com/x"}
                      ).status_code == 404
        assert c.post("/api/webhooks", headers=h, json={"tenant_id": tid, "url": "https://hooks.example.com/x",
                                                        "format": "nope"}).status_code == 400

        rule = c.post("/api/workflow-rules", headers=h, json={"tenant_id": tid, "action": "notify",
                                                              "endpoint_id": ep["id"], "min_severity": "high"})
        assert rule.status_code == 201, rule.text
        rid = rule.json()["id"]
        assert mongo_web[C.WORKFLOW_RULES].find_one({"_id": rid}) is not None
        assert [x["id"] for x in c.get("/api/workflow-rules", headers=h).json()] == [rid]
        assert c.get(f"/api/webhooks/{ep['id']}/deliveries", headers=h).json() == []
        assert c.post("/api/webhooks/dispatch", headers=h).json() == {"attempted": 0, "delivered": 0}

        o = _bearer(outsider_key)  # lead of another tenant
        assert c.get("/api/webhooks", headers=o).json() == []
        assert c.get("/api/workflow-rules", headers=o).json() == []
        assert c.delete(f"/api/webhooks/{ep['id']}", headers=o).status_code == 404
        assert c.get(f"/api/webhooks/{ep['id']}/deliveries", headers=o).status_code == 404
        assert c.post(f"/api/workflow-rules/{rid}/deactivate", headers=o).status_code == 404
        assert c.post("/api/workflow-rules", headers=o, json={"tenant_id": tid, "action": "assign",
                                                              "assignee": "x"}).status_code == 404

        assert c.post(f"/api/workflow-rules/{rid}/deactivate", headers=h).json()["active"] is False
        assert c.delete(f"/api/webhooks/{ep['id']}", headers=h).json()["active"] is False
    assert mongo_web[C.WEBHOOK_ENDPOINTS].find_one({"_id": ep["id"]})["active"] is False
    assert mongo_web[C.WORKFLOW_RULES].find_one({"_id": rid})["active"] is False


def test_alert_settings_routes_use_mongo(mongo_web, api_credentials, engagement):
    from attestra.persistence.mongo import collections as C

    tid = _tenant_of(engagement)
    _, outsider_key = _sql_user("lead-b", "lead", tenant_id=_other_tenant())
    h = _bearer(api_credentials["lead_key"])
    with _client() as c:
        fresh = c.get(f"/api/alerts/settings?tenant_id={tid}", headers=h)
        assert fresh.status_code == 200, fresh.text
        assert fresh.json()["recipients"] == [] and fresh.json()["notify_new_high"] is True
        r = c.put(f"/api/alerts/settings?tenant_id={tid}", headers=h,
                  json={"recipients": ["SecOps@Example.com", "secops@example.com"], "notify_sla_missed": False})
        assert r.status_code == 200, r.text
        assert r.json()["recipients"] == ["secops@example.com"] and r.json()["notify_sla_missed"] is False
        assert r.json()["updated_by"] and r.json()["updated_at"]
        doc = mongo_web[C.EMAIL_ALERT_SETTINGS].find_one({"tenant_id": tid})
        assert doc["recipients"] == ["secops@example.com"] and doc["notify_sla_missed"] is False
        got = c.get(f"/api/alerts/settings?tenant_id={tid}", headers=h).json()
        assert got["recipients"] == ["secops@example.com"] and "known_emails" in got
        assert c.put(f"/api/alerts/settings?tenant_id={tid}", headers=h, json={"recipients": ["not-an-email"]}
                     ).status_code == 400
        assert mongo_web[C.EMAIL_ALERT_SETTINGS].find_one({"tenant_id": tid})["recipients"] == ["secops@example.com"]

        o = _bearer(outsider_key)
        assert c.get(f"/api/alerts/settings?tenant_id={tid}", headers=o).status_code == 404
        assert c.put(f"/api/alerts/settings?tenant_id={tid}", headers=o, json={"recipients": []}).status_code == 404
    with _client() as c:
        _login(c, "lead", "test-pass-lead")
        page = c.get(f"/settings/alerts?tenant_id={tid}")
        assert page.status_code == 200 and "secops@example.com" in page.text
    assert mongo_web[C.AUDIT_EVENTS].find_one({"action": "alert.settings.update"}) is not None
    assert mongo_web[C.EMAIL_ALERT_SETTINGS].find_one({"tenant_id": tid}) is not None


def test_certification_authority_routes_use_mongo(mongo_web, api_credentials):
    from attestra.persistence.mongo import collections as C

    _, admin_key = _sql_user("root", "admin")
    h = _bearer(admin_key)
    with _client() as c:
        assert c.get("/api/certification-authority", headers=h).json()["legal_name"] == ""
        r = c.put("/api/certification-authority", headers=h,
                  json={"legal_name": "Acme Certification Ltd", "contact_email": "CA@Example.com", "city": "Pune"})
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["legal_name"] == "Acme Certification Ltd" and out["city"] == "Pune" and out["updated_by"]
        doc = mongo_web[C.CERTIFICATION_AUTHORITY].find_one({"_id": 1})
        assert doc["legal_name"] == "Acme Certification Ltd" and doc["city"] == "Pune"
        assert doc["contact_email"] == out["contact_email"]
        assert c.put("/api/certification-authority", headers=h, json={"contact_email": "nope"}).status_code == 400
        assert c.put("/api/certification-authority", headers=_bearer(api_credentials["reviewer_key"]),
                     json={"legal_name": "Evil"}).status_code == 403
        assert c.get("/api/certification-authority", headers=_bearer(api_credentials["reviewer_key"])).status_code == 403
        got = c.get("/api/certification-authority", headers=h).json()
        assert got["legal_name"] == "Acme Certification Ltd" and got["city"] == "Pune"
    with _client() as c:
        _login(c, "root")
        page = c.get("/settings/certification-authority")
        assert page.status_code == 200 and "Acme Certification Ltd" in page.text
    assert mongo_web[C.AUDIT_EVENTS].find_one({"action": "certification_authority.update"}) is not None
    assert mongo_web[C.CERTIFICATION_AUTHORITY].find_one({"_id": 1})["legal_name"] == "Acme Certification Ltd"


def test_evidence_download_serves_bytes_and_stays_tenant_scoped(mongo_web, api_credentials, loaded):
    from attestra import db, services
    from attestra.persistence.mongo import collections as C

    with db.session() as s:
        fid = services.list_findings(s, loaded)[0].id
        evid = services.add_evidence(s, fid, kind="note", filename="dl.txt", data=b"download me", note="",
                                     actor="tester").id
    _, outsider_key = _sql_user("out-t", "tester", tenant_id=_other_tenant())
    with _client() as c:
        r = c.get(f"/api/evidence/{evid}/download", headers=_bearer(api_credentials["lead_key"]))
        assert r.status_code == 200 and r.content == b"download me"
        assert r.headers["content-disposition"] == 'attachment; filename="dl.txt"'
        assert c.get(f"/api/evidence/{evid}/download", headers=_bearer(outsider_key)).status_code == 404
        assert c.get("/api/evidence/999999/download", headers=_bearer(api_credentials["lead_key"])).status_code == 404
    with _client() as c:
        _login(c, "lead", "test-pass-lead")
        ui = c.get(f"/engagements/{loaded}/evidence/{evid}/download")
        assert ui.status_code == 200 and ui.content == b"download me"
    assert mongo_web[C.AUDIT_EVENTS].count_documents({"action": "evidence.download", "entity_id": evid}) == 2
