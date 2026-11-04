"""Service-level mongo mode: email-alert settings/dedup, CA report branding and webhook emit.

``alerts.service`` / ``certification.service`` read and write the settings repositories, and
``webhooks.service.emit`` delegates to ``webhooks.mongo_service`` so SQL-side callers
(services.py, retest, scans) need no edits. Runs on a throwaway ``attestra_test_*`` DB only.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("pymongo")
pytestmark = pytest.mark.mongo


@pytest.fixture
def mongo_mode(fresh_db, mongo_test_db, monkeypatch):
    import attestra.config as cfg

    monkeypatch.setattr(cfg, "PERSISTENCE_BACKEND", "mongo")
    monkeypatch.setenv("ATTESTRA_PERSISTENCE", "mongo")
    monkeypatch.delenv("ATTESTRA_MONGO_READS", raising=False)
    return mongo_test_db


def _admin():
    return SimpleNamespace(actor="admin:test", role="admin", tenant_id=None, user_id=None, username="admin")


def _tenant_of(eid: int) -> int:
    from attestra import db, services

    with db.session() as s:
        return services.get_engagement(s, eid).tenant_id


def test_alert_settings_recipients_and_dedup_in_mongo(mongo_mode, engagement):
    from attestra.alerts import service as alerts
    from attestra.persistence.mongo import collections as C

    tid = _tenant_of(engagement)
    assert alerts.get_settings(None, tid) is None
    assert alerts._recipients_for(None, tid, event=alerts.EVENT_NEW_HIGH) == []
    row = alerts.update_settings(None, _admin(), tid, recipients=["Ops@Example.com"], notify_sla_missed=False)
    assert row.recipients == ["ops@example.com"] and row.notify_sla_missed is False
    assert alerts._recipients_for(None, tid, event=alerts.EVENT_NEW_HIGH) == ["ops@example.com"]
    assert alerts._recipients_for(None, tid, event=alerts.EVENT_SLA_MISSED) == []
    with pytest.raises(alerts.AlertError):
        alerts.update_settings(None, _admin(), tid, recipients=["nope"])
    with pytest.raises(LookupError):
        alerts.update_settings(None, _admin(), 987654, recipients=[])
    assert not alerts._already_sent(None, alerts.EVENT_NEW_HIGH, "finding", 42)
    alerts._mark_sent(None, tid, alerts.EVENT_NEW_HIGH, "finding", 42)
    alerts._mark_sent(None, tid, alerts.EVENT_NEW_HIGH, "finding", 42)
    assert alerts._already_sent(None, alerts.EVENT_NEW_HIGH, "finding", 42)
    assert mongo_mode[C.AUDIT_EVENTS].find_one({"action": "alert.settings.update"}) is not None


def test_ca_report_branding_reads_mongo(mongo_mode):
    from attestra.certification import service as ca

    assert ca.report_branding(None)["legal_name"] == ""
    row = ca.update_settings(None, _admin(), legal_name="Acme Cert Ltd", contact_email="ca@example.com")
    assert row.legal_name == "Acme Cert Ltd"
    assert ca.report_branding(None)["legal_name"] == "Acme Cert Ltd"
    assert ca.get_settings(None).contact_email == "ca@example.com"
    with pytest.raises(ca.CertificationError):
        ca.update_settings(None, _admin(), contact_email="bad")


def test_sql_emit_delegates_to_mongo_webhooks(mongo_mode, engagement, monkeypatch):
    import socket as _socket

    from cryptography.fernet import Fernet

    from attestra.persistence.mongo import collections as C
    from attestra.webhooks import mongo_service as mwh
    from attestra.webhooks import service as wh

    monkeypatch.setenv("ATTESTRA_CREDENTIAL_FERNET_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(_socket, "getaddrinfo",
                        lambda *a, **k: [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))])
    tid = _tenant_of(engagement)
    ep, _secret = mwh.create_endpoint(mongo_mode, None, tid, url="https://hooks.example.com/x", actor="t",
                                      events=["finding.created"])
    finding = SimpleNamespace(id=7, engagement_id=engagement, title="XSS", severity="high", status="open",
                              risk_score=8.0, location="/", asset_id=None)
    out = wh.emit(None, "finding.created", tenant_id=tid, data=wh.finding_data(finding), finding=finding)
    assert len(out) == 1
    assert mongo_mode[C.WEBHOOK_DELIVERIES].count_documents({"endpoint_id": ep["id"]}) == 1
    # safe_emit_* keep their SQL engagement lookup but land deliveries in Mongo
    from attestra import db

    with db.session() as s:
        wh.safe_emit_finding(s, finding, "finding.created")
    assert mongo_mode[C.WEBHOOK_DELIVERIES].count_documents({"endpoint_id": ep["id"]}) == 2
