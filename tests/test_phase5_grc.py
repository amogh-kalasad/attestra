"""Phase 5 workflow: optional GRC evidence push (Vanta/Drata/Sprinto webhook)."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from attestra import db
from attestra.integrations import grc
from attestra.models import AuditEvent, Report


def _signed_report(s, engagement_id: int) -> Report:
    r = Report(
        engagement_id=engagement_id,
        kind="technical",
        version=1,
        path="reports/t.html",
        sha256="a" * 64,
        status="signed",
        generated_by="tester",
        approved_by="lead",
        signed_at=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
        algorithm="hmac-sha256",
        signature="sig",
    )
    s.add(r)
    s.flush()
    return r


# @lat: [[tests#Phase 5 workflow#GRC off by default]]
def test_grc_off_by_default(monkeypatch):
    monkeypatch.delenv("ATTESTRA_GRC_BACKEND", raising=False)
    monkeypatch.delenv("ATTESTRA_GRC_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("ATTESTRA_GRC_WEBHOOK_SECRET", raising=False)
    assert grc.connector_from_env({}) is None
    assert grc.safe_push_grc_report.__module__.endswith("grc")


# @lat: [[tests#Phase 5 workflow#GRC push signed metadata]]
def test_grc_push_posts_metadata_without_secret(engagement, monkeypatch, caplog):
    secret = "grc-webhook-secret-NEVER-LOG"
    sent = []

    def post(url, headers, body):
        sent.append((url, headers, body))
        assert url == "https://grc.example/hooks/attestra"
        assert headers.get("X-Attestra-Backend") == "vanta"
        assert headers.get("X-Attestra-Signature", "").startswith("sha256=")
        assert secret not in json.dumps(body)
        assert secret not in json.dumps(headers)
        return {"ok": True, "id": "ev-1"}

    monkeypatch.setenv("ATTESTRA_GRC_BACKEND", "vanta")
    monkeypatch.setenv("ATTESTRA_GRC_WEBHOOK_URL", "https://grc.example/hooks/attestra")
    monkeypatch.setenv("ATTESTRA_GRC_WEBHOOK_SECRET", secret)

    with db.session() as s:
        r = _signed_report(s, engagement)
        rid = r.id
        with caplog.at_level(logging.DEBUG):
            out = grc.push_signed_report(s, rid, actor="lead", connector=grc.connector_from_env(http_post=post))
        assert out == {"ok": True, "id": "ev-1"}
        rows = list(s.scalars(select(AuditEvent).where(AuditEvent.action == "report.grc_pushed")))
        assert len(rows) == 1
        assert rows[0].details.get("backend") == "vanta"
        assert secret not in str(rows[0].details)

    assert len(sent) == 1
    meta = sent[0][2]["report"]
    assert meta["report_id"] == rid
    assert meta["sha256"] == "a" * 64
    assert meta["kind"] == "technical"
    assert meta["download_hint"] == f"/reports/{rid}/sealed"
    assert secret not in caplog.text


# @lat: [[tests#Phase 5 workflow#GRC safe push no-op when off]]
def test_safe_push_noop_when_disabled(engagement, monkeypatch):
    monkeypatch.delenv("ATTESTRA_GRC_BACKEND", raising=False)
    with db.session() as s:
        r = _signed_report(s, engagement)
        assert grc.safe_push_grc_report(s, r.id, actor="system") is None
        assert list(s.scalars(select(AuditEvent).where(AuditEvent.action == "report.grc_pushed"))) == []


# @lat: [[tests#Phase 5 workflow#GRC rejects unsigned]]
def test_push_rejects_unsigned_and_bad_backend(engagement, monkeypatch):
    monkeypatch.setenv("ATTESTRA_GRC_BACKEND", "nope")
    with pytest.raises(grc.GrcError, match="unknown"):
        grc.connector_from_env(dict(ATTESTRA_GRC_BACKEND="nope", ATTESTRA_GRC_WEBHOOK_URL="https://x", ATTESTRA_GRC_WEBHOOK_SECRET="s"))

    with db.session() as s:
        r = Report(
            engagement_id=engagement,
            kind="executive",
            version=1,
            path="reports/e.html",
            sha256="b" * 64,
            status="draft",
            generated_by="tester",
        )
        s.add(r)
        s.flush()
        conn = grc.VantaConnector("https://grc.example/h", "sec", http_post=lambda *a, **k: {})
        with pytest.raises(grc.GrcError, match="not signed"):
            grc.push_signed_report(s, r.id, actor="lead", connector=conn)


# @lat: [[tests#Phase 5 workflow#GRC connector names]]
def test_named_connectors_and_repr_hide_secret():
    secret = "super-secret-value"
    for factory, name in (
        (grc.VantaConnector, "vanta"),
        (grc.DrataConnector, "drata"),
        (grc.SprintoConnector, "sprinto"),
    ):
        c = factory("https://hooks.example/x", secret, http_post=lambda *a, **k: {"ok": True})
        assert c.name == name
        assert secret not in repr(c)
        out = c.push_signed_report({"report_id": 1, "sha256": "c" * 64, "kind": "technical", "signed_at": "", "download_hint": "/reports/1/sealed"})
        assert out == {"ok": True}
