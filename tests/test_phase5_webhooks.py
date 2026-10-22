"""Phase 5: webhook delivery, HMAC signatures, retry/backoff (fake sender only)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from attestra import db
from attestra.models import Engagement, WebhookDelivery, utcnow
from attestra.webhooks import formats
from attestra.webhooks import service as wh
from attestra.webhooks.guard import WebhookUrlError, check_url

PUBLIC = lambda host: ["93.184.216.34"]  # noqa: E731


def _tenant(s, eid: int) -> int:
    return s.get(Engagement, eid).tenant_id


# @lat: [[tests#Phase 5 workflow#Successful signed delivery]]
def test_successful_delivery_marks_delivered_and_verifies(engagement):
    captured: list[tuple[bytes, dict[str, str]]] = []

    def sender(ep, body: bytes, headers: dict[str, str]) -> int:
        captured.append((body, dict(headers)))
        return 200

    with db.session() as s:
        tid = _tenant(s, engagement)
        ep = wh.create_endpoint(
            s, tid, url="https://hooks.example.com/in", actor="lead", resolver=PUBLIC,
            events=["report.signed"],
        )
        deliveries = wh.emit(s, "report.signed", tenant_id=tid, data={"report_id": 1})
        assert len(deliveries) == 1
        d = deliveries[0]
        now = utcnow()
        out = wh.dispatch_due(s, sender=sender, now=now)
        assert out == [d]
        assert d.status == "delivered"
        assert d.delivered_at is not None
        assert d.attempts == 1
        assert d.last_status_code == 200
        assert d.last_error == ""

    assert len(captured) == 1
    body, headers = captured[0]
    assert formats.TS_HEADER in headers
    assert formats.SIG_HEADER in headers
    assert headers["X-Attestra-Event"] == "report.signed"
    assert formats.verify(ep.secret, body, headers[formats.TS_HEADER], headers[formats.SIG_HEADER])


# @lat: [[tests#Phase 5 workflow#Retry backoff then failed]]
def test_non_2xx_schedules_retry_then_marks_failed(engagement):
    with db.session() as s:
        tid = _tenant(s, engagement)
        wh.create_endpoint(s, tid, url="https://hooks.example.com/in", actor="lead", resolver=PUBLIC)
        wh.emit(s, "report.signed", tenant_id=tid, data={"report_id": 1})
        d = s.scalars(select(WebhookDelivery)).one()
        now = utcnow()

        assert wh.dispatch_due(s, sender=lambda *a: 503, now=now) == [d]
        assert d.status == "pending"
        assert d.attempts == 1
        assert d.last_error == "HTTP 503"
        assert d.last_status_code == 503
        expected = now + timedelta(seconds=wh.BACKOFF_SECONDS[0])
        assert d.next_attempt_at == expected

        for attempt in range(2, wh.MAX_ATTEMPTS + 1):
            now = d.next_attempt_at
            assert wh.dispatch_due(s, sender=lambda *a: 503, now=now) == [d]
            assert d.attempts == attempt
            if attempt < wh.MAX_ATTEMPTS:
                assert d.status == "pending"
                assert d.next_attempt_at == now + timedelta(seconds=wh.BACKOFF_SECONDS[attempt - 1])
            else:
                assert d.status == "failed"
                assert d.last_error == "HTTP 503"


# @lat: [[tests#Phase 5 workflow#Inactive endpoint fails cleanly]]
def test_bad_and_inactive_endpoint_fail_cleanly(engagement):
    with pytest.raises(WebhookUrlError):
        check_url("https://hooks.example.com/x", resolver=lambda host: ["10.0.0.1"])
    with pytest.raises(wh.WebhookError, match="blocked|non-global|internal"):
        with db.session() as s:
            tid = _tenant(s, engagement)
            wh.create_endpoint(
                s, tid, url="https://hooks.example.com/x", actor="lead",
                resolver=lambda host: ["127.0.0.1"],
            )

    with db.session() as s:
        tid = _tenant(s, engagement)
        ep = wh.create_endpoint(
            s, tid, url="https://hooks.example.com/in", actor="lead", resolver=PUBLIC,
        )
        deliveries = wh.emit(s, "report.signed", tenant_id=tid, data={"report_id": 9})
        d = deliveries[0]
        wh.deactivate_endpoint(s, ep.id, actor="lead")
        called = []

        def sender(ep_, body, headers):
            called.append(1)
            return 200

        wh.deliver(s, d, sender=sender)
        assert d.status == "failed"
        assert d.last_error == "endpoint inactive"
        assert d.attempts == 0
        assert called == []


# @lat: [[tests#Phase 5 workflow#Verify rejects bad signature and expired timestamp]]
def test_verify_rejects_wrong_signature_and_expired_timestamp():
    body = b'{"id":1}'
    ts, sig = formats.sign("secret", body, ts="1000")
    assert formats.verify("secret", body, ts, sig, now=1000.0) is True
    assert formats.verify("secret", body, ts, "sha256=deadbeef", now=1000.0) is False
    assert formats.verify("other", body, ts, sig, now=1000.0) is False
    assert formats.verify("secret", b'{"id":2}', ts, sig, now=1000.0) is False
    # Default tolerance is 300s; 1000 + 301 is expired.
    assert formats.verify("secret", body, ts, sig, now=1301.0) is False
    assert formats.verify("secret", body, "not-a-ts", sig, now=1000.0) is False
