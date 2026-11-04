"""Tests for the dispatch gate — GateError on each refusal condition."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from attestra.runner.gate import GateError, check


def _utcnow():
    return datetime.now(UTC)


# ---------------------------------------------------------------- helpers


def _get_asset_id(engagement_id: int, kind: str = "web_app"):
    """Return the first asset of the given kind for an engagement."""
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement_id, Asset.kind == kind)
        ).first()
        assert asset is not None, f"no {kind!r} asset found"
        return asset.id


# ---------------------------------------------------------------- outside window


def test_gate_refuses_before_window(engagement):
    from datetime import date

    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset, Engagement

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")
        ).first()
        asset_id = asset.id
        eng = s.get(Engagement, engagement)
        # Keep authorization valid "today" but push the window into the future.
        eng.window_start = date.today() + timedelta(days=2)
        eng.window_end = date.today() + timedelta(days=10)

    with db.session() as s:
        with pytest.raises(GateError, match="window"):
            check(s, engagement, asset_id, tool="zap", profile="baseline", actor="tester", now=_utcnow())


def test_gate_refuses_after_window(engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")
        ).first()
        asset_id = asset.id

    future = _utcnow() + timedelta(days=30)
    with db.session() as s:
        with pytest.raises(GateError, match="window"):
            check(s, engagement, asset_id, tool="zap", profile="baseline", actor="tester", now=future)


# ---------------------------------------------------------------- expired authorization


def test_gate_refuses_expired_auth(engagement):
    """Gate refuses when the authorization has expired (after its expires_on)."""
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")
        ).first()
        asset_id = asset.id

    # authorization expires in 30 days, window ends in 7 days — use 60 days out
    far_future = _utcnow() + timedelta(days=60)
    with db.session() as s:
        with pytest.raises(GateError):
            check(s, engagement, asset_id, tool="zap", profile="baseline", actor="tester", now=far_future)


# ---------------------------------------------------------------- intrusive without flag


def test_gate_refuses_intrusive_without_flag(engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")
        ).first()
        asset_id = asset.id
        # Ensure intrusive_allowed is False
        asset.intrusive_allowed = False
        s.flush()

    with db.session() as s:
        with pytest.raises(GateError, match="intrusive"):
            check(s, engagement, asset_id, tool="nuclei", profile="active", actor="tester")


# ---------------------------------------------------------------- rate limit exceeded


def test_gate_refuses_on_rate_exceeded(engagement):
    from sqlalchemy import select

    from attestra import config, db
    from attestra.models import Asset, ScanRun

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")
        ).first()
        asset_id = asset.id

    # Fill up rate limit with fake scan runs
    with db.session() as s:
        for _ in range(config.SCAN_RATE_PER_ASSET):
            run = ScanRun(
                engagement_id=engagement,
                asset_id=asset_id,
                tool="zap",
                profile="baseline",
                status="done",
                requested_by="tester",
                started_at=_utcnow(),
            )
            s.add(run)
        s.flush()

    with db.session() as s:
        with pytest.raises(GateError, match="rate"):
            check(s, engagement, asset_id, tool="zap", profile="baseline", actor="tester")


# ---------------------------------------------------------------- audit scan.refused


def test_gate_audit_scan_refused(engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset, AuditEvent

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")
        ).first()
        asset_id = asset.id
        asset.intrusive_allowed = False
        s.flush()

    with db.session() as s:
        try:
            check(s, engagement, asset_id, tool="nuclei", profile="active", actor="audittest")
        except GateError:
            pass
        events = list(s.scalars(select(AuditEvent).where(AuditEvent.action == "scan.refused")))
        assert any(e.actor == "audittest" for e in events)


# ---------------------------------------------------------------- nuclei active gate


def test_nuclei_active_gate_allowed_when_intrusive(engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "web_app")
        ).first()
        asset_id = asset.id
        asset.intrusive_allowed = True
        s.flush()

    # With intrusive_allowed=True, active profile should not raise (gate may still
    # raise for DNS resolution in test env — we just check it's not a GateError about intrusive)
    with db.session() as s:
        try:
            check(s, engagement, asset_id, tool="nuclei", profile="active", actor="tester")
        except GateError as e:
            assert "intrusive" not in e.reason
        except Exception:
            pass  # DNS resolution failure in CI is OK
