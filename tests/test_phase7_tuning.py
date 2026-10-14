"""Phase 7.4: per-tenant risk weights, expiring suppression rules, false-positive rate."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from attestra import scoring

FIX = Path(__file__).parent / "fixtures"


def test_default_scoring_unchanged():
    assert scoring.risk_score(7.5, "high", criticality=5, exposure="internet") == round(7.5 * 1.4 * 1.3, 2)
    assert scoring.risk_score(7.5, "high", criticality=5, exposure="internet", weights=None) == round(7.5 * 1.4 * 1.3, 2)


def test_weights_override():
    w = scoring.RiskWeights(criticality={5: 2.0}, internet=1.0, cde=1.8)
    assert scoring.asset_weight(5, w) == 2.0
    assert scoring.asset_weight(3, w) == pytest.approx(1.0)  # falls back to default curve
    assert scoring.exposure_weight("internet", False, w) == 1.0
    assert scoring.exposure_weight("internal", True, w) == 1.8
    assert scoring.exposure_weight("internal", False, w) == 1.0


def _tenant_id(s, eid):
    from attestra.models import Engagement

    return s.get(Engagement, eid).tenant_id


def test_set_weights_rescores_and_audits(loaded):
    from sqlalchemy import select

    from attestra import audit, db, tuning
    from attestra.models import AuditEvent, Finding

    with db.session() as s:
        tid = _tenant_id(s, loaded)
        before = {f.id: f.risk_score for f in s.scalars(select(Finding))}
        tuning.set_weights(s, tid, actor="lead", criticality={5: 3.0}, internet=1.3, cde=1.3)
        after = {f.id: f.risk_score for f in s.scalars(select(Finding))}
        assert any(after[i] > before[i] for i in before)
        assert s.scalars(select(AuditEvent).where(AuditEvent.action == "tenant.risk_weights")).first()
        assert audit.verify(s) == (True, None)
        tuning.clear_weights(s, tid, actor="lead")
        assert {f.id: f.risk_score for f in s.scalars(select(Finding))} == before


def test_set_weights_validation(engagement):
    from attestra import db, tuning

    with db.session() as s:
        tid = _tenant_id(s, engagement)
        with pytest.raises(tuning.TuningError):
            tuning.set_weights(s, tid, actor="lead", criticality={6: 1.0})
        with pytest.raises(tuning.TuningError):
            tuning.set_weights(s, tid, actor="lead", internet=50)


def test_suppression_drops_matching_findings(engagement):
    from sqlalchemy import select

    from attestra import db, services, tuning
    from attestra.models import AuditEvent, utcnow

    with db.session() as s:
        tid = _tenant_id(s, engagement)
        rule = tuning.create_suppression(
            s, tid, actor="lead", reason="Accepted test key, rotated", tool="gitleaks",
            location_contains="services/payments", expires_at=utcnow() + timedelta(days=30),
        )
        run = services.import_results(
            s, engagement, tool="gitleaks", filename="gitleaks.json",
            data=(FIX / "gitleaks" / "gitleaks.json").read_bytes(), actor="tester",
        )
        assert run.new_findings == 0
        assert rule.hits == 1
        ev = s.scalars(select(AuditEvent).where(AuditEvent.action == "import.create")).all()[-1]
        assert ev.details["suppressed"] == 1
        assert s.scalars(select(AuditEvent).where(AuditEvent.action == "suppression.create")).first()

        tuning.revoke_suppression(s, rule.id, actor="lead")
        run2 = services.import_results(
            s, engagement, tool="gitleaks", filename="gitleaks.json",
            data=(FIX / "gitleaks" / "gitleaks.json").read_bytes(), actor="tester",
        )
        assert run2.new_findings == 1


def test_expired_suppression_does_not_match(engagement):
    from attestra import db, tuning
    from attestra.models import utcnow

    with db.session() as s:
        tid = _tenant_id(s, engagement)
        rule = tuning.create_suppression(
            s, tid, actor="lead", reason="temp", rule_id="aws-access-token",
            expires_at=utcnow() + timedelta(days=1),
        )
        rule.expires_at = utcnow() - timedelta(seconds=1)
        s.flush()
        assert tuning.active_suppressions(s, tid, engagement) == []


def test_suppression_validation(engagement):
    from attestra import db, tuning
    from attestra.models import utcnow

    with db.session() as s:
        tid = _tenant_id(s, engagement)
        soon = utcnow() + timedelta(days=1)
        with pytest.raises(tuning.TuningError, match="reason"):
            tuning.create_suppression(s, tid, actor="lead", reason=" ", tool="zap", expires_at=soon)
        with pytest.raises(tuning.TuningError, match="at least one"):
            tuning.create_suppression(s, tid, actor="lead", reason="x", expires_at=soon)
        with pytest.raises(tuning.TuningError, match="future"):
            tuning.create_suppression(s, tid, actor="lead", reason="x", tool="zap", expires_at=utcnow() - timedelta(days=1))
        with pytest.raises(tuning.TuningError, match="at most"):
            tuning.create_suppression(s, tid, actor="lead", reason="x", tool="zap", expires_at=utcnow() + timedelta(days=400))
        with pytest.raises(tuning.TuningError, match="tenant"):
            tuning.create_suppression(s, tid + 999, actor="lead", reason="x", tool="zap", expires_at=soon, engagement_id=engagement)


def test_fp_rate_by_tool(loaded):
    from sqlalchemy import select

    from attestra import db, tuning
    from attestra.models import Finding

    with db.session() as s:
        f = s.scalars(select(Finding).where(Finding.status == "new")).first()
        f.status = "false_positive"
        s.flush()
        rows = {r["tool"]: r for r in tuning.fp_rate_by_tool(s)}
        tool = f.tools[0]
        assert rows[tool]["false_positive"] >= 1
        assert 0 < rows[tool]["rate"] <= 1
        tid = _tenant_id(s, loaded)
        assert tuning.fp_rate_by_tool(s, {tid + 999}) == []


def test_fp_rate_dashboard(loaded):
    from fastapi.testclient import TestClient
    from sqlalchemy import select

    from attestra import db
    from attestra.api import app
    from attestra.auth.keys import create_user
    from attestra.models import Finding

    with db.session() as s:
        create_user(s, username="fpadmin", role="admin", password="pw-123456", display_name="FP")
        f = s.scalars(select(Finding).where(Finding.status == "new")).first()
        f.status = "false_positive"
        tool = f.tools[0]
    with TestClient(app) as c:
        assert c.get("/tuning/false-positives", follow_redirects=False).status_code in (302, 303)
        r = c.post("/login", data={"username": "fpadmin", "password": "pw-123456"}, follow_redirects=False)
        assert r.status_code in (302, 303)
        r = c.get("/tuning/false-positives")
        assert r.status_code == 200
        assert "False-positive rate by tool" in r.text and tool in r.text
        assert "/tuning/false-positives" in c.get("/").text
