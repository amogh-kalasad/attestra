"""Phase 0 critical integrity and security fixes from the Gap Implementation Plan."""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from sqlalchemy import func, select


# @lat: [[tests#Phase 0 integrity#Auditor ownership of confirmations]]
def test_lead_cannot_confirm_control(loaded):
    from attestra import db, services
    from attestra.models import AuditEvent
    from attestra.services import ServiceError

    with db.session() as s:
        results = services.compliance(s, loaded, "pci_dss_4")
        # Prefer a process control with no open findings (e.g. authorization).
        ref = next((r.ref for r in results if not r.finding_ids), results[0].ref)
        with pytest.raises(ServiceError, match="not allowed"):
            services.confirm_control(
                s, loaded, framework="pci_dss_4", ref=ref, status="partial",
                assessor="priya.lead", rationale="lead trying to confirm", role="lead",
            )
        refused = list(
            s.scalars(select(AuditEvent).where(AuditEvent.action == "control.confirm_refused"))
        )
        assert refused, "lead confirm attempt must write control.confirm_refused"
        assert any(e.actor == "priya.lead" for e in refused)


def test_auditor_can_confirm_and_lead_cannot_overwrite(loaded):
    from attestra import db, services
    from attestra.services import ServiceError

    with db.session() as s:
        results = services.compliance(s, loaded, "pci_dss_4")
        ref = next((r.ref for r in results if not r.finding_ids), results[0].ref)
        a = services.confirm_control(
            s, loaded, framework="pci_dss_4", ref=ref, status="partial",
            assessor="rahul.qsa", rationale="auditor review", role="auditor",
        )
        aid, status_before = a.id, a.status
    with db.session() as s:
        from attestra.models import ControlAssessment

        with pytest.raises(ServiceError, match="not allowed"):
            services.confirm_control(
                s, loaded, framework="pci_dss_4", ref=ref, status="met",
                assessor="priya.lead", rationale="overwrite", role="lead",
            )
        row = s.get(ControlAssessment, aid)
        assert row is not None
        assert row.status == status_before
        assert row.assessor == "rahul.qsa"


def test_lead_api_confirm_returns_403(client, loaded):
    """Lead Bearer POST to compliance/confirm returns 403 and commits the refuse audit."""
    from attestra import db, services
    from attestra.models import AuditEvent

    with db.session() as s:
        results = services.compliance(s, loaded, "pci_dss_4")
        ref = next((r.ref for r in results if not r.finding_ids), results[0].ref)
        before = s.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.action == "control.confirm_refused"
            )
        ) or 0

    r = client.post(
        f"/api/engagements/{loaded}/compliance/confirm",
        json={
            "framework": "pci_dss_4",
            "ref": ref,
            "status": "partial",
            "rationale": "lead API confirm attempt",
        },
    )
    assert r.status_code == 403
    assert "not allowed" in r.json()["detail"]

    with db.session() as s:
        after = s.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.action == "control.confirm_refused"
            )
        ) or 0
        assert after > before, "API lead confirm must commit control.confirm_refused"


# @lat: [[tests#Phase 0 integrity#Block met with open findings]]
def test_met_refused_while_open_findings(loaded):
    from attestra import db, services
    from attestra.services import ServiceError

    with db.session() as s:
        results = services.compliance(s, loaded, "cert_in_2022")
        with_open = [r for r in results if r.finding_ids]
        if not with_open:
            results = services.compliance(s, loaded, "pci_dss_4")
            with_open = [r for r in results if r.finding_ids]
        assert with_open, "fixture should map open findings to at least one control"
        ref = with_open[0].ref
        fw = with_open[0].framework
        with pytest.raises(ServiceError, match=r"open findings.*F-\d+") as ei:
            services.confirm_control(
                s, loaded, framework=fw, ref=ref, status="met",
                assessor="rahul.qsa", rationale="should fail", role="auditor",
            )
        assert "(" in str(ei.value) and ":" in str(ei.value)
        # Override allowed when explicitly requested.
        a = services.confirm_control(
            s, loaded, framework=fw, ref=ref, status="met",
            assessor="rahul.qsa", rationale="accepted residual risk",
            role="auditor", allow_open_findings_override=True,
        )
        assert a.status == "met"
        assert "override" in a.rationale


def test_met_allowed_when_only_low_or_info_open(loaded):
    """P0-2: low/info open mapped findings alone do not block confirming met."""
    from attestra import db, services
    from attestra.models import Finding

    with db.session() as s:
        results = services.compliance(s, loaded, "pci_dss_4")
        with_open = [r for r in results if r.finding_ids]
        if not with_open:
            pytest.skip("fixture has no control with mapped open findings")
        ctrl = with_open[0]
        for fid in ctrl.finding_ids:
            f = s.get(Finding, fid)
            if f is not None and f.status in ("new", "triaged", "validated"):
                f.severity = "low"
        s.flush()
        a = services.confirm_control(
            s, loaded, framework=ctrl.framework, ref=ctrl.ref, status="met",
            assessor="rahul.qsa", rationale="only low residual findings",
            role="auditor",
        )
        assert a.status == "met"


# @lat: [[tests#Phase 0 integrity#Risk acceptance record required]]
def test_bare_risk_accepted_transition_refused(loaded):
    from attestra import db, services
    from attestra.services import ServiceError

    with db.session() as s:
        f = services.list_findings(s, loaded)[0]
        if f.status == "new":
            services.transition(s, f.id, to="triaged", actor="tester")
        with pytest.raises(ServiceError, match="risk-acceptance record"):
            services.transition(s, f.id, to="risk_accepted", actor="tester", note="just a note")


def test_accept_risk_creates_record_and_status(loaded):
    from attestra import db, services

    with db.session() as s:
        f = next(x for x in services.list_findings(s, loaded) if x.status in ("new", "triaged", "validated"))
        row = services.accept_risk(
            s, f.id, expires_on=date.today() + timedelta(days=30),
            rationale="Compensating control in place", actor="lead", owner_user_id=None,
        )
        s.refresh(f)
        assert f.status == "risk_accepted"
        assert row.finding_id == f.id
        assert row.rationale.startswith("Compensating")


def test_cli_accept_risk_and_transition_still_refuses(loaded, capsys):
    """CLI accept-risk wires to services.accept_risk; bare transition still refused."""
    from attestra import cli, db, services
    from attestra.models import Finding

    with db.session() as s:
        f = next(x for x in services.list_findings(s, loaded) if x.status in ("new", "triaged", "validated"))
        fid = f.id
        if f.status == "new":
            services.transition(s, fid, to="triaged", actor="tester")

    with pytest.raises(SystemExit) as ei:
        cli.main(["transition", str(fid), "risk_accepted", "--note", "bare flip"])
    assert ei.value.code == 2
    err = capsys.readouterr().err
    assert "risk-acceptance record" in err

    expires = (date.today() + timedelta(days=30)).isoformat()
    cli.main(
        [
            "accept-risk",
            str(fid),
            "--expires-on",
            expires,
            "--rationale",
            "CLI compensating control",
        ]
    )
    out = capsys.readouterr().out
    assert f"F-{fid}" in out
    assert "risk_accepted" in out

    with db.session() as s:
        assert s.get(Finding, fid).status == "risk_accepted"


# @lat: [[tests#Phase 0 integrity#Share untested grade]]
def test_share_untested_shows_no_grade(fresh_db):
    from attestra import db, services
    from attestra.auth.keys import Principal, create_user
    from attestra.share import service as share

    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s, tenant="Share Co", name="Untested share", type="va",
            frameworks=["pci_dss_4"], window_start=today, window_end=today + timedelta(days=7),
            actor="lead",
        )
        a = services.add_asset(
            s, e.id, kind="web_app", identifier="https://untested.example.com",
            name="Untested", environment="production", criticality=3, exposure="internet",
            in_cde=False, actor="lead",
        )
        user = create_user(
            s, username="share.lead", role="lead", password="demo-lead-pass-xx",
            display_name="Share Lead", tenant_id=e.tenant_id,
        )
        principal = Principal(
            user_id=user.id, username=user.username, display_name=user.display_name,
            role=user.role, tenant_id=e.tenant_id,
        )
        _row, token = share.create_share(s, principal, kind="grade", asset_id=a.id, ttl_days=7)
        view = share.public_view(s, token)
        assert view is not None
        assert view["untested"] is True
        assert view["grade"] is None
        assert view["score"] is None
        svg = share.badge_svg(s, token)
        assert svg and "Not tested" in svg


# @lat: [[tests#Phase 0 integrity#Metrics require auth]]
def test_metrics_unauthenticated_denied(client, monkeypatch):
    from attestra import observability as obs

    monkeypatch.setattr(obs, "METRICS_TOKEN", "")
    monkeypatch.setattr(obs, "METRICS_ALLOW_ANON", False)
    assert client.get("/metrics").status_code == 401


def test_metrics_token_allows(client, monkeypatch):
    from attestra import observability as obs

    monkeypatch.setattr(obs, "METRICS_TOKEN", "s3cret")
    monkeypatch.setattr(obs, "METRICS_ALLOW_ANON", False)
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer s3cret"}).status_code == 200


# @lat: [[tests#Phase 0 integrity#Risk acceptance is partial evidence]]
def test_risk_acceptance_only_partial_for_soc2_and_dora(loaded):
    from attestra import db, services
    from attestra.compliance.engine import clear_library_cache

    clear_library_cache()
    with db.session() as s:
        f = services.list_findings(s, loaded)[0]
        services.accept_risk(
            s, f.id, expires_on=date.today() + timedelta(days=14),
            rationale="temporary accept", actor="lead",
        )
        soc2 = {r.ref: r for r in services.compliance(s, loaded, "soc2")}
        dora = {r.ref: r for r in services.compliance(s, loaded, "dora_2022")}
    # Proposed status (before auditor confirm) must not be met from acceptance alone.
    if "CC3.2" in soc2:
        assert soc2["CC3.2"].proposed != "met"
        assert soc2["CC3.2"].proposed in ("partial", "not_assessed", "no_exceptions", "not_met")
    if "Art.6" in dora:
        assert dora["Art.6"].proposed != "met"
        assert dora["Art.6"].proposed in ("partial", "not_assessed", "no_exceptions", "not_met")
