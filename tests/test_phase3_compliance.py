"""Phase 3: risk acceptance, ASV, schedules, OWASP, SLA."""
# @lat: [[tests#Phase 3 compliance tests#tests/test_phase3_compliance.py]]

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select


def test_asv_passing_makes_11_3_2_met(engagement):
    from attestra import db, services
    from attestra.compliance.engine import clear_library_cache

    clear_library_cache()
    with db.session() as s:
        before = {r.ref: r.status for r in services.compliance(s, engagement, "pci_dss_4")}
        assert before.get("11.3.2") in {"not_assessed", "not_met", "partial"}
        services.add_asv_scan(
            s, engagement,
            vendor="Qualys ASV",
            scan_date=date.today(),
            passing=True,
            filename="asv.txt",
            data=b"ASV PASS attestation",
            actor="tester",
        )
        after = {r.ref: r.status for r in services.compliance(s, engagement, "pci_dss_4")}
    assert after["11.3.2"] == "met"


def test_risk_acceptance_expires_and_reopens(loaded):
    from attestra import audit, db, services
    from attestra.models import Finding, RiskAcceptance

    with db.session() as s:
        f = s.scalars(select(Finding).where(Finding.engagement_id == loaded)).first()
        fid = f.id
        services.accept_risk(
            s, fid,
            expires_on=date.today() + timedelta(days=30),
            rationale="accepted temporarily for expiry test",
            actor="lead",
        )
        row = s.scalars(select(RiskAcceptance).where(RiskAcceptance.finding_id == fid)).first()
        row.expires_on = date.today() - timedelta(days=1)
        s.flush()
        n = services.expire_risk_acceptances(s, today=date.today(), actor="system")
        assert n >= 1
        f = s.get(Finding, fid)
        assert f.status == "validated"
        ok, _ = audit.verify(s)
        assert ok


def test_risk_accept_rejects_past_expiry(loaded):
    from attestra import db, services
    from attestra.models import Finding
    from attestra.services import ServiceError

    with db.session() as s:
        f = s.scalars(select(Finding).where(Finding.engagement_id == loaded)).first()
        with pytest.raises(ServiceError, match="expires_on"):
            services.accept_risk(
                s, f.id,
                expires_on=date.today() - timedelta(days=1),
                rationale="too late",
                actor="lead",
            )


def test_owasp_cwe_89_maps_to_a03(loaded):
    from attestra import db
    from attestra.compliance.owasp import map_finding_to_owasp
    from attestra.models import Finding

    with db.session() as s:
        f = s.scalars(select(Finding).where(Finding.engagement_id == loaded, Finding.cwe == 89)).first()
        assert f is not None, "fixture SARIF should produce CWE-89"
        refs = map_finding_to_owasp(f)
        assert refs["owasp_top10"].startswith("A03")
        assert "A03" in (f.owasp_top10 or refs["owasp_top10"])


def test_sla_breach_lists_old_critical(engagement):
    from attestra import db, services
    from attestra.models import Finding

    with db.session() as s:
        old = datetime(2020, 1, 1, tzinfo=UTC)
        f = Finding(
            engagement_id=engagement,
            fingerprint="sla" + "0" * 61,
            title="Old critical",
            severity="critical",
            status="validated",
            first_seen=old,
            last_seen=old,
            sla_due=date.today() - timedelta(days=5),
        )
        s.add(f)
        s.flush()
        breaches = services.sla_breaches(s, engagement, today=date.today())
        assert any(b.id == f.id for b in breaches)


def test_scan_schedule_enqueues(engagement, monkeypatch):
    from attestra import db, services
    from attestra.models import Asset, ScanRun, ScanSchedule

    def fake_request(s, eid, *, asset_id, tool, profile="baseline", actor="system"):
        run = ScanRun(
            engagement_id=eid, asset_id=asset_id, tool=tool, profile=profile,
            status="queued", requested_by=actor,
        )
        s.add(run)
        s.flush()
        return run

    monkeypatch.setattr(services, "request_scan", fake_request)
    with db.session() as s:
        asset = s.scalars(select(Asset).where(Asset.engagement_id == engagement)).first()
        sch = services.add_scan_schedule(
            s, engagement,
            asset_id=asset.id,
            tool="nuclei",
            cadence="quarterly",
            next_due=date.today() - timedelta(days=1),
            actor="lead",
        )
        sid = sch.id
        runs = services.enqueue_due_schedules(s, today=date.today(), actor="system")
        assert runs
        sch = s.get(ScanSchedule, sid)
        assert sch.last_enqueued_at is not None
        assert sch.next_due >= date.today()


def test_segmentation_and_iso_soa_report(engagement):
    from attestra import db, services
    from attestra.reports import generate_report

    with db.session() as s:
        services.add_segmentation_test(
            s, engagement,
            boundary="CDE / corporate",
            method="port scan + firewall review",
            result="pass",
            tested_on=date.today(),
            actor="tester",
        )
        results = {r.ref: r.status for r in services.compliance(s, engagement, "pci_dss_4")}
        assert results.get("11.4.5") == "met"
        r = generate_report(s, engagement, kind="iso_soa", actor="tester", framework="iso_27001_2022")
        assert "Statement of Applicability" in open(r.path, encoding="utf-8").read()


def test_ageing_report(engagement):
    from attestra import db
    from attestra.models import Finding
    from attestra.reports import generate_report

    with db.session() as s:
        s.add(
            Finding(
                engagement_id=engagement,
                fingerprint="age" + "1" * 61,
                title="Aged critical",
                severity="critical",
                status="new",
                sla_due=date.today() - timedelta(days=40),
            )
        )
        s.flush()
        r = generate_report(s, engagement, kind="ageing", actor="tester")
        body = open(r.path, encoding="utf-8").read()
        assert "Aged critical" in body


def test_new_pci_controls_in_rollup(loaded):
    from attestra import db, services
    from attestra.compliance.engine import clear_library_cache

    clear_library_cache()
    with db.session() as s:
        refs = {r.ref for r in services.compliance(s, loaded, "pci_dss_4")}
    for ref in ("11.3.2", "11.4.5", "12.3.1", "6.4.2"):
        assert ref in refs
