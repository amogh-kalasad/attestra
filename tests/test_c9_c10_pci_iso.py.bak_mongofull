"""C9 (PCI calendar, segmentation, ASV import) and C10 (ISO SoA, NC/CA, 9.2 sampling)."""
from __future__ import annotations

import json
import zipfile
from datetime import date, timedelta

import pytest

from attestra import db, services
from attestra.importers import asv
from tests.conftest import FIXTURES

ASV_JSON = (FIXTURES / "asv" / "asv_results.json").read_bytes()
ASV_CSV = (FIXTURES / "asv" / "asv_results.csv").read_bytes()


# ------------------------------------------------------------- importer

def test_asv_json_fixture_parses_and_fails_on_cvss_4():
    r = asv.parse(ASV_JSON)
    assert r.vendor == "Example ASV Ltd" and r.scan_date == date(2026, 9, 15)
    assert len(r.items) == 3
    assert [i.passing for i in r.items] == [False, True, True]
    assert r.failing_count == 1 and r.passing is False


def test_asv_csv_fixture_passes():
    r = asv.parse(ASV_CSV)
    assert r.passing is True and len(r.items) == 2 and r.items[1].port == 22


def test_asv_explicit_overall_and_errors():
    doc = {"vendor": "V", "scan_date": "2026-01-02", "passing": "pass", "components": [{"host": "h", "cvss": 9.8}]}
    assert asv.parse(json.dumps(doc).encode()).passing is True
    with pytest.raises(ValueError):
        asv.parse(b'{"vendor": "V", "scan_date": "nope"}')
    with pytest.raises(ValueError):
        asv.parse(b'{"scan_date": "2026-01-02"}')
    with pytest.raises(ValueError):
        asv.parse(b"")


# ------------------------------------------------------------- C9 services

def _import(eid, data=ASV_JSON, name="asv.json"):
    with db.session() as s:
        row = services.import_asv_results(s, eid, filename=name, data=data, actor="tester")
        return row.id, row.passing, row.item_count, row.failing_count


def test_import_asv_results_stores_items_and_audits(engagement):
    sid, passing, items, failing = _import(engagement)
    assert (passing, items, failing) == (False, 3, 1)
    from attestra.models import AsvScan, AuditEvent

    with db.session() as s:
        row = s.get(AsvScan, sid)
        assert row.source == "import" and len(row.items) == 3 and len(row.sha256) == 64
        assert any(e.action == "asv.import" for e in s.query(AuditEvent).all())


def test_import_asv_bad_file_is_service_error(engagement):
    with db.session() as s, pytest.raises(services.ServiceError):
        services.import_asv_results(s, engagement, filename="x.json", data=b"{bad", actor="t")


def test_pci_calendar_due_overdue_done(engagement):
    today = date(2026, 10, 14)  # 2026-Q4
    with db.session() as s:
        cal = services.pci_scan_calendar(s, engagement, today=today)
    assert [q["quarter"] for q in cal["quarters"]] == ["2026-Q4", "2026-Q3", "2026-Q2", "2026-Q1"]
    assert cal["quarters"][0]["status"] == "due" and cal["quarters"][0]["days_left"] == 78
    assert cal["quarters"][1]["status"] == "overdue" and cal["status"] == "overdue"
    # passing scans for every quarter -> current done
    for d in ("2026-01-10", "2026-04-10", "2026-07-10", "2026-10-01"):
        doc = {"vendor": "V", "scan_date": d, "components": [{"host": "h", "cvss": 0}]}
        _import(engagement, json.dumps(doc).encode(), f"{d}.json")
    with db.session() as s:
        cal = services.pci_scan_calendar(s, engagement, today=today)
        overview = services.pci_calendar_overview(s, None, today=today)
    assert all(q["status"] == "done" for q in cal["quarters"]) and cal["status"] == "done"
    assert overview[0]["engagement_id"] == engagement


def test_pci_calendar_failing_scan_is_not_done(engagement):
    _import(engagement)  # failing, 2026-09-15 (Q3)
    with db.session() as s:
        cal = services.pci_scan_calendar(s, engagement, today=date(2026, 10, 14))
    q3 = cal["quarters"][1]
    assert q3["external_scans"] == 1 and q3["external_passing"] == 0 and q3["status"] == "overdue"


def test_segmentation_record_details_and_validation(engagement):
    with db.session() as s:
        t = services.add_segmentation_test(
            s, engagement, boundary="CDE / corp", method="nmap from corp VLAN", result="PASS",
            tested_on=date.today(), source_zone="corp", target_zone="cde", notes="no open paths", actor="tester",
        )
        assert t.result == "pass" and t.tester == "tester" and t.target_zone == "cde"
        with pytest.raises(services.ServiceError):
            services.add_segmentation_test(s, engagement, boundary="x", method="", result="maybe",
                                           tested_on=date.today(), actor="t")
        assert len(services.list_segmentation_tests(s, engagement)) == 1


# ------------------------------------------------------------- C10 services

def test_soa_generate_update_and_justification_rule(engagement):
    with db.session() as s:
        added = services.generate_soa(s, engagement, actor="lead")
        assert added > 0
        assert services.generate_soa(s, engagement, actor="lead") == 0  # idempotent
        rows = services.list_soa(s, engagement)
        first = rows[0]
        with pytest.raises(services.ServiceError):
            services.update_soa_entry(s, engagement, first.id, applicable=False, justification="",
                                      implementation="planned", actor="lead")
        services.update_soa_entry(s, engagement, first.id, applicable=False, justification="No such process",
                                  implementation="planned", actor="lead")
        assert first.applicable is False and first.implementation == "not_implemented"


def test_nonconformity_corrective_action_workflow(engagement):
    with db.session() as s:
        nc = services.add_nonconformity(s, engagement, control_ref="A.8.8", corrective_action="",
                                        owner="ops", description="Patch SLA missed", grade="major", actor="lead")
        assert nc.status == "open" and nc.grade == "major"
        with pytest.raises(services.ServiceError):
            services.update_nonconformity(s, engagement, nc.id, status="closed", verified_by="qa", actor="lead")
        services.update_nonconformity(s, engagement, nc.id, status="in_progress", root_cause="no owner",
                                      corrective_action="Weekly patch window", actor="lead")
        with pytest.raises(services.ServiceError):
            services.update_nonconformity(s, engagement, nc.id, status="closed", actor="lead")
        services.update_nonconformity(s, engagement, nc.id, status="closed", verified_by="meera", actor="lead")
        assert nc.status == "closed" and nc.closed_at and nc.verified_by == "meera"
        with pytest.raises(services.ServiceError):
            services.update_nonconformity(s, engagement, nc.id, status="open", actor="lead")
        with pytest.raises(services.ServiceError):
            services.add_nonconformity(s, engagement, control_ref="A.1", corrective_action="", owner="",
                                       grade="huge", actor="lead")


def test_default_sample_size():
    # Shared Type II table (same as SOC 2 / compliance.sampling).
    assert services.default_sample_size(3) == 2
    assert services.default_sample_size(10) == 2
    assert services.default_sample_size(100) == 25


def test_audit_sample_is_reproducible_from_seed(engagement):
    with db.session() as s:
        services.generate_soa(s, engagement, actor="lead")
        a = services.draw_audit_sample(s, engagement, actor="lead", seed="abc")
        b = services.draw_audit_sample(s, engagement, actor="lead", seed="abc")
        assert a.items == b.items and a.clause == "9.2" and a.sample_size == len(a.items)
        assert set(a.items) <= {r.control_ref for r in services.list_soa(s, engagement) if r.applicable}
        c = services.draw_audit_sample(s, engagement, actor="lead", sample_size=1)
        assert len(c.items) == 1 and c.seed
        with pytest.raises(services.ServiceError):
            services.draw_audit_sample(s, engagement, actor="lead", population="nonconformities")
        with pytest.raises(services.ServiceError):
            services.draw_audit_sample(s, engagement, actor="lead", sample_size=10_000)
        assert len(services.list_audit_samples(s, engagement)) == 3


# ------------------------------------------------------------- packs

def _pack_names(eid, fw):
    from attestra.reports.packs import build_framework_pack

    with db.session() as s:
        path = build_framework_pack(s, eid, fw)
    with zipfile.ZipFile(path) as z:
        return set(z.namelist()), z.read("MANIFEST.sha256").decode()


def test_packs_include_pci_and_iso_records(engagement):
    _import(engagement)
    with db.session() as s:
        services.generate_soa(s, engagement, actor="lead")
        services.add_nonconformity(s, engagement, control_ref="A.8.8", corrective_action="fix", owner="o",
                                   description="d", actor="lead")
        services.draw_audit_sample(s, engagement, actor="lead", seed="x")
    names, manifest = _pack_names(engagement, "pci_dss_4")
    assert {"pci/scan_calendar.csv", "pci/asv_scans.csv", "pci/segmentation_tests.csv"} <= names
    assert "pci/asv_scans.csv" in manifest
    names, manifest = _pack_names(engagement, "iso_27001_2022")
    assert {"iso/statement_of_applicability.csv", "iso/nonconformities.csv", "iso/audit_samples_9_2.json"} <= names
    assert "iso/nonconformities.csv" in manifest


# ------------------------------------------------------------- API and UI

def _engagement_via_services():
    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s, tenant="API Client", name="PCI ISO", type="va", frameworks=["pci_dss_4", "iso_27001_2022"],
            window_start=today - timedelta(days=1), window_end=today + timedelta(days=30), actor="lead",
        )
        return e.id


def test_api_asv_import_calendar_soa_sample(client):
    eid = _engagement_via_services()
    r = client.post(f"/api/engagements/{eid}/asv/import", files={"file": ("asv.json", ASV_JSON, "application/json")})
    assert r.status_code == 201, r.text
    assert r.json()["items"] == 3 and r.json()["passing"] is False
    r = client.get(f"/api/engagements/{eid}/pci/calendar")
    assert r.status_code == 200 and len(r.json()["quarters"]) == 4
    assert client.post(f"/api/engagements/{eid}/iso/soa/generate").json()["added"] > 0
    assert client.get(f"/api/engagements/{eid}/iso/soa").json()
    r = client.post(f"/api/engagements/{eid}/iso/samples", json={"seed": "s1"})
    assert r.status_code == 201 and r.json()["items"]
    r = client.post(f"/api/engagements/{eid}/asv/import", files={"file": ("bad.json", b"{x", "application/json")})
    assert r.status_code in (400, 409, 422)


def test_ui_pci_and_iso_pages(client):
    eid = _engagement_via_services()
    client.headers.pop("Authorization", None)
    r = client.post("/login", data={"username": "lead", "password": "test-pass-lead"}, follow_redirects=False)
    assert r.status_code == 303
    r = client.post(f"/engagements/{eid}/asv/import", files={"file": ("asv.csv", ASV_CSV, "text/csv")},
                    follow_redirects=False)
    assert r.status_code == 303 and "error" not in r.headers["location"]
    r = client.post(f"/engagements/{eid}/pci/segmentation", follow_redirects=False, data={
        "boundary": "CDE", "result": "pass", "tested_on": date.today().isoformat(), "target_zone": "cde"})
    assert "error" not in r.headers["location"]
    page = client.get(f"/engagements/{eid}/pci")
    assert page.status_code == 200 and "Example ASV Ltd" in page.text and "cde" in page.text
    assert client.get("/compliance/pci-calendar").status_code == 200
    client.post(f"/engagements/{eid}/iso/soa/generate", follow_redirects=False)
    r = client.post(f"/engagements/{eid}/iso/nc", follow_redirects=False, data={
        "control_ref": "A.8.8", "description": "Missed patch", "grade": "minor", "corrective_action": "patch"})
    assert "error" not in r.headers["location"]
    r = client.post(f"/engagements/{eid}/iso/sample", data={"seed": "z"}, follow_redirects=False)
    assert "error" not in r.headers["location"]
    page = client.get(f"/engagements/{eid}/iso")
    assert page.status_code == 200 and "Missed patch" in page.text and "Statement of Applicability" in page.text
