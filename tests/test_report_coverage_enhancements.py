"""Report coverage enhancements from the consolidated good-to-have features DOCX."""

from __future__ import annotations

from pathlib import Path

import pytest

from attestra.models import ENGAGEMENT_TYPES
from attestra.reports.render import KINDS


def test_retest_kind_registered():
    assert "retest" in KINDS


# @lat: [[tests#Report coverage enhancements#Template config metadata]]
def test_template_config_covers_assessment_types_and_frameworks():
    from attestra.reports.template_config import load_template_config

    cfg = load_template_config()
    assert cfg["template_id"] == "attestra_builtin"
    for t in ENGAGEMENT_TYPES:
        assert t in cfg["supported_assessment_types"]
    assert len(cfg["supported_frameworks"]) == 9
    assert "retest" in cfg["kinds"]
    assert "technical" in cfg["kinds"]
    assert cfg["cvss_legend"]["critical"]
    assert cfg["disclaimer"]


# @lat: [[tests#Report coverage enhancements#Nine frameworks load]]
def test_nine_frameworks_load():
    from attestra.compliance.engine import clear_library_cache, load_library

    clear_library_cache()
    lib = load_library()
    expected = {
        "pci_dss_4",
        "iso_27001_2022",
        "soc2",
        "iso_42001_2023",
        "cert_in_2022",
        "nist_csf_2",
        "rbi_csf_2016",
        "sebi_cscrf_2024",
        "dora_2022",
    }
    assert expected <= set(lib.frameworks)


# @lat: [[tests#Report coverage enhancements#Stored fields rendered in technical report]]
def test_technical_renders_stored_fields(loaded):
    from attestra import db, services
    from attestra.reports import generate_report

    with db.session() as s:
        findings = services.list_findings(s, loaded)
        assert findings
        f = findings[0]
        f.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        f.owasp_top10 = "A03:2021"
        f.asvs_ref = "V5.1.1"
        f.wstg_ref = "WSTG-INPV-05"
        assets = services.get_engagement(s, loaded).assets
        if assets:
            assets[0].test_types = ["web_dast", "manual_pt", "tls"]
            assets[0].environment = "staging"
        r = generate_report(s, loaded, kind="technical", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")

    assert "Document control" in body
    assert "Contents" in body
    assert "Risk rating legend" in body
    assert "Findings overview" in body
    assert "Standards and test types" in body
    assert "OWASP Top 10" in body or "A03:2021" in body
    assert "CVSS:3.1/AV:N" in body
    assert "staging" in body
    assert "web_dast" in body or "Web app scan" in body
    assert "Assumptions, limitations and confidentiality" in body
    assert "Conclusion" in body
    assert "DRAFT" in body
    assert "VA + PT" in body
    assert "Environment" in body


# @lat: [[tests#Report coverage enhancements#Retest report kind]]
def test_retest_report_kind(loaded):
    from attestra import db, services
    from attestra.reports import generate_report
    from attestra.retest import finalize_retest, request_retest

    with db.session() as s:
        findings = [f for f in services.list_findings(s, loaded) if f.status in ("new", "triaged", "validated")]
        assert findings
        f = findings[0]
        if f.status == "new":
            services.transition(s, f.id, to="triaged", actor="tester")
        if f.status == "triaged":
            services.transition(s, f.id, to="validated", actor="tester", note="validated for retest test")
        rt = request_retest(s, f.id, actor="tester", note="please verify fix")
        finalize_retest(s, rt.id, result="still_open", actor="lead", force_asset_reached=True, note="still present")
        r = generate_report(s, loaded, kind="retest", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")

    assert "Retest and remediation verification" in body
    assert f"F-{f.id}" in body
    assert "still_open" in body
    assert "Unresolved risks" in body
    assert "Historical evidence is not overwritten" in body or "not overwritten" in body


def test_screenshot_embed_in_technical(loaded, tmp_path):
    from attestra import db, services
    from attestra.proof.store import attach_screenshot
    from attestra.reports import generate_report

    # Minimal 1x1 PNG
    png = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
        b"\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    with db.session() as s:
        f = services.list_findings(s, loaded)[0]
        attach_screenshot(s, f.id, filename="poc.png", data=png, actor="tester", note="PoC screenshot")
        r = generate_report(s, loaded, kind="technical", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")

    assert "data:image/png;base64," in body
    assert "PoC screenshot" in body
    assert "Evidence (screenshots)" in body


@pytest.mark.parametrize("eng_type", list(ENGAGEMENT_TYPES))
def test_technical_report_for_each_assessment_type(fresh_db, eng_type):
    from datetime import date, timedelta

    from attestra import db, services
    from attestra.reports import generate_report

    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s,
            tenant=f"Type {eng_type}",
            name=f"{eng_type} engagement",
            type=eng_type,
            frameworks=["pci_dss_4"],
            window_start=today - timedelta(days=1),
            window_end=today + timedelta(days=1),
            actor="tester",
        )
        kind = "retest" if eng_type == "retest" else "technical"
        r = generate_report(s, e.id, kind=kind, actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")
        from attestra.models import engagement_type_label

        assert engagement_type_label(eng_type) in body


@pytest.mark.parametrize(
    "fw",
    [
        "pci_dss_4",
        "iso_27001_2022",
        "soc2",
        "iso_42001_2023",
        "cert_in_2022",
        "nist_csf_2",
        "rbi_csf_2016",
        "sebi_cscrf_2024",
        "dora_2022",
    ],
)
def test_compliance_report_each_framework(loaded, fw):
    from attestra import db
    from attestra.compliance.engine import clear_library_cache
    from attestra.reports import generate_report

    clear_library_cache()
    with db.session() as s:
        r = generate_report(s, loaded, kind="compliance", actor="tester", framework=fw)
        body = Path(r.path).read_text(encoding="utf-8")
    assert body
    assert "DRAFT" in body or fw.replace("_", " ") in body.lower() or "control" in body.lower()
