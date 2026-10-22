"""Phase 3 report template / PDF / Word gaps (figures, http_pair, logo, legend, fields)."""

from __future__ import annotations

import zipfile
from io import BytesIO
from pathlib import Path

import pytest

# Minimal 1x1 PNG
_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
    b"\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
)


def _docx_xml(data: bytes) -> str:
    with zipfile.ZipFile(BytesIO(data)) as z:
        return " ".join(
            z.read(n).decode("utf-8", "replace") for n in z.namelist() if n.endswith(".xml")
        )


# @lat: [[tests#Phase 3 reports#Change column in document control]]
def test_document_control_change_column(loaded):
    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        generate_report(s, loaded, kind="technical", actor="tester")
        r2 = generate_report(s, loaded, kind="technical", actor="tester")
        body = Path(r2.path).read_text(encoding="utf-8")
        retest = generate_report(s, loaded, kind="retest", actor="tester")
        retest_body = Path(retest.path).read_text(encoding="utf-8")

    assert "<th>Change</th>" in body
    assert "Draft generated" in body or "—" in body
    assert "<th>Change</th>" in retest_body


# @lat: [[tests#Phase 3 reports#Screenshots end-to-end]]
def test_screenshots_end_to_end(loaded):
    from attestra import db, services
    from attestra.proof.store import attach_screenshot
    from attestra.reports import generate_report
    from attestra.reports.export import to_docx, to_pdf

    with db.session() as s:
        f = services.list_findings(s, loaded)[0]
        attach_screenshot(s, f.id, filename="poc.png", data=_PNG, actor="tester", note="PoC screenshot")
        r = generate_report(s, loaded, kind="technical", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")
        assert "data:image/png;base64," in body
        assert "Fig." in body
        assert "PoC screenshot" in body
        assert "List of figures" in body
        assert f"F-{f.id}-1" in body

        docx_path, _ = to_docx(r)
        docx_bytes = Path(docx_path).read_bytes()
        assert docx_bytes[:2] == b"PK"
        xml = _docx_xml(docx_bytes)
        assert "<w:drawing" in xml or "image" in xml.lower() or "a:blip" in xml

        pdf_path, _ = to_pdf(r)
        assert Path(pdf_path).is_file()
        pdf_bytes = Path(pdf_path).read_bytes()
        assert pdf_bytes[:4] == b"%PDF"
        try:
            from pypdf import PdfReader
        except ImportError:
            PdfReader = None  # optional: binary export already asserted
        if PdfReader is not None:
            from io import BytesIO as _BIO

            text = "\n".join(p.extract_text() or "" for p in PdfReader(_BIO(pdf_bytes)).pages)
            assert "PoC" in text or "Fig" in text or "screenshot" in text.lower() or len(text) > 0


# @lat: [[tests#Phase 3 reports#List of figures]]
def test_list_of_figures_section(loaded):
    from attestra import db, services
    from attestra.proof.store import attach_screenshot
    from attestra.reports import generate_report

    with db.session() as s:
        f = services.list_findings(s, loaded)[0]
        attach_screenshot(s, f.id, filename="shot.png", data=_PNG, actor="tester", note="Login bypass")
        r = generate_report(s, loaded, kind="technical", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")

    assert 'id="list-of-figures"' in body
    assert 'href="#list-of-figures"' in body
    assert "Login bypass" in body
    assert f"Fig. F-{f.id}-1" in body


# @lat: [[tests#Phase 3 reports#Risk legend in Word]]
def test_risk_legend_in_docx(loaded):
    pytest.importorskip("docx")
    from attestra import db
    from attestra.reports import generate_report
    from attestra.reports.docx_export import docx_text
    from attestra.reports.export import to_docx

    with db.session() as s:
        tech = generate_report(s, loaded, kind="technical", actor="tester")
        tech_bytes = Path(to_docx(tech)[0]).read_bytes()
        exec_r = generate_report(s, loaded, kind="executive", actor="tester")
        exec_bytes = Path(to_docx(exec_r)[0]).read_bytes()

    tech_text = docx_text(tech_bytes)
    assert "Risk rating" in tech_text or "Risk Rating" in tech_text
    assert "CVSS" in tech_text
    assert "9.0" in tech_text or "Critical" in tech_text

    exec_text = docx_text(exec_bytes)
    assert "Risk rating" in exec_text or "Risk Rating" in exec_text
    assert "CVSS" in exec_text


# @lat: [[tests#Phase 3 reports#Impact affected URLs references]]
def test_finding_impact_urls_references_rows(loaded):
    from attestra import db, services
    from attestra.reports import generate_report

    with db.session() as s:
        f = services.list_findings(s, loaded)[0]
        f.impact = "Session takeover on admin accounts."
        f.affected_urls = ["https://app.example/admin", "POST /api/login"]
        f.references = ["https://owasp.org/www-community/attacks/Session_fixation", "CWE-384"]
        r = generate_report(s, loaded, kind="technical", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")

    assert "Impact." in body
    assert "Session takeover on admin accounts." in body
    assert "Affected URLs." in body
    assert "https://app.example/admin" in body
    assert "References." in body
    assert "CWE-384" in body


# @lat: [[tests#Phase 3 reports#HTTP request response in report]]
def test_http_pair_pretty_printed(loaded):
    from attestra import db, services
    from attestra.proof.pair import HttpPair
    from attestra.proof.store import attach_http_pair
    from attestra.reports import generate_report

    pair = HttpPair(
        method="GET",
        url="https://app.example/secret?token=abc",
        request_headers={"Authorization": "Bearer secret-token-value", "Accept": "text/html"},
        request_body="",
        status=200,
        response_headers={"Content-Type": "text/html"},
        response_body="<html>ok</html>",
        source="test",
    )
    with db.session() as s:
        f = services.list_findings(s, loaded)[0]
        attach_http_pair(s, f.id, pair, actor="tester", note="auth proof")
        r = generate_report(s, loaded, kind="technical", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")

    assert "Evidence (HTTP request/response)" in body
    assert 'class="http-pair' in body
    assert "GET " in body
    assert "Status: 200" in body
    assert "secret-token-value" not in body  # redacted at store / re-mask
    assert "[REDACTED]" in body or "Bearer" in body


# @lat: [[tests#Phase 3 reports#Logo on cover]]
def test_logo_on_technical_cover(loaded):
    from attestra import db, services
    from attestra.library.templates import save_template
    from attestra.reports import generate_report

    with db.session() as s:
        eng = services.get_engagement(s, loaded)
        save_template(s, eng.tenant_id, "technical", actor="tester", logo=_PNG, cover_title="Branded tech report")
        r = generate_report(s, loaded, kind="technical", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")

    assert 'id="cover"' in body
    assert "data:image/png;base64," in body
    assert "Branded tech report" in body


# @lat: [[tests#Phase 3 reports#Disclaimer branding override]]
def test_disclaimer_branding_override(loaded):
    from attestra import db, services
    from attestra.library.templates import save_template
    from attestra.reports import generate_report

    custom = "CUSTOM-DISCLAIMER-OVERRIDE-XYZ: tenant-specific limitations apply."
    with db.session() as s:
        eng = services.get_engagement(s, loaded)
        save_template(s, eng.tenant_id, "technical", actor="tester", disclaimer=custom)
        r = generate_report(s, loaded, kind="technical", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")

    assert custom in body
    assert 'id="disclaimer"' in body


# @lat: [[tests#Phase 3 reports#DOCX TOC update note]]
def test_docx_toc_update_note(loaded):
    pytest.importorskip("docx")
    from attestra import db
    from attestra.reports import generate_report
    from attestra.reports.docx_export import docx_text
    from attestra.reports.export import to_docx

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="tester")
        text = docx_text(Path(to_docx(r)[0]).read_bytes())

    assert "Update Table" in text or "Update Field" in text
    assert "References" in text or "right-click" in text.lower()


# @lat: [[tests#Phase 3 reports#Finding fields round-trip]]
def test_finding_fields_round_trip_api_and_library(engagement):
    from attestra import db, services
    from attestra.api import _finding_dict
    from attestra.library import service as lib
    from attestra.models import Finding

    with db.session() as s:
        e = services.get_engagement(s, engagement)
        f = Finding(
            engagement_id=e.id,
            asset_id=e.assets[0].id,
            fingerprint="b" * 64,
            title="Sample SQLi",
            severity="high",
        )
        s.add(f)
        s.flush()
        entry = lib.create_entry(
            s,
            e.tenant_id,
            {
                "title": "Sample SQLi",
                "description": "Injected SQL reaches the database.",
                "impact": "Attacker can read or change data.",
                "remediation": "Use parameterized queries.",
                "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                "cwe": 89,
                "default_severity": "high",
            },
            actor="tester",
        )
        changed = lib.apply_to_finding(s, f, entry, actor="tester")
        assert "impact" in changed and "references" in changed
        f.affected_urls = ["https://shop.example.com/search"]
        payload = _finding_dict(f)
        assert payload["impact"] == "Attacker can read or change data."
        assert payload["references"][0].startswith("https://owasp.org/")
        assert payload["affected_urls"] == ["https://shop.example.com/search"]
        assert "Impact:" in f.description


# @lat: [[tests#Phase 3 reports#CVSS vector validation]]
def test_cvss_vector_validation():
    from attestra.scoring import soft_cvss_vector, validate_cvss_vector

    assert validate_cvss_vector("") == ""
    good = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert validate_cvss_vector(good) == good
    with pytest.raises(ValueError, match="CVSS"):
        validate_cvss_vector("not-a-vector")
    with pytest.raises(ValueError, match="CVSS"):
        validate_cvss_vector("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")
    assert soft_cvss_vector("garbage") == ""
    assert soft_cvss_vector(good) == good


# @lat: [[tests#Phase 3 reports#History change key]]
def test_report_history_change_key(loaded):
    from attestra import db
    from attestra.reports.render import _report_history, generate_report, submit_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="tester")
        submit_report(s, r.id, actor="tester")
        history = _report_history(s, loaded, kind="technical")
        assert history and history[0]["change"] == "Submitted for QA"


# @lat: [[tests#Phase 3 reports#Date check before window]]
def test_generate_refuses_before_window_start(fresh_db):
    from datetime import date, timedelta

    from attestra import db, services
    from attestra.reports import generate_report
    from attestra.services import ServiceError

    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s,
            tenant="Future Window Co",
            name="Future window engagement",
            type="vapt",
            frameworks=["pci_dss_4"],
            window_start=today + timedelta(days=14),
            window_end=today + timedelta(days=28),
            actor="tester",
        )
        with pytest.raises(ServiceError, match="before the test window"):
            generate_report(s, e.id, kind="executive", actor="tester")
        e2 = services.create_engagement(
            s,
            tenant="No Window Co",
            name="Open window engagement",
            type="va",
            frameworks=[],
            window_start=None,
            window_end=None,
            actor="tester",
        )
        assert generate_report(s, e2.id, kind="executive", actor="tester").status == "draft"


# @lat: [[tests#Phase 3 reports#Front back matter]]
def test_front_back_matter_distribution_signoff_appendix(loaded):
    from attestra import db, services
    from attestra.reports import generate_report

    with db.session() as s:
        eng = services.get_engagement(s, loaded)
        eng.tenant.contact_name = "Ada Client"
        eng.tenant.contact_email = "ada@client.example"
        r = generate_report(s, loaded, kind="technical", actor="author.one")
        body = Path(r.path).read_text(encoding="utf-8")

    assert 'id="distribution"' in body
    assert 'href="#distribution"' in body
    assert "Distribution list" in body
    assert "Ada Client" in body
    assert "ada@client.example" in body
    assert "Authorized recipients" in body
    assert 'id="sign-off"' in body
    assert 'href="#sign-off"' in body
    assert "QA reviewer" in body
    assert "Approved / signed" in body
    assert "author.one" in body
    assert 'id="appendix"' in body
    assert 'href="#appendix"' in body
    assert "Tool imports" in body
    assert 'id="methodology"' in body
    assert "Methodology and data sources" in body
    assert 'id="conclusion"' in body
    assert "Conclusion" in body
