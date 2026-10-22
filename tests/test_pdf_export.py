"""Report PDF/Word export: styled PDF, no dropped words, repeat exports, UI download buttons."""

from __future__ import annotations

import re
from io import BytesIO
from pathlib import Path

import pytest

from attestra.reports.render import KINDS

FRAMEWORK_FOR = {"compliance": "pci_dss_4", "iso_soa": "iso_27001_2022"}


def _pdf_text(data: bytes) -> str:
    from pypdf import PdfReader

    return "\n".join(p.extract_text() or "" for p in PdfReader(BytesIO(data)).pages)


def _squash(text: str) -> str:
    return re.sub(r"\s+", "", text)


@pytest.mark.parametrize("kind", KINDS)
def test_every_kind_exports_twice_without_dropping_words(loaded, kind):
    from attestra import db
    from attestra.reports import generate_report
    from attestra.reports.export import _html_to_text, export_report_formats

    with db.session() as s:
        r = generate_report(s, loaded, kind=kind, framework=FRAMEWORK_FOR.get(kind, ""), actor="tester")
        first = export_report_formats(r)
        second = export_report_formats(r)  # re-export must not fail (read-only previous file)
        assert first["pdf_path"] == second["pdf_path"]
        data = Path(second["pdf_path"]).read_bytes()
        assert data[:4] == b"%PDF"
        html = Path(r.path).read_text(encoding="utf-8")
    html = re.sub(r"(?is)<svg.*?</svg>|<nav class=\"toc\".*?</nav>|<div class=\"draft-mark\".*?</div>", "", html)
    html = re.sub(r"(?is)<br>\s*Page numbers appear when printed[^<]*", "", html)
    from attestra.reports.pdf import _framework_names, _human_times

    html = _human_times(_framework_names(html))  # display-only normalisation done for the PDF
    pdf = _squash(_pdf_text(data)).lower()  # display labels are Title Case
    words = re.findall(r"[A-Za-z0-9]{3,}", _html_to_text(html))
    missing = [w for w in words if w.lower() not in pdf]
    assert not missing, missing[:20]


def test_pdf_is_styled_and_marked_draft_until_signed(loaded):
    from attestra import db
    from attestra.reports import approve_report, generate_report
    from attestra.reports.export import export_report_formats

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="author@x")
        draft = _pdf_text(Path(export_report_formats(r)["pdf_path"]).read_bytes())
        approve_report(s, r.id, actor="approver@x")
        signed = _pdf_text(Path(export_report_formats(r)["pdf_path"]).read_bytes())
    assert "Contents" in draft and "Risk Rating Legend" in draft
    assert re.search(r"Page 1 of \d+", draft)
    assert "DRAFT" in draft
    assert "DRAFT" not in signed


def test_executive_pdf_gets_legend_and_disclaimer(loaded):
    from attestra import db
    from attestra.reports import generate_report
    from attestra.reports.export import export_report_formats

    with db.session() as s:
        r = generate_report(s, loaded, kind="executive", actor="tester")
        text = _pdf_text(Path(export_report_formats(r)["pdf_path"]).read_bytes())
    assert "Severity Legend" in text and "Disclaimer" in text


def test_fallback_pdf_keeps_every_word():
    from attestra.reports.export import _minimal_pdf

    text = "\n".join(f"line {i} " + " ".join(f"word{i}x{j}" for j in range(30)) for i in range(150))
    data = _minimal_pdf(text)
    got = _squash(_pdf_text(data))
    assert all(w in got for w in re.findall(r"word\d+x\d+", text))


def test_ui_export_buttons_download_files(client, loaded):
    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        rid = generate_report(s, loaded, kind="technical", actor="tester").id
    client.headers.pop("Authorization", None)
    assert client.post("/login", data={"username": "lead", "password": "test-pass-lead"},
                       follow_redirects=False).status_code == 303
    page = client.get(f"/engagements/{loaded}")
    assert f"/engagements/{loaded}/reports/{rid}/export/pdf" in page.text
    assert f"/engagements/{loaded}/export/sarif" in page.text
    for _ in range(2):
        r = client.get(f"/engagements/{loaded}/reports/{rid}/export/pdf")
        assert r.status_code == 200 and r.content[:4] == b"%PDF"
    r = client.get(f"/engagements/{loaded}/reports/{rid}/export/docx")
    assert r.status_code == 200 and r.content[:2] == b"PK"
    assert client.get(f"/engagements/{loaded}/export/sarif").json()["version"] == "2.1.0"
    assert "plan-of-action-and-milestones" in client.get(f"/engagements/{loaded}/export/oscal-poam").json()
    assert "assessment-results" in client.get(
        f"/engagements/{loaded}/export/oscal", params={"framework": "pci_dss_4"}).json()
    assert client.get(f"/engagements/{loaded}/reports/{rid}/export/exe").status_code == 404


def test_api_reexport_twice(client, loaded):
    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        rid = generate_report(s, loaded, kind="executive", actor="tester").id
    for _ in range(2):
        r = client.post(f"/api/reports/{rid}/export")
        assert r.status_code == 200, r.text
    assert client.get(f"/api/engagements/{loaded}/export/oscal").status_code == 200


def test_csv_target_falls_back_to_location_when_unlinked():
    from attestra.models import Finding
    from attestra.reports.findings_csv import findings_to_rows

    f = Finding(id=1, title="t", severity="low", status="new", risk_score=0.0, fingerprint="x",
                location="https://demo.example.com/login", tools=[])
    assert findings_to_rows([f])[0][1] == "https://demo.example.com/login"


def test_pdf_layout_transforms():
    from attestra.reports.pdf import prepare_html

    html = ('<html><head><style>x{}</style></head><body><div class="kpis"><div class="kpi">'
            '<span class="st st-met">met</span><b>3</b>controls</div><div class="kpi">x<b>4</b>y</div></div>'
            '<table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>' + "d" * 64 + '</td></tr></table></body></html>')
    out = prepare_html(html, kind="compliance", draft=True)
    assert '<table class="kpis"' in out and 'class="kpi-num">3</' in out
    assert 'width="' in out  # columns sized by content
    assert "d" * 17 not in out  # long hash wraps instead of being clipped


def test_docx_is_styled_word_document(loaded):
    import zipfile
    from xml.dom import minidom

    from attestra import db
    from attestra.reports import approve_report, generate_report
    from attestra.reports.export import export_report_formats

    with db.session() as s:
        r = generate_report(s, loaded, kind="compliance", framework="pci_dss_4", actor="author@x")
        path = export_report_formats(r)["docx_path"]
        z = zipfile.ZipFile(path)
        for name in z.namelist():
            if name.endswith((".xml", ".rels")):
                minidom.parseString(z.read(name))  # well-formed parts
        doc = z.read("word/document.xml").decode()
        assert 'w:val="Heading1"' in doc and doc.count("<w:tbl>") >= 2
        assert "w:tblGrid" in doc and 'w:type="page"' in doc  # tables with grids, cover page break
        assert "DRAFT" in z.read("word/header1.xml").decode()
        assert "NUMPAGES" in z.read("word/footer1.xml").decode()
        z.close()  # Windows: an open handle blocks re-export of the same file
        approve_report(s, r.id, actor="approver@x")
        z = zipfile.ZipFile(export_report_formats(r)["docx_path"])
        assert "DRAFT" not in z.read("word/header1.xml").decode()


def test_pdf_display_fixes():
    from attestra.reports.pdf import _human_times, _register_badge_font, prepare_html

    out = _human_times("<html><body>on 2026-10-22 07:35:54.475008+00:00.</body></html>")
    assert "22 Oct 2026, 13:05 IST" in out
    assert _register_badge_font() == "Inter-Bold"
    html = '<html><head><style></style></head><body><h1>x</h1><svg width="100" height="40"><rect width="10" height="10"/></svg></body></html>'
    assert "data:image/svg+xml" in prepare_html(html, kind="executive", draft=False)
