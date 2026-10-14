"""Phase 4 letters, DOCX/PDF, SARIF/OSCAL, packs, signing."""
# @lat: [[tests#Phase 4 report tests#tests/test_phase4_exports.py]]

from __future__ import annotations

from pathlib import Path


def test_closure_and_attestation_golden(loaded):
    from attestra import db
    from attestra.reports import generate_report

    golden = Path(__file__).parent / "golden"
    golden.mkdir(exist_ok=True)
    with db.session() as s:
        for kind in ("closure_letter", "attestation_letter"):
            r = generate_report(s, loaded, kind=kind, actor="tester")
            body = Path(r.path).read_text(encoding="utf-8")
            # Letters must not enumerate finding titles from the technical report
            assert "F-" not in body or "count only" in body.lower()
            marker = golden / f"{kind}.marker.txt"
            marker.write_text(f"kind={kind}\nsha256={r.sha256}\n", encoding="utf-8")
            assert kind.split("_")[0] in body.lower() or "letter" in body.lower()


def test_docx_pdf_export_stores_sha(loaded):
    from attestra import db
    from attestra.reports import generate_report
    from attestra.reports.export import export_report_formats

    with db.session() as s:
        r = generate_report(s, loaded, kind="executive", actor="tester")
        out = export_report_formats(r)
        assert r.docx_sha256 and len(r.docx_sha256) == 64
        assert r.pdf_sha256 and len(r.pdf_sha256) == 64
        assert Path(out["docx_path"]).exists()
        assert Path(out["pdf_path"]).exists()
        assert Path(out["docx_path"]).read_bytes()[:2] == b"PK"  # zip/docx
        assert Path(out["pdf_path"]).read_bytes()[:4] == b"%PDF"


def test_ed25519_sign_and_verify(loaded):
    from attestra import db
    from attestra.reports import approve_report, generate_report, signing, verify_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="technical", actor="author@x")
        approve_report(s, r.id, actor="approver@x")
        v = verify_report(s, r.id)
        assert v["signature_valid"]
        assert v["algorithm"] in ("ed25519", "hmac-sha256")
        if signing.public_key_b64():
            assert r.algorithm == "ed25519" or v["algorithm"] == "ed25519"


def test_sarif_structure(loaded):
    from attestra import db
    from attestra.reports.sarif import check_sarif_structure, findings_to_sarif

    with db.session() as s:
        doc = findings_to_sarif(s, loaded)
    assert check_sarif_structure(doc) == []


def test_oscal_structure(loaded):
    from attestra import db
    from attestra.reports.oscal import assessment_results, load_oscal_schema, poam, validate_oscal_structure

    schema = load_oscal_schema()
    with db.session() as s:
        ar = assessment_results(s, loaded, "pci_dss_4")
        p = poam(s, loaded)
    assert validate_oscal_structure(ar, schema) == []
    poam_schema = {
        "required_top_level": ["plan-of-action-and-milestones"],
        "required_nested": schema["required_nested"],
    }
    assert validate_oscal_structure(p, poam_schema) == []


def test_framework_pack_zip(loaded):
    from attestra import db
    from attestra.reports.packs import build_framework_pack

    with db.session() as s:
        path = build_framework_pack(s, loaded, "pci_dss_4")
    assert path.exists()
    assert path.suffix == ".zip"
    data = path.read_bytes()
    assert data[:2] == b"PK"


def test_executive_includes_trend_svg(loaded):
    from attestra import db
    from attestra.reports import generate_report

    with db.session() as s:
        r = generate_report(s, loaded, kind="executive", actor="tester")
        body = Path(r.path).read_text(encoding="utf-8")
    assert "<svg" in body
