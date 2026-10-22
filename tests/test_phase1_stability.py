"""Phase 1 stability fixes from the Gap Implementation Plan (re-export, CSV target)."""

from __future__ import annotations

from pathlib import Path


# @lat: [[tests#Phase 1 stability#Report re-export succeeds]]
def test_report_reexport_twice(loaded):
    from attestra import db
    from attestra.reports import generate_report, verify_report
    from attestra.reports.export import export_report_formats

    with db.session() as s:
        r = generate_report(s, loaded, kind="executive", actor="tester")
        sealed_sha = r.sha256
        first = export_report_formats(r)
        second = export_report_formats(r)
        assert Path(first["docx_path"]).exists()
        assert Path(second["docx_path"]).exists()
        assert Path(first["pdf_path"]).exists()
        assert Path(second["pdf_path"]).exists()
        assert r.sha256 == sealed_sha
        v = verify_report(s, r.id)
        assert v["hash_matches"]


# @lat: [[tests#Phase 1 stability#CSV target column filled]]
def test_findings_csv_target_column(loaded):
    from attestra import db
    from attestra.reports.findings_csv import export_findings_csv

    with db.session() as s:
        csv_body = export_findings_csv(s, loaded, actor="tester")
    lines = csv_body.strip().splitlines()
    assert lines[0].startswith("id,target,")
    data_rows = lines[1:]
    assert data_rows
    # At least one imported finding should show the shop target identifier.
    assert any("shop.example.com" in row for row in data_rows)


# @lat: [[tests#Phase 1 stability#Shared ISO and SOC 2 sample sizes]]
def test_shared_sample_size_rules():
    """ISO default_sample_size and SOC 2 sample_size_for use the same table."""
    from attestra import services
    from attestra.compliance.sampling import sample_size_for
    from attestra.reports import soc2_sampling

    for n in (0, 1, 2, 3, 4, 12, 13, 52, 53, 100, 250, 251, 5000):
        shared = sample_size_for(n)
        assert services.default_sample_size(n) == shared
        assert soc2_sampling.sample_size_for(n) == shared
    assert sample_size_for(3) == 2
    assert sample_size_for(10) == 2
    assert sample_size_for(100) == 25
