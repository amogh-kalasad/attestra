"""E20: technical report embeds automated VAPT images only for failed/finding cases."""

from __future__ import annotations

from attestra.automated_vapt.evidence import run_evidence


def test_report_image_files_skips_passed():
    case = {
        "test_id": "T01",
        "status": "PASSED",
        "evidence_files": ["T01_http_1.png", "T01_http_2.png"],
    }
    assert run_evidence.report_image_files(case) == []


def test_report_image_files_uses_fail_subset():
    case = {
        "test_id": "T21",
        "status": "FINDING",
        "evidence_files": [f"T21_http_{i}.png" for i in range(1, 13)],
        "report_evidence_files": ["T21_fail_http_1.png", "T21_fail_http_2.png"],
        "validation": {"status": "CONFIRMED"},
    }
    assert run_evidence.report_image_files(case) == ["T21_fail_http_1.png", "T21_fail_http_2.png"]


def test_report_image_files_legacy_finding_keeps_all_when_no_subset():
    case = {
        "test_id": "T21",
        "status": "FINDING",
        "evidence_files": ["T21_http_1.png", "T21_http_5.png"],
    }
    assert run_evidence.report_image_files(case) == ["T21_http_1.png", "T21_http_5.png"]


def test_case_rows_embed_filters_passed(tmp_path, monkeypatch):
    monkeypatch.setattr(run_evidence, "run_dir", lambda _xid: tmp_path)
    # create two pngs
    png = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
        b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    (tmp_path / "T01_http_1.png").write_bytes(png)
    (tmp_path / "T21_fail_http_1.png").write_bytes(png)
    result = {
        "cases": [
            {"test_id": "T01", "status": "PASSED", "detail": "ok", "evidence_files": ["T01_http_1.png"]},
            {
                "test_id": "T21",
                "status": "FINDING",
                "detail": "1 finding",
                "evidence_files": ["T01_http_1.png", "T21_fail_http_1.png"],
                "report_evidence_files": ["T21_fail_http_1.png"],
                "finding_id": 61,
            },
        ]
    }
    # UI: all files
    ui = run_evidence.case_rows(result, 1, 7, embed=False)
    assert [c["test_id"] for c in ui] == ["T01", "T21"]
    assert len(ui[0]["evidence"]) == 1
    assert len(ui[1]["evidence"]) == 2
    # Report: T01 no images, T21 only fail subset
    rep = run_evidence.case_rows(result, 1, 7, embed=True)
    assert rep[0]["evidence"] == []
    assert len(rep[1]["evidence"]) == 1
    assert rep[1]["evidence"][0]["name"] == "T21_fail_http_1.png"
    assert rep[1]["evidence"][0]["data_uri"].startswith("data:image/png;base64,")
    assert sum(len(c["evidence"]) for c in rep) == 1


def test_report_image_files_failed_and_skipped():
    assert run_evidence.report_image_files({"status": "SKIPPED", "evidence_files": ["x.png"]}) == []
    assert run_evidence.report_image_files({"status": "FAILED", "evidence_files": ["x.png"]}) == ["x.png"]

