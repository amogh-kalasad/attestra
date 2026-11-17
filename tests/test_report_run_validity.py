"""J-01 run-validity + coverage section in HTML (PDF/DOCX source), Markdown and XLSX. No DB."""
# @lat: [[intel-and-reporting#Run validity in reports]]

from __future__ import annotations

import json

from attestra.reports import run_validity as rv

BLOCKED_RUN = {
    "run_validity": {"state": "CHALLENGE_DETECTED", "reasons": ["cloudflare challenge on 14/20 samples"],
                     "sample_count": 20, "by_class": {"CHALLENGE": 14, "OK": 6}, "affected_cases": ["T03", "T07"],
                     "computed_at": "2026-11-17T06:00:00Z", "version": "rv1"},
    "checklist_version": "wstg-4.2-c1",
    "cases": [{"test_id": "T03", "status": "BLOCKED", "skip_reason": "challenge"},
              {"test_id": "T04", "status": "PASSED", "validity": {"state": "VALID"}},
              {"test_id": "T07", "status": "INCONCLUSIVE"}],
}
LEGACY_RUN = {"cases": [{"test_id": "T01", "status": "PASSED"}]}


def test_blocked_run_section_shows_reason_and_cases():
    sec = rv.build_section([(12, json.dumps(BLOCKED_RUN)), (11, LEGACY_RUN)], reportable_count=0)
    assert sec["has_runs"] and sec["computed"] and sec["incomplete"]
    assert sec["overall_state"] == "CHALLENGE_DETECTED" and sec["zero_findings"] is True
    assert sec["runs"][0]["reasons"] == ["cloudflare challenge on 14/20 samples"]
    assert {c["test_id"] for c in sec["incomplete_cases"]} == {"T03", "T07"}
    assert sec["checklist_versions"] == ["wstg-4.2-c1"]


def test_legacy_run_not_computed():
    sec = rv.build_section([(3, LEGACY_RUN)])
    assert sec["overall_state"] == "NOT_COMPUTED" and sec["overall_label"] == "Not computed"
    assert not sec["computed"] and not sec["incomplete"] and sec["notice"] == ""
    assert rv.build_section([])["has_runs"] is False


def test_precedence_worst_wins():
    runs = [(1, {"run_validity": {"state": "RATE_LIMITED"}}), (2, {"run_validity": {"state": "AUTH_EXPIRED"}}),
            (3, {"run_validity": {"state": "VALID"}})]
    assert rv.build_section(runs)["overall_state"] == "AUTH_EXPIRED"
    assert rv.build_section([(1, {"run_validity": {"state": "VALID"}})])["incomplete"] is False


def _render(section, compact=False):
    from attestra.reports.render import _env

    tpl = _env.from_string(
        '{% set sec = namespace(n=4) %}{% set rv_compact = compact %}{% include "_run_validity.html.j2" %}'
    )
    return tpl.render(run_validity=section, compact=compact)


def test_html_partial_full_and_compact():
    sec = rv.build_section([(12, BLOCKED_RUN)], reportable_count=0)
    html = _render(sec)
    assert 'id="run-validity"' in html and "5. Run validity and coverage" in html
    assert "Challenge detected" in html and "Testing was incomplete" in html
    assert "cloudflare challenge on 14/20 samples" in html and "T03" in html
    compact = _render(sec, compact=True)
    assert 'id="run-validity-summary"' in compact and "Testing was incomplete" in compact
    legacy = _render(rv.build_section([(3, LEGACY_RUN)]))
    assert "Not computed" in legacy and "Testing was incomplete" not in legacy
    assert _render(rv.build_section([])).strip() == ""


def test_templates_include_partial_and_keep_report_rules():
    from pathlib import Path

    tdir = Path(__file__).resolve().parents[1] / "attestra" / "reports" / "templates"
    tech = (tdir / "technical.html.j2").read_text(encoding="utf-8")
    execu = (tdir / "executive.html.j2").read_text(encoding="utf-8")
    assert '{% include "_run_validity.html.j2" %}' in tech and 'href="#run-validity"' in tech
    assert '{% include "_run_validity.html.j2" %}' in execu
    partial = (tdir / "_run_validity.html.j2").read_text(encoding="utf-8")
    assert "Powered by" not in partial and "Distribution" not in partial
    # checklist "not tested" rows stay hidden in the technical report
    assert 'if row.result != "not_tested"' in tech


def test_markdown_and_xlsx_blocks():
    sec = rv.build_section([(12, BLOCKED_RUN)], reportable_count=0)
    md = "\n".join(rv.markdown_lines(sec))
    assert "## Run validity and coverage" in md and "Challenge detected" in md and "Testing was incomplete" in md
    assert "T03" in md
    assert rv.markdown_lines(rv.build_section([])) == []
    rows = rv.xlsx_rows(sec)
    assert rows[0][0] == 12 and rows[0][1] == "Challenge detected" and "T03" in rows[0][5]
    assert len(rv.XLSX_COLUMNS) == len(rows[0])
