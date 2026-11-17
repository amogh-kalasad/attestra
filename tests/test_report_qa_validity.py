"""J-02 QA gate: a non-VALID run can never be presented as a clean report. No DB."""
# @lat: [[intel-and-reporting#QA validity gate]]

from __future__ import annotations

from collections import Counter
from types import SimpleNamespace

import pytest

from attestra.reports import run_validity as rv
from attestra.reports.qa import checks

BLOCKED = {"run_validity": {"state": "PARTIALLY_BLOCKED", "reasons": ["waf 403"]}, "cases": []}
VALID = {"run_validity": {"state": "VALID"}, "checklist_version": "c1"}


def _ctx(html: str, runs, *, open_vulns=(), kind="technical", monkeypatch):
    section = rv.build_section(runs, reportable_count=len(open_vulns))
    monkeypatch.setattr(rv, "section_for_engagement", lambda s, eid, reportable_count=None: section)
    return checks.QaContext(
        s=None, report=SimpleNamespace(status="draft"), html=html, engagement=SimpleNamespace(id=1),
        reportable=list(open_vulns), open_vulns=list(open_vulns), by_sev=Counter(), tenant_id=1, kind=kind,
    )


def _codes(ctx):
    for chk in (checks.check_run_validity_disclosed, checks.check_blocked_not_clean, checks.check_checklist_version):
        chk(ctx)
    return {i.code: i.severity for i in ctx.issues}


def test_blocked_no_findings_without_section_fails(monkeypatch):
    codes = _codes(_ctx("<html><h2 id='summary'>No findings</h2></html>", [(1, BLOCKED)], monkeypatch=monkeypatch))
    assert codes["run_validity_not_disclosed"] == "critical"
    assert codes["blocked_run_presented_clean"] == "critical"


def test_blocked_no_findings_with_section_is_warning_only(monkeypatch):
    html = '<html><h2 id="run-validity">Run validity</h2><b>Testing was incomplete: zero findings ...</b></html>'
    codes = _codes(_ctx(html, [(1, BLOCKED)], monkeypatch=monkeypatch))
    assert "run_validity_not_disclosed" not in codes and "blocked_run_presented_clean" not in codes
    assert codes["zero_findings_incomplete_run"] == "warning"


def test_valid_run_passes(monkeypatch):
    codes = _codes(_ctx("<html></html>", [(1, VALID)], monkeypatch=monkeypatch))
    assert not {c for c, s in codes.items() if s == "critical"}


def test_legacy_runs_are_not_blocked(monkeypatch):
    codes = _codes(_ctx("<html></html>", [(1, {"cases": []})], monkeypatch=monkeypatch))
    assert codes == {"checklist_version_missing": "info"}


def test_blocked_with_open_findings_still_requires_disclosure(monkeypatch):
    codes = _codes(_ctx("<html></html>", [(1, BLOCKED)], open_vulns=[object()], monkeypatch=monkeypatch))
    assert codes["run_validity_not_disclosed"] == "critical"
    assert "blocked_run_presented_clean" not in codes


@pytest.mark.parametrize("kind", ["retest", "closure_letter"])
def test_other_kinds_skipped(monkeypatch, kind):
    assert _codes(_ctx("<html></html>", [(1, BLOCKED)], kind=kind, monkeypatch=monkeypatch)) == {}


def test_mixed_checklist_versions_warn(monkeypatch):
    runs = [(1, VALID), (2, {"run_validity": {"state": "VALID"}, "checklist_version": "c2"})]
    assert _codes(_ctx("<html></html>", runs, monkeypatch=monkeypatch))["checklist_version_mixed"] == "warning"


def test_checks_registered():
    names = [c.__name__ for c in checks.ALL_CHECKS]
    for n in ("check_run_validity_disclosed", "check_blocked_not_clean", "check_checklist_version"):
        assert n in names
    assert names[-1] == "check_approval_status"
