"""Automatic WSTG/ASVS checklist updates (auth_web.checklist_auto)."""

from __future__ import annotations

import json
from pathlib import Path

from attestra.audit import find_events

FIXTURES = Path(__file__).parent / "fixtures"


def _items(s, eid):
    from attestra.auth_web.checklists import list_checklist

    return {i.ref: i for i in list_checklist(s, eid)}


def _import_zap(s, eid):
    from attestra import services

    return services.import_results(
        s, eid, tool="zap", filename="zap.json", data=(FIXTURES / "zap.json").read_bytes(), actor="tester"
    )


def _execution(s, eid, cases, *, tenant_id=None, status="COMPLETED"):
    from attestra.models import AutomatedTestExecution, Engagement, utcnow

    eng = s.get(Engagement, eid)
    ex = AutomatedTestExecution(
        engagement_id=eid,
        tenant_id=tenant_id if tenant_id is not None else eng.tenant_id,
        status=status,
        test_case_ids=[c["test_id"] for c in cases],
        result_json=json.dumps({"cases": cases}),
        ended_at=utcnow(),
    )
    s.add(ex)
    s.flush()
    return ex


def test_zap_import_hook_sets_failed_and_passed(engagement):
    from attestra import db

    with db.session() as s:
        run = _import_zap(s, engagement)
        items = _items(s, engagement)
        inpv01 = items["WSTG-INPV-01"]  # 40012 reflected XSS alert in fixture
        assert inpv01.status == "failed"
        assert inpv01.updated_by == "attestra-auto"
        assert inpv01.notes.startswith("auto:")
        assert f"zap import #{run.id}" in inpv01.notes and "40012" in inpv01.notes
        assert inpv01.finding_ids, "failed item must link the finding ids"
        assert items["WSTG-SESS-05"].status == "failed"  # 10202 anti-CSRF alert
        # Catalog passive rules ran with no alert -> passed with an honest note.
        for ref in ("WSTG-CONF-12", "WSTG-SESS-02"):
            assert items[ref].status == "passed", ref
            assert "no issues" in items[ref].notes
            assert f"import_run:{run.id}" in items[ref].evidence_ids
        # No mapping evidence -> untouched; manual-only refs never set.
        for ref in ("WSTG-INFO-02", "WSTG-CRYP-01", "WSTG-ATHZ-02", "ASVS-V2.1.1", "WSTG-CONF-01"):
            assert items[ref].status == "not_started", ref


def test_manual_item_never_overwritten(engagement):
    from attestra import db
    from attestra.auth_web.checklists import ensure_checklist, update_checklist_item
    from attestra.models import Engagement

    with db.session() as s:
        eng = s.get(Engagement, engagement)
        items = {i.ref: i for i in ensure_checklist(s, engagement, eng.tenant_id)}
        update_checklist_item(
            s, items["WSTG-INPV-01"].id, status="not_applicable", notes="no HTML output", actor="alice"
        )
        _import_zap(s, engagement)
        item = _items(s, engagement)["WSTG-INPV-01"]
        assert item.status == "not_applicable"
        assert item.updated_by == "alice"
        assert item.notes == "no HTML output"


def test_failed_only_cleared_by_same_source_with_fixed_findings(engagement):
    from attestra import db
    from attestra.auth_web.checklist_auto import Verdict, apply_verdicts
    from attestra.models import Finding

    with db.session() as s:
        _import_zap(s, engagement)
        item = _items(s, engagement)["WSTG-INPV-01"]
        assert item.status == "failed"
        fids = list(item.finding_ids)
        clean = Verdict("WSTG-INPV-01", "passed", "zap", "zap import #999", "no issues", [], ["import_run:999"])
        other = Verdict("WSTG-INPV-01", "passed", "automated_vapt", "automated run #5 T21", "no issues", [], ["x"])

        res = apply_verdicts(s, engagement, [other])
        assert res[0]["action"] == "kept_failed_other_source"
        res = apply_verdicts(s, engagement, [clean])
        assert res[0]["action"] == "kept_failed_findings_open"
        assert _items(s, engagement)["WSTG-INPV-01"].status == "failed"

        for fid in fids:
            s.get(Finding, fid).status = "fixed"
        s.flush()
        res = apply_verdicts(s, engagement, [clean])
        assert res[0]["action"] == "updated"
        assert _items(s, engagement)["WSTG-INPV-01"].status == "passed"


def test_blocked_never_downgrades_and_never_passes_on_skip(engagement):
    from attestra import db
    from attestra.auth_web.checklist_auto import apply_automated_run

    with db.session() as s:
        skipped = {"test_id": "T19", "status": "SKIPPED", "detail": "login profile not ready"}
        apply_automated_run(s, _execution(s, engagement, [skipped]))
        item = _items(s, engagement)["WSTG-ATHN-04"]
        assert item.status == "blocked"
        assert "login profile not ready" in item.notes

        passed = {"test_id": "T19", "status": "PASSED", "detail": "auth bypass: 0 finding(s) across 3 endpoint(s)"}
        apply_automated_run(s, _execution(s, engagement, [passed]))
        assert _items(s, engagement)["WSTG-ATHN-04"].status == "passed"

        # A later skipped run must not downgrade passed -> blocked.
        apply_automated_run(s, _execution(s, engagement, [skipped]))
        assert _items(s, engagement)["WSTG-ATHN-04"].status == "passed"


def test_automated_t20_t21_semantics(engagement):
    from attestra import db
    from attestra.auth_web.checklist_auto import apply_automated_run

    cases = [
        {
            "test_id": "T20", "status": "PASSED", "detail": "IDOR: 0 finding(s)",
            "secondary_auth": {"status": "none", "profile_id": None},
        },
        {
            "test_id": "T21", "status": "FINDING", "detail": "input validation: 1 finding(s)",
            "endpoints": [
                {"status": "FINDING", "detail": "input validation issue (sqli_quote): server returned HTTP 500",
                 "meta": {"endpoint": "/api/a", "param": "id", "payload": "sqli_quote"}},
                {"status": "PASSED", "detail": "no 5xx / leak / reflection", "meta": {"endpoint": "/api/b", "param": "q"}},
            ],
        },
        {"test_id": "T22", "status": "SKIPPED", "detail": "mutation disabled"},
    ]
    with db.session() as s:
        apply_automated_run(s, _execution(s, engagement, cases))
        items = _items(s, engagement)
        # T20 without a secondary (non-admin) profile is never a pass.
        assert items["WSTG-ATHZ-04"].status == "blocked"
        assert "secondary" in items["WSTG-ATHZ-04"].notes
        assert items["WSTG-INPV-05"].status == "failed"
        assert "/api/a" in items["WSTG-INPV-05"].notes
        assert items["WSTG-INPV-01"].status == "passed"
        assert "not covered" in items["WSTG-INPV-01"].notes

        finding = {"test_id": "T20", "status": "FINDING", "detail": "IDOR: 1 finding(s)"}
        apply_automated_run(s, _execution(s, engagement, [finding]))
        assert _items(s, engagement)["WSTG-ATHZ-04"].status == "failed"


def test_tenant_mismatch_is_ignored(engagement):
    from attestra import db
    from attestra.auth_web.checklist_auto import apply_automated_run
    from attestra.models import Engagement, Tenant

    with db.session() as s:
        other = Tenant(name="Other Tenant")
        s.add(other)
        s.flush()
        assert other.id != s.get(Engagement, engagement).tenant_id
        ex = _execution(s, engagement, [{"test_id": "T19", "status": "PASSED", "detail": "ok"}], tenant_id=other.id)
        assert apply_automated_run(s, ex) == []


def test_incomplete_run_is_ignored(engagement):
    from attestra import db
    from attestra.auth_web.checklist_auto import verdicts_for_automated

    with db.session() as s:
        ex = _execution(s, engagement, [{"test_id": "T19", "status": "PASSED", "detail": "ok"}], status="RUNNING")
        assert verdicts_for_automated(s, ex) == []


def test_sync_engagement_idempotent_and_dry_run(engagement):
    from attestra import db
    from attestra.auth_web.checklist_auto import sync_engagement

    with db.session() as s:
        _import_zap(s, engagement)
        _execution(s, engagement, [{"test_id": "T19", "status": "PASSED", "detail": "0 finding(s)"}])
    with db.session() as s:
        dry = sync_engagement(s, engagement, dry_run=True)
        assert dry["final"]["WSTG-ATHN-04"] == "passed"
    with db.session() as s:
        assert _items(s, engagement)["WSTG-ATHN-04"].status == "not_started"  # dry run saved nothing
        first = sync_engagement(s, engagement)
        assert {c["ref"] for c in first["changes"]} == {"WSTG-ATHN-04"}
    with db.session() as s:
        n_audit = len(find_events(s))
        second = sync_engagement(s, engagement)
        assert second["changes"] == []
        assert len(find_events(s)) == n_audit


def test_nuclei_template_mapping_is_conservative():
    from attestra.auth_web.checklist_auto import NUCLEI_MAP

    def refs(tid):
        return {
            ref for ref, pat, excl in NUCLEI_MAP if pat.search(tid) and not (excl and excl.search(tid))
        }

    assert refs("weak-csp-detect") == {"WSTG-CONF-12"}
    assert refs("csp-script-src-wildcard") == {"WSTG-CONF-12"}
    assert refs("xss-deprecated-header") == set()
    assert refs("http-missing-security-headers:cross-origin-opener-policy") == set()
    assert refs("generic-ssrf-detect") == {"WSTG-BUSL-09"}
    assert refs("cookies-without-secure") == {"WSTG-SESS-02"}