"""AASI Phase 7 reporting section builders and QA helpers."""

from __future__ import annotations

from types import SimpleNamespace

from attestra.reports.aasi_sections import (
    COVERAGE_STATUSES,
    aasi_qa_issues,
    aasi_report_context,
    build_coverage_matrix,
    build_executive_section,
    build_technical_section,
    build_traceability_appendix,
    empty_aasi_payload,
)

# @lat: [[tests#AASI Phase 7 reporting]]


def _finding(**kwargs):
    defaults = {
        "id": 101,
        "title": "Prompt injection",
        "validation_status": "potential",
        "cwe": 1427,
        "owasp_top10": "LLM01: Prompt Injection",
        "tools": ["garak"],
        "evidence": [],
        "remediation": "Add input filtering",
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _bundle():
    runs = [
        {
            "id": 1,
            "tenant_id": 9,
            "engagement_id": 42,
            "status": "COMPLETED",
            "tasks": [{"tool": "garak"}],
        }
    ]
    decisions = [
        {
            "id": 10,
            "run_id": 1,
            "tenant_id": 9,
            "engagement_id": 42,
            "kind": "hypothesis",
            "payload": {
                "id": "hyp-1",
                "statement": "Model may accept injected instructions",
                "basis": "observed",
                "uncertainty": 0.4,
                "evidence_ids": ["ev-1"],
            },
        },
        {
            "id": 11,
            "run_id": 1,
            "tenant_id": 9,
            "engagement_id": 42,
            "kind": "recommendation",
            "payload": {
                "id": "rec-1",
                "hypothesis_id": "hyp-1",
                "registered_test_id": "garak",
                "authorized_test_type": "ai_llm",
                "rationale": "Run garak promptinject probes",
                "approval_required": False,
            },
        },
        {
            "id": 12,
            "run_id": 1,
            "tenant_id": 9,
            "engagement_id": 42,
            "kind": "planner_outcome",
            "payload": {
                "id": "plan-1",
                "recommendation_id": "rec-1",
                "registered_test_id": "garak",
                "outcome": "EXECUTED",
                "tool": "garak",
            },
        },
        {
            "id": 13,
            "run_id": 1,
            "tenant_id": 9,
            "engagement_id": 42,
            "kind": "conclusion",
            "payload": {
                "id": "conc-1",
                "subject_ids": ["rec-1", "hyp-1", "101"],
                "conclusion_type": "potential_finding",
                "evidence_citations": ["ev-1"],
                "evidence_hash": "abc123",
                "finding_id": 101,
                "recommended_action": "Filter untrusted instructions",
                "confidence": 0.7,
                "confidence_basis": "scanner heuristic",
            },
        },
    ]
    findings = [_finding(evidence=[SimpleNamespace(id="ev-1", sha256="abc123")])]
    assets = [
        SimpleNamespace(id=7, kind="ai_app", name="Chatbot", identifier="https://llm.example"),
        SimpleNamespace(id=8, kind="web_app", name="Portal", identifier="https://app.example"),
    ]
    return runs, decisions, findings, assets


# @lat: [[tests#AASI Phase 7 reporting#Empty when disabled]]
def test_empty_when_disabled():
    ctx = aasi_report_context(enabled=False, tenant_id=1, engagement_id=1, runs=[{"id": 1}])
    assert ctx["aasi"]["present"] is False
    assert ctx["aasi"]["executive"] is None


# @lat: [[tests#AASI Phase 7 reporting#Empty when no runs]]
def test_empty_when_no_runs():
    ctx = aasi_report_context(enabled=True, tenant_id=1, engagement_id=1, runs=[], decisions=[])
    assert ctx["aasi"] == empty_aasi_payload()


# @lat: [[tests#AASI Phase 7 reporting#Executive posture and inventory]]
def test_executive_posture_and_inventory():
    runs, decisions, findings, assets = _bundle()
    section = build_executive_section(
        runs=runs, decisions=decisions, findings=findings, assets=assets
    )
    assert section["inventory"][0]["kind"] == "ai_app"
    assert len(section["inventory"]) == 1
    assert section["potential"] == 1
    assert section["confirmed"] == 0
    assert "not AI confidence" in section["posture"]
    assert section["confidence_disclaimer"]


# @lat: [[tests#AASI Phase 7 reporting#Technical rows]]
def test_technical_rows():
    runs, decisions, findings, _ = _bundle()
    tech = build_technical_section(
        runs=runs,
        decisions=decisions,
        findings=findings,
        framework_version="Attestra-test",
    )
    assert len(tech["rows"]) == 1
    row = tech["rows"][0]
    assert row["test_id"] == "garak"
    assert row["hypothesis_id"] == "hyp-1"
    assert row["recommendation_id"] == "rec-1"
    assert row["evidence_hash"] == "abc123"
    assert row["validation"] == "potential"
    assert row["confidence_is_not_severity"] is True
    assert row["framework_version"] == "Attestra-test"


# @lat: [[tests#AASI Phase 7 reporting#Traceability chain ids]]
def test_traceability_chain_ids():
    runs, decisions, findings, _ = _bundle()
    trace = build_traceability_appendix(runs=runs, decisions=decisions, findings=findings)
    assert len(trace["chains"]) == 1
    chain = trace["chains"][0]
    assert chain["hypothesis_id"] == "hyp-1"
    assert chain["recommendation_id"] == "rec-1"
    assert chain["conclusion_id"] == "conc-1"
    assert chain["finding_id"] == "101"
    assert "ev-1" in chain["evidence_ids"]
    assert chain["run_id"] == "1"


# @lat: [[tests#AASI Phase 7 reporting#Coverage never missing as pass]]
def test_coverage_never_missing_as_pass():
    matrix = build_coverage_matrix(findings=[], decisions=[], runs=[])
    assert set(matrix["statuses"]) == COVERAGE_STATUSES
    for row in matrix["owasp_llm"]:
        assert row["status"] == "not_assessed"
        assert row["status"] not in {"pass", "passed", "ok"}
    for row in matrix["tools"]:
        assert row["status"] == "not_tested"

    runs, decisions, findings, _ = _bundle()
    matrix2 = build_coverage_matrix(findings=findings, decisions=decisions, runs=runs)
    llm01 = next(r for r in matrix2["owasp_llm"] if r["id"] == "LLM01")
    assert llm01["status"] == "potential"
    garak = next(r for r in matrix2["tools"] if r["id"] == "garak")
    assert garak["status"] == "potential"


# @lat: [[tests#AASI Phase 7 reporting#Not tested stays not tested]]
def test_not_tested_from_planner_outcome():
    decisions = [
        {
            "kind": "planner_outcome",
            "payload": {
                "id": "p1",
                "tool": "promptfoo",
                "outcome": "NOT_TESTED",
                "llm_ids": ["LLM08"],
            },
        }
    ]
    matrix = build_coverage_matrix(findings=[], decisions=decisions, runs=[])
    llm08 = next(r for r in matrix["owasp_llm"] if r["id"] == "LLM08")
    assert llm08["status"] == "not_tested"
    pf = next(r for r in matrix["tools"] if r["id"] == "promptfoo")
    assert pf["status"] == "not_tested"


# @lat: [[tests#AASI Phase 7 reporting#QA invalid evidence ref]]
def test_qa_invalid_evidence_ref():
    runs, decisions, findings, assets = _bundle()
    ctx = aasi_report_context(
        enabled=True,
        tenant_id=9,
        engagement_id=42,
        runs=runs,
        decisions=decisions,
        findings=findings,
        assets=assets,
        known_evidence_ids={"other-ev"},
    )
    codes = {i["code"] for i in ctx["aasi"]["qa_issues"]}
    assert "aasi_invalid_evidence_ref" in codes


# @lat: [[tests#AASI Phase 7 reporting#QA unreproduced confirmed]]
def test_qa_unreproduced_confirmed():
    runs, decisions, findings, assets = _bundle()
    findings[0].validation_status = "confirmed"
    findings[0].evidence = []
    # Strip evidence from conclusion so technical row has no hash.
    for d in decisions:
        if d["kind"] == "conclusion":
            d["payload"].pop("evidence_hash", None)
            d["payload"]["evidence_citations"] = []
    ctx = aasi_report_context(
        enabled=True,
        tenant_id=9,
        engagement_id=42,
        runs=runs,
        decisions=decisions,
        findings=findings,
        assets=assets,
        known_evidence_ids=set(),
    )
    codes = {i["code"] for i in aasi_qa_issues(ctx)}
    assert "aasi_unreproduced_confirmed" in codes


# @lat: [[tests#AASI Phase 7 reporting#QA cross tenant]]
def test_qa_cross_tenant():
    runs, decisions, findings, assets = _bundle()
    # Inject a foreign run summary after build via direct QA call.
    ctx = aasi_report_context(
        enabled=True,
        tenant_id=9,
        engagement_id=42,
        runs=runs,
        decisions=decisions,
        findings=findings,
        assets=assets,
        known_evidence_ids={"ev-1"},
    )
    ctx["aasi"]["runs"].append({"id": 99, "tenant_id": 999, "engagement_id": 42})
    codes = {i["code"] for i in aasi_qa_issues(ctx)}
    assert "aasi_cross_tenant" in codes


# @lat: [[tests#AASI Phase 7 reporting#Unresolved hypotheses]]
def test_unresolved_hypotheses_listed():
    runs = [{"id": 1, "tenant_id": 1, "engagement_id": 1, "status": "COMPLETED"}]
    decisions = [
        {
            "kind": "hypothesis",
            "run_id": 1,
            "tenant_id": 1,
            "payload": {
                "id": "hyp-open",
                "statement": "Possible tool misuse",
                "basis": "inferred",
                "uncertainty": "high",
            },
        }
    ]
    section = build_executive_section(
        runs=runs, decisions=decisions, findings=[], assets=[]
    )
    assert any(h["id"] == "hyp-open" for h in section["unresolved_hypotheses"])


# @lat: [[tests#AASI Phase 7 reporting#Full context present]]
def test_full_context_present():
    runs, decisions, findings, assets = _bundle()
    ctx = aasi_report_context(
        enabled=True,
        tenant_id=9,
        engagement_id=42,
        runs=runs,
        decisions=decisions,
        findings=findings,
        assets=assets,
        known_evidence_ids={"ev-1", "abc123"},
    )
    aasi = ctx["aasi"]
    assert aasi["present"] is True
    assert aasi["executive"]["potential"] == 1
    assert aasi["technical"]["rows"]
    assert aasi["traceability"]["chains"]
    assert aasi["coverage_matrix"]["owasp_llm"]
    assert "aasi_invalid_evidence_ref" not in {i["code"] for i in aasi["qa_issues"]}


# @lat: [[tests#AASI Phase 7 reporting#Render hook empty off]]
def test_render_hook_empty_when_aasi_off(monkeypatch):
    from attestra.reports import render as render_mod

    monkeypatch.setattr(
        "attestra.reports.aasi_sections._aasi_enabled", lambda: False, raising=False
    )
    monkeypatch.setattr("attestra.aasi.enabled", lambda: False)

    eng = SimpleNamespace(id=1, tenant_id=1, assets=[])
    out = render_mod._aasi_report_context(None, eng, [])
    assert out["aasi"]["present"] is False
