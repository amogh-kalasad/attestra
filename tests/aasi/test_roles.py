"""Unit tests for AASI Phase 3 logical roles (provider=None stubs)."""

from __future__ import annotations

# @lat: [[tests#AASI Phase 3 roles]]

from attestra.aasi.roles import (
    AI_ADAPTER_TEST_IDS,
    run_ai_security,
    run_evidence_reviewer,
    run_hypothesis,
    run_quality_reviewer,
    run_strategist,
)


def _ctx(**overrides):
    base = {
        "run_id": "run-test",
        "tenant_id": 1,
        "engagement_id": 10,
        "objective": "Assess AI chat endpoint",
        "authorized_assets": [{"id": 42, "kind": "ai_app"}],
        "authorized_test_types": ["ai_llm", "ai_agent"],
        "coverage_gaps": ["ai_llm", "garak"],
        "observations": [],
        "findings_meta": [],
        "evidence_meta": [],
        "plan_skips": ["T02"],
    }
    base.update(overrides)
    return base


# @lat: [[tests#AASI Phase 3 roles#Strategist stub outline]]
def test_strategist_stub_outline():
    plan = run_strategist(_ctx(), provider=None)
    assert plan.objectives
    assert any("coverage gap" in o.lower() or "assess" in o.lower() for o in plan.objectives)
    assert 42 in plan.asset_ids
    assert plan.notes == "stub-strategist"


# @lat: [[tests#AASI Phase 3 roles#Hypothesis empty without observations]]
def test_hypothesis_empty_without_observations():
    hyps = run_hypothesis(_ctx(observations=[]), provider=None)
    assert hyps == []


# @lat: [[tests#AASI Phase 3 roles#Hypothesis from observations]]
def test_hypothesis_from_observations():
    hyps = run_hypothesis(
        _ctx(observations=[{"id": "obs-1", "asset_id": 42}]),
        provider=None,
    )
    assert len(hyps) == 1
    assert hyps[0].asset_id == 42
    assert hyps[0].cites == ("obs-1",)
    assert hyps[0].basis == "observed"


# @lat: [[tests#AASI Phase 3 roles#AI security catalogue-gap stubs]]
def test_ai_security_catalogue_gap_stubs():
    recs = run_ai_security(_ctx(), provider=None, hypotheses=[])
    assert recs
    assert all(r.test_id.lower() in AI_ADAPTER_TEST_IDS for r in recs)
    assert all(r.asset_id == 42 for r in recs)
    assert all(r.needs_approval for r in recs)


# @lat: [[tests#AASI Phase 3 roles#AI security empty without gaps]]
def test_ai_security_empty_without_gaps():
    recs = run_ai_security(_ctx(coverage_gaps=[]), provider=None)
    assert recs == []


# @lat: [[tests#AASI Phase 3 roles#Evidence missing notes]]
def test_evidence_reviewer_missing_notes():
    notes = run_evidence_reviewer(
        _ctx(findings_meta=[{"id": "f1", "evidence_ids": []}]),
        provider=None,
    )
    assert any("no_evidence" in m for m in notes.missing)


# @lat: [[tests#AASI Phase 3 roles#Quality completeness]]
def test_quality_reviewer_completeness():
    plan = run_strategist(_ctx(), provider=None)
    recs = run_ai_security(_ctx(), provider=None)
    report = run_quality_reviewer(_ctx(), provider=None, plan=plan, recommendations=recs)
    assert report.completeness
    assert "T02" in report.skipped
    assert report.notes == "stub-quality"


# @lat: [[tests#AASI Phase 3 roles#Provider complete_json path]]
def test_roles_prefer_provider_complete_json():
    class FakeProvider:
        def complete_json(self, system, prompt, schema=None):
            if "strategist" in system or "Role=strategist" in system:
                return {"objectives": ["Priority probe"], "notes": "from-provider", "asset_ids": [42]}
            if "Role=hypothesis" in system:
                return {
                    "hypotheses": [
                        {
                            "statement": "Possible prompt injection",
                            "basis": "inferred",
                            "asset_id": 42,
                            "cites": [],
                            "uncertainty": "low",
                        }
                    ]
                }
            if "Role=ai_security" in system:
                return {
                    "recommendations": [
                        {
                            "hypothesis_id": "h1",
                            "asset_id": 42,
                            "test_id": "garak",
                            "test_type": "ai_llm",
                            "expected_evidence": ["garak-jsonl"],
                            "rationale": "probe injection",
                        }
                    ]
                }
            if "Role=evidence_reviewer" in system:
                return {"missing": ["x"], "contradictory": [], "suggested_retests": []}
            if "Role=quality_reviewer" in system:
                return {
                    "completeness": "ok",
                    "skipped": [],
                    "unsupported_claims": [],
                    "notes": "provider-quality",
                }
            return {}

    provider = FakeProvider()
    plan = run_strategist(_ctx(), provider=provider)
    assert plan.notes == "from-provider"
    assert plan.objectives == ("Priority probe",)
    hyps = run_hypothesis(_ctx(), provider=provider, plan=plan)
    assert hyps and hyps[0].statement.startswith("Possible")
    recs = run_ai_security(_ctx(), provider=provider, hypotheses=hyps)
    assert recs[0].test_id == "garak"
    notes = run_evidence_reviewer(_ctx(), provider=provider, recommendations=recs)
    assert notes.missing == ("x",)
    quality = run_quality_reviewer(_ctx(), provider=provider, plan=plan, recommendations=recs)
    assert quality.notes == "provider-quality"
