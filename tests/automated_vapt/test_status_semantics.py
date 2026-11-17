"""FND-06: case status vocabulary, run-validity gating and checklist honesty (INT wiring)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from attestra import config
from attestra.auth_web import checklist_auto
from attestra.automated_vapt.core import orchestrator as orch
from attestra.automated_vapt.core import run_validity as rv
from attestra.automated_vapt.core.test_context import TestContext


def _ctx(**extra) -> TestContext:
    return TestContext(
        engagement_id=1, tenant_id=1, asset_id=1, target_base_url="https://app.example.test/",
        test_case_ids=["T03"], profile="baseline", actor="t", allow_private=False, extra=dict(extra),
    )


def _waf(n: int) -> list[dict]:
    return [{"cls": "waf_block", "reasons": ["cloudflare"], "confidence": 0.9}] * n


def _ok(n: int) -> list[dict]:
    return [{"cls": "app_ok", "reasons": [], "confidence": 0.9}] * n


@pytest.fixture(autouse=True)
def _enforce(monkeypatch):
    monkeypatch.setattr(config, "RUN_VALIDITY_MODE", "enforce", raising=False)


def test_waf_blocked_pass_becomes_blocked_and_never_confirmed():
    acc: list[rv.CaseValidity] = []
    case = {"test_id": "T03", "status": "PASSED", "module": {"validity_samples": _waf(4)},
            "validation": {"status": "CONFIRMED"}}
    orch._apply_case_validity("T03", case, _ctx(), acc)
    assert case["status"] == "BLOCKED"
    assert case["validation"] == {}
    assert case["case_validity"]["state"] == rv.PARTIALLY_BLOCKED
    assert "validity_samples" not in case["module"]  # value-free summary only
    run = orch._aggregate_validity(acc, _ctx())
    assert run.state == rv.PARTIALLY_BLOCKED and run.fully_blocked


def test_waf_finding_is_capped_to_potential():
    acc: list[rv.CaseValidity] = []
    case = {"test_id": "T07", "status": "FINDING",
            "module": {"validity_samples": _waf(2) + _ok(1), "finding_candidate": True},
            "validation": {"status": "CONFIRMED"}}
    orch._apply_case_validity("T07", case, _ctx(), acc)
    assert case["status"] == "FINDING"
    assert case["validation"]["status"] == "POTENTIAL"
    assert case["validation"]["capped_reason"].startswith("capped")


def test_valid_samples_keep_pass_and_confirmed():
    acc: list[rv.CaseValidity] = []
    case = {"test_id": "T03", "status": "PASSED", "module": {"validity_samples": _ok(3)},
            "validation": {"status": "CONFIRMED"}}
    orch._apply_case_validity("T03", case, _ctx(), acc)
    assert case["status"] == "PASSED"
    assert case["validation"]["status"] == "CONFIRMED"
    assert orch._aggregate_validity(acc, _ctx()).state == rv.VALID


def test_legacy_case_without_samples_is_unchanged():
    acc: list[rv.CaseValidity] = []
    case = {"test_id": "T19", "status": "PASSED", "validation": {}}
    orch._apply_case_validity("T19", case, _ctx(), acc)
    assert case["status"] == "PASSED"
    assert acc == [] and "case_validity" not in case


def test_observe_mode_does_not_gate(monkeypatch):
    monkeypatch.setattr(config, "RUN_VALIDITY_MODE", "observe", raising=False)
    case = {"test_id": "T03", "status": "PASSED", "module": {"validity_samples": _waf(3)},
            "validation": {"status": "CONFIRMED"}}
    orch._apply_case_validity("T03", case, _ctx(), [])
    assert case["status"] == "PASSED"
    assert case["validation"]["status"] == "CONFIRMED"
    assert case["case_validity"]["state"] == rv.PARTIALLY_BLOCKED


@pytest.mark.parametrize("hint", ["BLOCKED", "INCONCLUSIVE", "NOT_TESTED", "DEFERRED", "SKIPPED"])
def test_run_authz_module_honours_status_hint(monkeypatch, hint):
    from attestra.automated_vapt.testing import cors_tests

    monkeypatch.setattr(
        cors_tests, "run",
        lambda client, base, **kw: {"status_hint": hint, "skip_reason": "x", "finding_candidate": False,
                                    "observations": {"detail": f"{hint} detail"}, "validity_samples": []},
    )
    out = orch._run_authz_module("CORS", _ctx(httpx_client=object()), "infrastructure")
    assert out["status"] == hint
    assert out["validation"] == {} and out["false_positive"] == {}


def test_missing_secondary_profile_rolediff_not_passed(monkeypatch):
    from attestra.automated_vapt.testing import role_diff_tests

    monkeypatch.setattr(
        role_diff_tests, "run",
        lambda client, base, **kw: {"status_hint": "NOT_TESTED", "skip_reason": "no_second_identity",
                                    "finding_candidate": False, "observations": {}},
    )
    out = orch._run_authz_module("ROLEDIFF", _ctx(httpx_client=object()), "authorization")
    assert out["status"] == "NOT_TESTED"


def _ex(cases: list[dict], run_validity: dict | None = None) -> SimpleNamespace:
    data: dict = {"cases": cases}
    if run_validity is not None:
        data["run_validity"] = run_validity
    return SimpleNamespace(id=7, status="COMPLETED", result_json=json.dumps(data))


def test_checklist_never_passes_blocked_or_inconclusive():
    ex = _ex([
        {"test_id": "SESSION", "status": "INCONCLUSIVE", "detail": "only edge responses"},
        {"test_id": "T20", "status": "NOT_TESTED", "detail": "no second identity"},
        {"test_id": "XSS", "status": "BLOCKED", "detail": "waf"},
    ])
    vs = checklist_auto.verdicts_for_automated(None, ex)
    assert vs and all(v.status == "blocked" for v in vs)


def test_checklist_pass_downgraded_when_run_not_valid():
    ex = _ex([{"test_id": "T19", "status": "PASSED", "detail": "ok"}],
             {"state": "PARTIALLY_BLOCKED", "sample_count": 10})
    vs = checklist_auto.verdicts_for_automated(None, ex)
    assert [v.status for v in vs] == ["blocked"]


def test_checklist_legacy_run_unchanged():
    ex = _ex([{"test_id": "T19", "status": "PASSED", "detail": "ok"}])
    assert [v.status for v in checklist_auto.verdicts_for_automated(None, ex)] == ["passed"]
    ex2 = _ex([{"test_id": "T19", "status": "PASSED", "detail": "ok"}], {"state": "VALID", "sample_count": 4})
    assert [v.status for v in checklist_auto.verdicts_for_automated(None, ex2)] == ["passed"]


def test_ssrf_maps_to_inpv19_and_unmapped_ids_are_audited():
    assert checklist_auto.AUTOMATED_MAP["SSRF"] == ("WSTG-INPV-19",)
    assert "WSTG-BUSL-09" not in {r for rs in checklist_auto.AUTOMATED_MAP.values() for r in rs}
    rows = checklist_auto.unmapped_audit(_ex([{"test_id": "NOPE_X", "status": "PASSED"}]))
    assert rows == [{"test_id": "NOPE_X", "ref": "", "kind": "unmapped"}]


def test_execution_public_dict_reads_legacy_as_not_computed():
    ex = SimpleNamespace(id=1, engagement_id=1, tenant_id=1, asset_id=1, target_base_url="", profile="baseline",
                         test_case_ids=[], status="COMPLETED", requested_by="", allow_private=False, error="",
                         result_json=json.dumps({"cases": []}), created_at=None, started_at=None, ended_at=None)
    d = orch.execution_public_dict(ex)
    assert d["run_validity"]["state"] == rv.NOT_COMPUTED
    assert d["policy_decisions"] == []
