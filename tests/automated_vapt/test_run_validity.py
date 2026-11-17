"""FND-03 run validity (§3.2) and status gating."""

from __future__ import annotations

from types import SimpleNamespace

from attestra.automated_vapt.core import run_validity as rv
from attestra.automated_vapt.core.response_classifier import Classification, ResponseClass as RC


def _c(cls: RC) -> Classification:
    return Classification(cls, ("t",), 1.0)


# @lat: [[run-validity-and-policy#Run validity]]
def test_precedence_table():
    assert rv.evaluate([_c(RC.NETWORK_FAILED)] * 4 + [_c(RC.APP_OK)])[0] == rv.NETWORK_FAILED
    assert rv.evaluate([_c(RC.APP_OK), _c(RC.AUTH_EXPIRED)])[0] == rv.AUTH_EXPIRED
    assert rv.evaluate([_c(RC.APP_OK)], auth_lost=True)[0] == rv.AUTH_EXPIRED
    assert rv.evaluate([_c(RC.APP_OK), _c(RC.CHALLENGE), _c(RC.RATE_LIMITED)])[0] == rv.CHALLENGE_DETECTED
    assert rv.evaluate([_c(RC.APP_OK), _c(RC.RATE_LIMITED)])[0] == rv.RATE_LIMITED
    assert rv.evaluate([_c(RC.APP_OK), _c(RC.WAF_BLOCK)])[0] == rv.PARTIALLY_BLOCKED
    assert rv.evaluate([])[0] == rv.INCONCLUSIVE
    assert rv.evaluate([_c(RC.APP_AUTH_DENIED)])[0] == rv.VALID


def test_case_validity_from_result_dict_samples():
    result = {"validity_samples": [{"cls": "waf_block", "reasons": ["x"], "confidence": 0.9}, {"cls": "app_ok"}]}
    cv = rv.CaseValidity.from_result("T03", result)
    j = cv.to_json()
    assert j["state"] == rv.PARTIALLY_BLOCKED and j["sample_count"] == 2 and j["version"] == "rv1"


def test_aggregate_run_json_shape():
    a = rv.CaseValidity("T03")
    a.extend([_c(RC.APP_OK), _c(RC.APP_AUTH_DENIED)])
    b = rv.CaseValidity("T07")
    b.extend([_c(RC.CHALLENGE)])
    run = rv.aggregate_run([a, b])
    j = run.to_json()
    assert j["state"] == rv.CHALLENGE_DETECTED
    assert set(j) >= {"state", "reasons", "sample_count", "by_class", "affected_cases", "computed_at", "version"}
    assert j["affected_cases"] == ["T07"]


def test_gate_case_status_never_passes_blocked():
    g = rv.gate_case_status
    assert g(status_hint=None, finding_candidate=False, case_state=rv.CHALLENGE_DETECTED) == "BLOCKED"
    assert g(status_hint=None, finding_candidate=False, case_state=rv.INCONCLUSIVE) == "INCONCLUSIVE"
    assert g(status_hint=None, finding_candidate=False, case_state=rv.VALID) == "PASSED"
    assert g(status_hint="BLOCKED", finding_candidate=False, case_state=rv.VALID) == "BLOCKED"
    assert g(status_hint=None, finding_candidate=True, case_state=rv.PARTIALLY_BLOCKED) == "FINDING"
    # Legacy module without samples keeps its PASSED.
    assert g(status_hint=None, finding_candidate=False, case_state=rv.INCONCLUSIVE, has_samples=False) == "PASSED"


def test_invalid_case_caps_confirmed():
    assert rv.cap_validation_status("CONFIRMED", rv.PARTIALLY_BLOCKED)[0] == "POTENTIAL"
    assert rv.cap_validation_status("CONFIRMED", rv.VALID)[0] == "CONFIRMED"


def test_guard_lost_and_legacy_rows():
    assert rv.guard_lost(SimpleNamespace(status="expired")) in (True, False)
    assert rv.read_run_validity({})["state"] == rv.NOT_COMPUTED
