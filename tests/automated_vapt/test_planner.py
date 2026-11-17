"""I-05 explainable planner and D-05 guided plans (pure, no traffic)."""

from __future__ import annotations

import pytest

from attestra.automated_vapt.core.planner import PlanFacts, plan_cases, rate_profile
from attestra.automated_vapt.guided import plans as gp


# @lat: [[run-validity-and-policy#Planner]]
def test_order_passive_before_authz_before_intrusive():
    out = plan_cases(["T22", "T04", "SESSION", "T03", "SSRF"], PlanFacts(has_session=True, has_secondary_session=True,
                     intrusive_decisions={"SSRF": {"allow": True}, "T22": {"allow": True}}))
    order = [c["test_id"] for c in out["cases"]]
    assert order.index("SESSION") < order.index("T03") < order.index("T04") < order.index("SSRF") < order.index("T22")
    assert out["run"] == order


def test_skips_carry_reasons():
    out = plan_cases(["T04", "SSRF", "UPLOAD", "T12", "T05"], PlanFacts(has_session=True, intrusive_decisions={"UPLOAD": {"allow": False, "reason": "cleanup_plan_missing"}}))
    assert out["skipped"] == {"T04": "no_second_role", "SSRF": "no_policy_decision", "UPLOAD": "cleanup_plan_missing", "T12": "not_executable"}
    assert "T05" in out["run"]
    assert all(c["explanation"] for c in out["cases"])


def test_low_rate_profile_on_cdn_or_prior_block():
    assert rate_profile(PlanFacts()).get("name") == "default"
    assert rate_profile(PlanFacts(cdn_detected=True))["name"] == "low_rate_cdn"
    assert rate_profile(PlanFacts(previous_validity="CHALLENGE_DETECTED"))["max_rps"] <= 1.0


def test_auth_expired_defers_session_cases():
    out = plan_cases(["T05", "T03"], PlanFacts(has_session=True, previous_validity="AUTH_EXPIRED"))
    assert out["deferred"] == ["T05"]


# @lat: [[run-validity-and-policy#Guided business-flow plans]]
def test_guided_plans_list_and_result():
    plans = gp.list_plans(two_identities_available=False)
    assert {p["plan_id"] for p in plans} >= {"BF-WORKFLOW-SKIP", "BF-OBJECT-OWNERSHIP"}
    assert any(p["available"] is False for p in plans if p["needs_two_identities"])
    res = gp.record_result("BF-REPLAY-LIMIT", "finding", evidence_ids=["ev-1"])
    assert res["status"] == "FINDING" and res["source"] == "guided"
    with pytest.raises(ValueError):
        gp.record_result("BF-REPLAY-LIMIT", "PASSED")
    with pytest.raises(ValueError):
        gp.record_result("nope", "PASSED", evidence_ids=["x"])
