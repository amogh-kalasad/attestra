"""H-01 explicit retest outcomes (pure decision logic) + H-05 verified-fix link. No DB."""
# @lat: [[intel-and-reporting#Retest outcomes]]

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from attestra import retest
from attestra.remediation import packs


@pytest.mark.parametrize(
    "requested,reached,validity,expected",
    [
        ("fixed", True, None, "confirmed_fixed"),
        ("confirmed_fixed", True, "VALID", "confirmed_fixed"),
        ("fixed", False, None, "not_reached"),
        ("confirmed_fixed", True, "PARTIALLY_BLOCKED", "blocked"),
        ("confirmed_fixed", True, {"state": "CHALLENGE_DETECTED"}, "challenged"),
        ("confirmed_fixed", True, "AUTH_EXPIRED", "auth_expired"),
        ("confirmed_fixed", True, "RATE_LIMITED", "blocked"),
        ("confirmed_fixed", True, "NETWORK_FAILED", "not_reached"),
        ("still_open", True, "CHALLENGE_DETECTED", "still_present"),
        ("blocked", True, "VALID", "blocked"),
        ("environment_changed", True, "VALID", "environment_changed"),
        ("inconclusive", True, "VALID", "inconclusive"),
    ],
)
def test_decide_outcome(requested, reached, validity, expected):
    outcome, _ = retest.decide_outcome(requested, asset_reached=reached, run_validity=validity)
    assert outcome == expected


def test_only_confirmed_fixed_closes():
    assert [o for o in retest.OUTCOMES if retest.can_close(o)] == ["confirmed_fixed"]
    for o in ("blocked", "not_reached", "challenged", "auth_expired", "inconclusive", "environment_changed"):
        assert retest.OUTCOME_TO_LEGACY[o] == "inconclusive"


def test_unknown_result_rejected():
    with pytest.raises(Exception, match="result must be one of"):
        retest.normalize_outcome("closed")


def test_legacy_values_readable():
    assert retest.outcome_of(SimpleNamespace(result="fixed")) == "confirmed_fixed"
    assert retest.outcome_of(SimpleNamespace(result="still_open")) == "still_present"
    assert retest.outcome_of(SimpleNamespace(result="")) == ""
    nr = SimpleNamespace(result="inconclusive", finalized_at="x", asset_reached=False)
    assert retest.outcome_of(nr) == "not_reached"
    detail = SimpleNamespace(result="inconclusive", outcome_detail_json=json.dumps({"outcome": "challenged"}))
    assert retest.outcome_of(detail) == "challenged"
    pub = retest.retest_public_dict(SimpleNamespace(id=1, finding_id=2, result="fixed", asset_reached=True))
    assert pub["result"] == "confirmed_fixed" and pub["legacy_result"] == "fixed" and pub["closes_finding"]


def test_regression_link_keeps_both_runs():
    link = retest.regression_link(SimpleNamespace(id=7, status="fixed"), previous_run_id=10, current_run_id=11, retest_id=3)
    assert link["regression_of_finding_id"] == 7
    assert (link["previous_run_id"], link["current_run_id"]) == (10, 11)


def test_verified_fix_link():
    pack = packs.pack_for_concept("header:hsts-missing")
    meta = packs.structured_metadata(pack)
    assert meta["version"] == packs.PACK_METADATA_VERSION and meta["verification_steps"]
    ok = packs.link_verified_fix(pack, retest_outcome="fixed", retest_id=5, run_validity="VALID", verified_at="2026-11-17")
    assert ok["fix_verification"]["verified"] is True
    blocked = packs.link_verified_fix(pack, retest_outcome="confirmed_fixed", run_validity={"state": "CHALLENGE_DETECTED"})
    assert blocked["fix_verification"]["verified"] is False and blocked["fix_verification"]["verified_at"] == ""
    assert packs.link_verified_fix(pack)["fix_verification"]["retest_outcome"] == "not_retested"
