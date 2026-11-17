"""G-04 explainable, versioned risk: golden scores unchanged; missing EPSS is unknown, not 0."""
# @lat: [[intel-and-reporting#Explainable versioned risk]]

from __future__ import annotations

import pytest

from attestra import scoring

GOLDEN = [
    # (cvss, severity, epss, kev, criticality, exposure, in_cde) -> risk_score (pre-G-04 formula)
    ((9.8, "critical", 0.97, True, 5, "internet", False), 9.8 * 1.97 * 1.5 * 1.4 * 1.3),
    ((5.0, "medium", None, False, 3, "internal", False), 5.0),
    ((None, "high", 0.1, False, 1, None, True), 7.5 * 1.1 * 0.6 * 1.3),
    ((None, "info", None, False, 3, "internet", False), 1.0 * 1.3),
    ((None, "info", None, False, 3, "internal", False), 0.0),
]


@pytest.mark.parametrize("args,expected", GOLDEN)
def test_risk_score_unchanged(args, expected):
    assert scoring.risk_score(*args) == round(expected, 2)
    exp = scoring.explain_risk_modifiers(*args)
    assert exp["risk_score"] == round(expected, 2)


def test_missing_epss_flagged_not_zeroed():
    exp = scoring.explain_risk_modifiers(7.5, "high", None, False, 3, "internet")
    assert exp["epss"] is None and exp["epss_known"] is False
    assert exp["epss_factor"] == 1.0
    assert any("EPSS unknown" in n for n in exp["notes"])
    known = scoring.explain_risk_modifiers(7.5, "high", 0.0, False, 3, "internet")
    assert known["epss"] == 0.0 and known["epss_known"] is True
    assert known["risk_score"] == exp["risk_score"]


def test_versioning_and_provenance_fields():
    exp = scoring.explain_risk_modifiers(
        None, "high", 0.2, False, 3, "internet",
        kev_known=True, stale_inputs=["epss"], intel_source_version="fs1;kev=x@1;epss=y@2",
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    )
    assert exp["scoring_version"] == scoring.SCORING_VERSION
    assert exp["formula_version"] == "risk-v1"
    assert exp["kev_known"] is True and exp["stale_inputs"] == ["epss"]
    assert exp["intel_source_version"].startswith("fs1;")
    assert exp["cvss_calculation"]["score"] == 9.3
    # CVSS of record is never rewritten by the explanation
    assert exp["cvss_score"] is None


def test_kev_unknown_unless_confirmed():
    assert scoring.explain_risk_modifiers(5.0, "medium")["kev_known"] is False
    assert scoring.explain_risk_modifiers(5.0, "medium", kev=True)["kev_known"] is True


def test_reconstructable():
    exp = scoring.explain_risk_modifiers(6.0, "medium", 0.3, True, 4, "internet", False)
    rebuilt = exp["base"] * exp["epss_factor"] * exp["kev_factor"] * exp["asset_weight"] * exp["exposure_weight"]
    assert round(rebuilt, 2) == exp["risk_score"]
