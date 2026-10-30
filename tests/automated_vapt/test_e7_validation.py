"""Elite Phase E7: vulnerability validation and false-positive checks."""

from __future__ import annotations

from attestra.automated_vapt.validation.confidence_calculator import confidence_for
from attestra.automated_vapt.validation.false_positive_checker import check_false_positive
from attestra.automated_vapt.validation.severity_calculator import severity_for
from attestra.automated_vapt.validation.vulnerability_validator import (
    CONFIRMED,
    NOT_VULNERABLE,
    POTENTIAL,
    validate_result,
)


# @lat: [[tests#Elite Phase E7 validation#Http 200 alone not confirmed]]
def test_http_200_alone_not_confirmed():
    out = validate_result(
        {
            "executed": True,
            "in_scope": True,
            "auth_valid": True,
            "identity_ok": True,
            "expected_control_defined": True,
            "status_code": 200,
            "finding_candidate": False,
        }
    )
    assert out["status"] == NOT_VULNERABLE
    assert any("200" in r for r in out["reasons"])


# @lat: [[tests#Elite Phase E7 validation#Exposure confirms]]
def test_exposure_confirms():
    out = validate_result(
        {
            "executed": True,
            "in_scope": True,
            "auth_valid": True,
            "identity_ok": True,
            "expected_control_defined": True,
            "protected_data_exposed": True,
            "authorization_bypass": True,
            "reproducible": True,
            "evidence_supports": True,
            "finding_candidate": True,
        }
    )
    assert out["status"] == CONFIRMED
    assert confidence_for(out["status"]) == "high"
    assert severity_for(cwe=639, hints={"protected_data_exposed": True}) == "high"


# @lat: [[tests#Elite Phase E7 validation#Authorized access not vulnerable]]
def test_authorized_access_not_vulnerable():
    out = validate_result(
        {
            "executed": True,
            "in_scope": True,
            "auth_valid": True,
            "identity_ok": True,
            "expected_control_defined": True,
            "authorized_access": True,
            "protected_data_exposed": False,
            "authorization_bypass": False,
        }
    )
    assert out["status"] == NOT_VULNERABLE


# @lat: [[tests#Elite Phase E7 validation#Fp checker empty error]]
def test_fp_checker_empty_error():
    fp = check_false_positive({"status_code": 404, "response_body": "", "protected_data_exposed": False})
    assert fp["is_likely_fp"] is True
    assert fp["allow_manual_review"] is True
    # Exposure is never suppressed.
    fp2 = check_false_positive({"status_code": 200, "protected_data_exposed": True})
    assert fp2["is_likely_fp"] is False


# @lat: [[tests#Elite Phase E7 validation#Potential without evidence]]
def test_potential_without_evidence():
    out = validate_result(
        {
            "executed": True,
            "in_scope": True,
            "auth_valid": True,
            "identity_ok": True,
            "expected_control_defined": True,
            "protected_data_exposed": True,
            "reproducible": True,
            "evidence_supports": False,
            "finding_candidate": True,
        }
    )
    assert out["status"] == POTENTIAL
