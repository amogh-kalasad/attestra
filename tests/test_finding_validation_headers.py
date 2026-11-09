"""Phase 0: evidence header helpers (attestra/finding_validation/headers.py)."""

from __future__ import annotations

from attestra.finding_validation.headers import (
    clickjacking_protection_present_in_evidence,
    finding_claims_header_missing,
    hsts_present_in_evidence,
    permissions_policy_present_in_evidence,
    response_has_header,
)


# @lat: [[tests#test_finding_validation_headers.py#HSTS presence requires max-age]]
def test_hsts_present_requires_max_age():
    assert hsts_present_in_evidence(["Strict-Transport-Security: max-age=31536000"])
    assert hsts_present_in_evidence(["x\nstrict-transport-security:max-age = 300; preload"])
    assert not hsts_present_in_evidence(["Strict-Transport-Security: preload"])
    assert not hsts_present_in_evidence(["Content-Type: text/html"])
    assert not hsts_present_in_evidence([])
    assert not hsts_present_in_evidence([None, ""])


# @lat: [[tests#test_finding_validation_headers.py#Permissions-Policy and clickjacking helpers]]
def test_permissions_policy_present():
    assert permissions_policy_present_in_evidence(["Permissions-Policy: geolocation=()"])
    assert permissions_policy_present_in_evidence(["HTTP/1.1 200\r\npermissions-policy: camera=()"])
    assert not permissions_policy_present_in_evidence(["Feature-Policy: camera 'none'"])


def test_clickjacking_protection_present():
    assert clickjacking_protection_present_in_evidence(["X-Frame-Options: SAMEORIGIN"])
    assert clickjacking_protection_present_in_evidence(["x-frame-options: deny"])
    assert clickjacking_protection_present_in_evidence(["Content-Security-Policy: frame-ancestors 'none'"])
    assert clickjacking_protection_present_in_evidence(["CSP: frame-ancestors https://parent.example.com"])
    # Obsolete ALLOW-FROM and an empty frame-ancestors are not protection.
    assert not clickjacking_protection_present_in_evidence(["X-Frame-Options: ALLOW-FROM https://x"])
    assert not clickjacking_protection_present_in_evidence(["Content-Security-Policy: default-src 'self'"])


# @lat: [[tests#test_finding_validation_headers.py#Header claim detection]]
def test_response_has_header():
    raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Frame-Options: DENY\r\n"
    assert response_has_header(raw, "X-Frame-Options")
    assert response_has_header(raw, "content-type")
    assert not response_has_header(raw, "Strict-Transport-Security")
    assert not response_has_header("", "X-Frame-Options")
    assert not response_has_header(raw, "")


def test_finding_claims_header_missing_keys():
    assert finding_claims_header_missing("Strict-Transport-Security Header Not Set") == "hsts"
    assert finding_claims_header_missing("HSTS header missing on HTTPS") == "hsts"
    assert finding_claims_header_missing("Permissions Policy Header Not Set") == "permissions_policy"
    assert finding_claims_header_missing("Missing Anti-clickjacking Header") == "clickjacking"
    assert finding_claims_header_missing("X-Frame-Options header absent") == "clickjacking"
    # Not a missing claim at all, or a header we do not track.
    assert finding_claims_header_missing("HSTS present with short max-age") is None
    assert finding_claims_header_missing("Content Security Policy header not set") is None
    # Description can carry the claim when the title does not.
    assert finding_claims_header_missing("Transport hardening", "HSTS is not present") == "hsts"
