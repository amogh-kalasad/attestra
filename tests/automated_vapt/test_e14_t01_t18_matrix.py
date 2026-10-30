"""Elite E14: catalogue T01–T18 coverage matrix against secure/vulnerable mocks."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from attestra.automated_vapt.capture.browser_capture import capture_screenshot
from attestra.automated_vapt.capture.http_capture import capture_request
from attestra.automated_vapt.core import scope_validator
from attestra.automated_vapt.core.test_registry import list_test_cases
from attestra.automated_vapt.evidence.evidence_hasher import EvidenceManifest, sha256_hex
from attestra.automated_vapt.evidence.evidence_redactor import redact_http_pair
from attestra.automated_vapt.evidence.request_response_renderer import render_http_pair_png
from attestra.automated_vapt.evidence.screenshot_annotator import annotate_screenshot, pillow_available
from attestra.automated_vapt.testing import (
    api_security_tests,
    authentication_tests,
    authorization_tests,
    idor_bola_tests,
    tenant_isolation_tests,
)
from attestra.automated_vapt.validation.false_positive_checker import check_false_positive
from attestra.automated_vapt.validation.vulnerability_validator import (
    CONFIRMED,
    NOT_VULNERABLE,
    validate_result,
)
from attestra.proof.pair import HttpPair
from tests.automated_vapt.fixtures import create_secure_app, create_vulnerable_app

_TINY_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
    b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
)


@pytest.fixture
def clients():
    return (
        TestClient(create_secure_app(), base_url="http://localhost:8765"),
        TestClient(create_vulnerable_app(), base_url="http://localhost:8765"),
    )


# @lat: [[tests#Elite Phase E14 matrix#Catalogue contains t01 t18]]
def test_catalogue_contains_t01_t18():
    ids = {c.id for c in list_test_cases()}
    for i in range(1, 19):
        assert f"T{i:02d}" in ids


# @lat: [[tests#Elite Phase E14 matrix#T01 t02 capture both apps]]
def test_t01_t02_capture_both_apps(clients):
    secure, vuln = clients
    scope = scope_validator.build_scope_from_asset("http://localhost:8765/", allow_private=True)
    for client in (secure, vuln):
        tx = capture_request(
            "GET",
            "http://localhost:8765/",
            scope=scope,
            client=client,
            check_dns=False,
        )
        assert tx.pair.status == 200
        shot = capture_screenshot(
            "http://localhost:8765/",
            scope=scope,
            capture_fn=lambda _u: _TINY_PNG,
            check_dns=False,
        )
        assert shot.screenshot_png.startswith(b"\x89PNG")


# @lat: [[tests#Elite Phase E14 matrix#T03 t07 secure vs vulnerable]]
def test_t03_t07_secure_vs_vulnerable(clients):
    secure, vuln = clients
    assert authentication_tests.run(secure, "http://localhost:8765/")["finding_candidate"] is False
    assert authentication_tests.run(vuln, "http://localhost:8765/")["finding_candidate"] is True
    assert idor_bola_tests.run(secure, "http://localhost:8765/")["finding_candidate"] is False
    assert idor_bola_tests.run(vuln, "http://localhost:8765/")["finding_candidate"] is True
    assert authorization_tests.run(secure, "http://localhost:8765/")["finding_candidate"] is False
    assert authorization_tests.run(vuln, "http://localhost:8765/")["finding_candidate"] is True
    assert tenant_isolation_tests.run(secure, "http://localhost:8765/")["finding_candidate"] is False
    assert tenant_isolation_tests.run(vuln, "http://localhost:8765/")["finding_candidate"] is True
    assert api_security_tests.run(secure, "http://localhost:8765/")["finding_candidate"] is False
    assert api_security_tests.run(vuln, "http://localhost:8765/")["finding_candidate"] is True


# @lat: [[tests#Elite Phase E14 matrix#T08 t09 validation]]
def test_t08_t09_validation():
    secure_v = validate_result(
        {
            "executed": True,
            "in_scope": True,
            "auth_valid": True,
            "identity_ok": True,
            "expected_control_defined": True,
            "authorized_access": True,
            "protected_data_exposed": False,
        }
    )
    assert secure_v["status"] == NOT_VULNERABLE
    vuln_v = validate_result(
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
    assert vuln_v["status"] == CONFIRMED
    fp = check_false_positive({"status_code": 200, "authorized_access": True, "protected_data_exposed": False})
    assert fp["allow_manual_review"] is True


# @lat: [[tests#Elite Phase E14 matrix#T10 t12 evidence]]
def test_t10_t12_evidence():
    pair = HttpPair(
        method="GET",
        url="http://localhost/api/projects/proj-b",
        request_headers={"Authorization": "Bearer x"},
        status=200,
        response_body='{"secret_note":"SENSITIVE"}',
    )
    red = redact_http_pair(pair)
    assert any(v == "[REDACTED]" for k, v in red.request_headers.items() if k.lower() == "authorization")
    png = render_http_pair_png(pair)
    assert png.startswith(b"\x89PNG")
    if pillow_available():
        annotated, _ = annotate_screenshot(png, [{"x": 1, "y": 1, "w": 10, "h": 10, "label": "1"}])
        assert annotated.startswith(b"\x89PNG")
    man = EvidenceManifest(engagement_id=1, test_execution_id=1)
    man.add(evidence_id="p1", file_name="pair.png", data=png, capture_method="renderer")
    assert man.verify("p1", png)
    assert sha256_hex(png) == man.entries[0].hash


# @lat: [[tests#Elite Phase E14 matrix#T16 scope enforcement]]
def test_t16_scope_enforcement():
    scope = scope_validator.build_scope_from_asset("http://localhost:8765/", allow_private=True)
    with pytest.raises(Exception):
        scope_validator.validate_target_url("https://evil.example/", scope, check_dns=False)
