"""Phase 3b: scoped SSRF canary + safe upload probe on lab fixtures."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from attestra.automated_vapt.core.test_registry import get_test_case
from attestra.automated_vapt.testing import file_upload_tests, ssrf_tests
from attestra.automated_vapt.testing.coverage_matrix import PHASE3_COVERAGE
from tests.automated_vapt.fixtures import create_secure_app, create_vulnerable_app

BASE = "http://localhost:8765/"


@pytest.fixture
def clients():
    return (
        TestClient(create_secure_app(), base_url=BASE),
        TestClient(create_vulnerable_app(), base_url=BASE),
    )


# @lat: [[tests#Phase 3b SSRF and upload#Registry and matrix]]
def test_registry_and_matrix_ssrf_upload():
    assert get_test_case("SSRF") is not None
    assert get_test_case("UPLOAD") is not None
    ssrf = next(r for r in PHASE3_COVERAGE["injection"] if r["capability"] == "ssrf_canary")
    assert ssrf["status"] == "partial" and "SSRF" in ssrf["test_ids"]
    up = next(r for r in PHASE3_COVERAGE["file_security"] if r["capability"] == "upload_file_inclusion")
    assert up["status"] == "partial" and "UPLOAD" in up["test_ids"]


# @lat: [[tests#Phase 3b SSRF and upload#Blocked metadata destinations]]
def test_blocked_ssrf_destinations():
    assert ssrf_tests.is_blocked_ssrf_destination("http://169.254.169.254/latest/meta-data/")
    assert ssrf_tests.is_blocked_ssrf_destination("http://127.0.0.1/admin")
    assert ssrf_tests.is_blocked_ssrf_destination("http://localhost/")
    assert not ssrf_tests.is_blocked_ssrf_destination("https://canary.attestra.invalid/probe")


# @lat: [[tests#Phase 3b SSRF and upload#SSRF vulnerable vs secure]]
def test_ssrf_vulnerable_vs_secure(clients):
    secure, vuln = clients
    v = ssrf_tests.run(vuln, BASE, force=True)
    assert v["finding_candidate"] is True
    assert any(p.get("canary_reflected") for p in v["observations"]["probes"])
    s = ssrf_tests.run(secure, BASE, force=True)
    assert s["finding_candidate"] is False


# @lat: [[tests#Phase 3b SSRF and upload#Upload vulnerable vs secure]]
def test_upload_vulnerable_vs_secure(clients):
    secure, vuln = clients
    v = file_upload_tests.run(vuln, BASE, force=True)
    assert v["finding_candidate"] is True
    assert v["observations"]["marker_served"] is True
    s = file_upload_tests.run(secure, BASE, force=True)
    assert s["finding_candidate"] is False


# @lat: [[tests#Phase 3b SSRF and upload#Disabled outside allowlist]]
def test_ssrf_upload_skip_when_disabled(monkeypatch, clients):
    monkeypatch.setenv("ATTESTRA_AUTOMATED_VAPT_SSRF", "0")
    monkeypatch.setenv("ATTESTRA_AUTOMATED_VAPT_UPLOAD", "0")
    _, vuln = clients
    assert ssrf_tests.run(vuln, BASE)["skip_reason"] == ssrf_tests.SKIP_DISABLED
    assert file_upload_tests.run(vuln, BASE)["skip_reason"] == file_upload_tests.SKIP_DISABLED
