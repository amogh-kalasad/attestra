"""Elite Phase E6: authentication and authorization test modules."""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from attestra import config, db, services
from attestra.automated_vapt.core import orchestrator as orch
from attestra.automated_vapt.testing import (
    api_security_tests,
    authentication_tests,
    authorization_tests,
    idor_bola_tests,
    tenant_isolation_tests,
)
from tests.automated_vapt.fixtures import create_secure_app, create_vulnerable_app


@pytest.fixture
def elite_flag(monkeypatch):
    monkeypatch.setattr(config, "AUTOMATED_VAPT_ENABLED", True)


@pytest.fixture
def clients():
    return (
        TestClient(create_secure_app(), base_url="http://localhost:8765"),
        TestClient(create_vulnerable_app(), base_url="http://localhost:8765"),
    )


# @lat: [[tests#Elite Phase E6 authz modules#Secure BOLA no finding]]
def test_secure_bola_no_finding(clients, elite_flag):
    secure, _ = clients
    result = idor_bola_tests.run(secure, "http://localhost:8765/")
    assert result["finding_candidate"] is False
    assert result["observations"]["unauthorized_blocked"] is True


# @lat: [[tests#Elite Phase E6 authz modules#Vulnerable BOLA finding]]
def test_vulnerable_bola_finding(clients, elite_flag):
    _, vuln = clients
    result = idor_bola_tests.run(vuln, "http://localhost:8765/")
    assert result["finding_candidate"] is True
    assert result["observations"]["exposed_secrets"] is True


# @lat: [[tests#Elite Phase E6 authz modules#Secure auth and role]]
def test_secure_auth_and_role(clients, elite_flag):
    secure, _ = clients
    authn = authentication_tests.run(secure, "http://localhost:8765/")
    assert authn["finding_candidate"] is False
    authz = authorization_tests.run(secure, "http://localhost:8765/")
    assert authz["finding_candidate"] is False


# @lat: [[tests#Elite Phase E6 authz modules#Vulnerable auth and role]]
def test_vulnerable_auth_and_role(clients, elite_flag):
    _, vuln = clients
    authn = authentication_tests.run(vuln, "http://localhost:8765/")
    assert authn["finding_candidate"] is True
    authz = authorization_tests.run(vuln, "http://localhost:8765/")
    assert authz["finding_candidate"] is True


# @lat: [[tests#Elite Phase E6 authz modules#Tenant and disclosure]]
def test_tenant_and_disclosure(clients, elite_flag):
    secure, vuln = clients
    assert tenant_isolation_tests.run(secure, "http://localhost:8765/")["finding_candidate"] is False
    assert tenant_isolation_tests.run(vuln, "http://localhost:8765/")["finding_candidate"] is True
    assert api_security_tests.run(secure, "http://localhost:8765/")["finding_candidate"] is False
    assert api_security_tests.run(vuln, "http://localhost:8765/")["finding_candidate"] is True


# @lat: [[tests#Elite Phase E6 authz modules#Orchestrator T04 secure vs vulnerable]]
def test_orchestrator_t04_secure_vs_vulnerable(fresh_db, elite_flag, clients):
    secure, vuln = clients
    today = date.today()

    def _run(client):
        with db.session() as s:
            e = services.create_engagement(
                s,
                tenant="Elite E6 Client",
                name="Elite E6",
                type="vapt",
                frameworks=["pci_dss_4"],
                window_start=today - timedelta(days=1),
                window_end=today + timedelta(days=30),
                actor="tester",
            )
            services.add_authorization(
                s,
                e.id,
                filename="roe.txt",
                data=b"authorized",
                signer="Client",
                signed_on=today - timedelta(days=1),
                expires_on=today + timedelta(days=30),
                rules_of_engagement="local",
                environments=["dev"],
                actor="tester",
            )
            a = services.add_asset(
                s,
                e.id,
                kind="web_app",
                identifier="http://localhost:8765/",
                name="Mock",
                environment="dev",
                actor="tester",
            )
            ex = orch.create_execution(
                s,
                engagement_id=e.id,
                asset_id=a.id,
                test_case_ids=["T04"],
                actor="tester",
                allow_private=True,
            )
            xid = ex.id
        with db.session() as s:
            done = orch.run_execution(s, xid, actor="tester", extra={"httpx_client": client})
            assert done.status == "COMPLETED"
            return orch.execution_public_dict(done)["result"]["cases"][0]

    secure_case = _run(secure)
    vuln_case = _run(vuln)
    assert secure_case["status"] == "PASSED"
    assert vuln_case["status"] == "FINDING"
