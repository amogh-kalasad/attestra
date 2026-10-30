"""Elite Phase E4: HTTPX capture and request/response normalization."""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from attestra import config, db, services
from attestra.automated_vapt.capture.http_capture import capture_request
from attestra.automated_vapt.capture.request_parser import parse_request
from attestra.automated_vapt.capture.response_parser import parse_response
from attestra.automated_vapt.core import orchestrator as orch
from attestra.automated_vapt.core import scope_validator
from attestra.proof.pair import HttpPair
from attestra.services import ServiceError
from tests.automated_vapt.fixtures import create_secure_app, create_vulnerable_app


@pytest.fixture
def elite_flag(monkeypatch):
    monkeypatch.setattr(config, "AUTOMATED_VAPT_ENABLED", True)


@pytest.fixture
def asgi_clients():
    # Starlette TestClient is an httpx.Client suitable for sync capture tests.
    secure = TestClient(create_secure_app(), base_url="http://localhost:8765")
    vuln = TestClient(create_vulnerable_app(), base_url="http://localhost:8765")
    yield secure, vuln


# @lat: [[tests#Elite Phase E4 HTTP capture#Capture public home]]
def test_capture_public_home(asgi_clients, elite_flag):
    secure, _ = asgi_clients
    scope = scope_validator.build_scope_from_asset("http://localhost:8765/", allow_private=True)
    tx = capture_request(
        "GET",
        "http://localhost:8765/",
        scope=scope,
        client=secure,
        check_dns=False,
    )
    assert tx.pair.status == 200
    assert "Public home" in tx.pair.response_body
    assert tx.elapsed_ms >= 0
    assert "[REDACTED]" not in (tx.report_pair.response_body if tx.report_pair else "")


# @lat: [[tests#Elite Phase E4 HTTP capture#Redacts authorization header]]
def test_redacts_authorization_header(asgi_clients, elite_flag):
    secure, _ = asgi_clients
    scope = scope_validator.build_scope_from_asset("http://localhost:8765/", allow_private=True)
    tx = capture_request(
        "GET",
        "http://localhost:8765/",
        scope=scope,
        headers={"Authorization": "Bearer secret-token-value"},
        client=secure,
        check_dns=False,
    )
    assert tx.report_pair is not None
    auth_vals = [v for k, v in tx.report_pair.request_headers.items() if k.lower() == "authorization"]
    assert auth_vals
    assert all(v == "[REDACTED]" for v in auth_vals)


# @lat: [[tests#Elite Phase E4 HTTP capture#Out of scope refused]]
def test_out_of_scope_refused(asgi_clients, elite_flag):
    secure, _ = asgi_clients
    scope = scope_validator.build_scope_from_asset("http://localhost:8765/", allow_private=True)
    with pytest.raises(ServiceError, match="out of scope"):
        capture_request(
            "GET",
            "https://evil.example/",
            scope=scope,
            client=secure,
            check_dns=False,
        )


# @lat: [[tests#Elite Phase E4 HTTP capture#Request parser extracts path ids]]
def test_request_parser_extracts_path_ids(elite_flag):
    pair = HttpPair(
        method="GET",
        url="http://localhost:8765/api/projects/proj-b?token=abc",
        request_headers={"Authorization": "Bearer x"},
        request_body="",
    )
    parsed = parse_request(pair)
    assert "proj-b" in parsed["path_identifiers"]
    assert parsed["query"]["token"] == "[REDACTED]"
    assert parsed["auth"]["has_authorization"] is True
    assert "Authorization" in parsed["original"]["headers"]


# @lat: [[tests#Elite Phase E4 HTTP capture#Response parser flags secrets]]
def test_response_parser_flags_secrets(elite_flag):
    pair = HttpPair(
        method="GET",
        url="http://localhost:8765/api/projects/proj-b",
        status=200,
        response_body='{"id":"proj-b","secret_note":"SENSITIVE: x","api_token":"tok_x"}',
    )
    parsed = parse_response(pair)
    assert parsed["status"] == 200
    assert "secret_note" in parsed["sensitive_indicators"] or "SENSITIVE" in parsed["sensitive_indicators"]


# @lat: [[tests#Elite Phase E4 HTTP capture#Orchestrator T01 with ASGI client]]
def test_orchestrator_t01_with_asgi_client(fresh_db, elite_flag, asgi_clients):
    secure, _ = asgi_clients
    today = date.today()
    with db.session() as s:
        e = services.create_engagement(
            s,
            tenant="Elite E4 Client",
            name="Elite E4",
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
            test_case_ids=["T01"],
            actor="tester",
            allow_private=True,
        )
        xid = ex.id

    with db.session() as s:
        done = orch.run_execution(
            s,
            xid,
            actor="tester",
            extra={"httpx_client": secure},
        )
        assert done.status == "COMPLETED"
        t01 = orch.execution_public_dict(done)["result"]["cases"][0]
        assert t01["test_id"] == "T01"
        assert t01["status"] == "PASSED"
        assert t01["capture"]["status"] == 200
