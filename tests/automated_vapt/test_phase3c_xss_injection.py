"""Phase 3c: DOM/stored XSS canaries and stronger boolean-safe injection."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from attestra.automated_vapt.core.test_registry import get_test_case
from attestra.automated_vapt.testing import injection_tests, xss_tests
from attestra.automated_vapt.testing.coverage_matrix import PHASE3_COVERAGE
from tests.automated_vapt.conftest import login
from tests.automated_vapt.fixtures import create_secure_app, create_vulnerable_app

BASE = "http://localhost:8765/"


@pytest.fixture
def clients():
    return (
        TestClient(create_secure_app(), base_url=BASE),
        TestClient(create_vulnerable_app(), base_url=BASE),
    )


# @lat: [[tests#Phase 3c DOM stored XSS#Registry XSSDOM XSSSTORE]]
def test_registry_xssdom_xssstore():
    assert get_test_case("XSSDOM") is not None
    assert get_test_case("XSSSTORE") is not None
    row = next(r for r in PHASE3_COVERAGE["xss"] if r["capability"] == "stored_dom_xss")
    assert row["status"] == "partial"
    assert "XSSDOM" in row["test_ids"] and "XSSSTORE" in row["test_ids"]


# @lat: [[tests#Phase 3c DOM stored XSS#DOM sink vulnerable vs secure]]
def test_dom_sink_vulnerable_vs_secure(clients):
    secure, vuln = clients
    login(vuln, "account_a", "account-a-pass")
    v = xss_tests.run_dom(vuln, BASE)
    assert v["finding_candidate"] is True
    assert v["observations"]["sink_in_source"] is True
    login(secure, "account_a", "account-a-pass")
    s = xss_tests.run_dom(secure, BASE)
    assert s["finding_candidate"] is False


# @lat: [[tests#Phase 3c DOM stored XSS#Stored guestbook vulnerable vs secure]]
def test_stored_guestbook_vulnerable_vs_secure(clients):
    secure, vuln = clients
    v = xss_tests.run_stored(vuln, BASE, force=True)
    assert v["finding_candidate"] is True
    login(secure, "account_a", "account-a-pass")
    s = xss_tests.run_stored(secure, BASE, force=True)
    assert s["finding_candidate"] is False


# @lat: [[tests#Phase 3c DOM stored XSS#Injection boolean canaries stay safe]]
def test_injection_boolean_canaries_flag(monkeypatch):
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    def search(request):
        q = request.query_params.get("q") or ""
        if "'" in q:
            return PlainTextResponse("PG::SyntaxError: ERROR:  syntax error at or near", status_code=500)
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/search", search)])
    client = TestClient(app, base_url=BASE)
    out = injection_tests.run(client, BASE, probes=[("/search", "q")])
    assert out["finding_candidate"] is True
    assert "error" in out["detail"].lower() or out["observations"]["probes"]
