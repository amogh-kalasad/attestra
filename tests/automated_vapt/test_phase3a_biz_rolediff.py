"""Phase 3a: BIZ and ROLEDIFF catalogue wiring on lab mocks."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from attestra.automated_vapt.core.test_registry import get_test_case
from attestra.automated_vapt.testing import business_logic_tests, role_diff_tests, tenant_isolation_tests
from attestra.automated_vapt.testing.coverage_matrix import PHASE3_COVERAGE
from tests.automated_vapt.fixtures import create_secure_app, create_vulnerable_app

BASE = "http://localhost:8765/"


@pytest.fixture
def clients():
    return (
        TestClient(create_secure_app(), base_url=BASE),
        TestClient(create_vulnerable_app(), base_url=BASE),
    )


# @lat: [[tests#Phase 3a BIZ and ROLEDIFF#Registry lists BIZ and ROLEDIFF]]
def test_registry_lists_biz_and_rolediff():
    assert get_test_case("BIZ") is not None
    assert get_test_case("ROLEDIFF") is not None
    biz = next(r for r in PHASE3_COVERAGE["business_logic"] if r["capability"] == "owner_access_sanity")
    assert biz["status"] == "implemented" and "BIZ" in biz["test_ids"]
    role = next(r for r in PHASE3_COVERAGE["business_logic"] if r["capability"] == "multi_role_comparison")
    assert role["status"] == "implemented" and "ROLEDIFF" in role["test_ids"]


# @lat: [[tests#Phase 3a BIZ and ROLEDIFF#BIZ on secure vs vulnerable]]
def test_biz_secure_vs_vulnerable(clients):
    secure, vuln = clients
    s = business_logic_tests.run(secure, BASE)
    assert s["finding_candidate"] is False
    assert s["observations"]["owner_access_ok"] is True
    assert s["observations"]["foreign_exposed"] is False
    v = business_logic_tests.run(vuln, BASE)
    assert v["finding_candidate"] is True
    assert v["observations"]["foreign_exposed"] is True


# @lat: [[tests#Phase 3a BIZ and ROLEDIFF#ROLEDIFF flags cross-role list]]
def test_rolediff_flags_cross_role_list(clients):
    secure, vuln = clients
    s = role_diff_tests.run(secure, BASE)
    assert s["finding_candidate"] is False
    v = role_diff_tests.run(vuln, BASE)
    assert v["finding_candidate"] is True
    assert v["observations"]["cross_role_list"] is True


# @lat: [[tests#Phase 3a BIZ and ROLEDIFF#T06 skips without mock accounts]]
def test_t06_skips_without_mock_accounts():
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    def login(request):
        return PlainTextResponse("no", status_code=401)

    app = Starlette(routes=[Route("/login", login, methods=["POST"])])
    client = TestClient(app, base_url=BASE)
    out = tenant_isolation_tests.run(client, BASE)
    assert out.get("status_hint") == "SKIPPED"
    assert out["skip_reason"] == "no_mock_accounts"
    assert out["finding_candidate"] is False


# @lat: [[tests#Phase 3a BIZ and ROLEDIFF#Orchestrator dispatches BIZ]]
def test_orchestrator_dispatches_biz(clients):
    from attestra.automated_vapt.core import orchestrator as orch
    from attestra.automated_vapt.core.test_context import TestContext

    secure, vuln = clients
    ctx = TestContext(
        engagement_id=1,
        tenant_id=1,
        asset_id=1,
        target_base_url=BASE,
        test_case_ids=["BIZ"],
        profile="baseline",
        actor="t",
        allow_private=True,
        extra={"httpx_client": vuln},
    )
    out = orch._run_authz_module("BIZ", ctx, "authorization")
    assert out["status"] == "FINDING"
    assert out["test_id"] == "BIZ"
