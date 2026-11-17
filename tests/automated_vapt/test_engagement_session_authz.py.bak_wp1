"""Engagement-profile path for Elite authz modules (no lab account_a passwords)."""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from attestra.automated_vapt.core.session_auth import SessionAuth
from attestra.automated_vapt.core import test_context as _test_context
from attestra.automated_vapt.testing import (
    api_security_tests,
    authentication_tests,
    authorization_tests,
    business_logic_tests,
    idor_bola_tests,
    role_diff_tests,
    session_security_tests,
    tenant_isolation_tests,
)
from attestra.automated_vapt.testing._session import (
    SKIP_NO_AUTH_SESSION,
    SKIP_NO_SECOND_ROLE,
    is_lab_client,
    resolve_mode,
)


BASE = "http://app.test/"
TOKEN_A = "test-session-a"
TOKEN_B = "test-session-b"


def _ctx(client, **extra) -> _test_context.TestContext:
    payload = {
        "httpx_client": client,
        "_capture_urls": [BASE + "dashboard"],
        "_capture_api_urls": [BASE + "api/me", BASE + "api/items/1"],
        **extra,
    }
    return _test_context.TestContext(
        engagement_id=1,
        tenant_id=1,
        asset_id=1,
        target_base_url=BASE,
        test_case_ids=["T03"],
        profile="baseline",
        actor="tester",
        allow_private=True,
        extra=payload,
    )


def _auth(token: str, *, profile_id: int = 1) -> SessionAuth:
    return SessionAuth(
        profile_id=profile_id,
        status="ready",
        note="test",
        headers={"Authorization": f"Bearer {token}"},
        redact_values=(token,),
    )


def _make_app(*, unauth_same: bool = False, leak_secrets: bool = False, tenants: bool = False):
    def _token(request: Request) -> str:
        header = request.headers.get("authorization") or ""
        if header.lower().startswith("bearer "):
            return header.split(" ", 1)[1].strip()
        return ""

    async def dashboard(request: Request):
        token = _token(request)
        if not token:
            if unauth_same:
                return JSONResponse({"id": "me", "role": "user"})
            return JSONResponse({"detail": "auth required"}, status_code=401)
        return JSONResponse({"id": "me", "role": "user"})

    async def api_me(request: Request):
        token = _token(request)
        if not token:
            return JSONResponse({"detail": "auth required"}, status_code=401)
        body: dict = {"id": "me", "role": "user" if token == TOKEN_A else "other"}
        if leak_secrets:
            body["password"] = "dummy-hash"
        if tenants:
            body["tenant"] = "tenant-a" if token == TOKEN_A else "tenant-b"
            if token == TOKEN_A:
                body["other_tenant"] = "tenant-b"
        return JSONResponse(body)

    async def api_item(request: Request):
        token = _token(request)
        if not token:
            return JSONResponse({"detail": "auth required"}, status_code=401)
        return JSONResponse({"id": "1", "owner": "shared"})

    async def login(_request: Request):
        # Must not be hit on the engagement path.
        return PlainTextResponse("lab-login-should-not-run", status_code=500)

    return Starlette(
        routes=[
            Route("/dashboard", dashboard, methods=["GET"]),
            Route("/api/me", api_me, methods=["GET"]),
            Route("/api/items/1", api_item, methods=["GET"]),
            Route("/login", login, methods=["POST"]),
        ]
    )


@pytest.fixture
def client():
    return TestClient(_make_app(), base_url=BASE)


def test_resolve_mode_lab_vs_skip_vs_engagement():
    app_client = TestClient(_make_app(), base_url=BASE)
    assert is_lab_client(app_client) is True
    assert resolve_mode(app_client, {}) == ("lab", None)

    raw = httpx.Client()
    try:
        assert is_lab_client(raw) is False
        assert resolve_mode(raw, {}) == ("skip", None)
        auth = _auth(TOKEN_A)
        ctx = _ctx(raw, _session_auth=auth)
        mode, got = resolve_mode(raw, {"ctx": ctx})
        assert mode == "engagement" and got is auth
    finally:
        raw.close()


def test_t03_engagement_uses_session_not_lab_login(client):
    ctx = _ctx(client, _session_auth=_auth(TOKEN_A))
    result = authentication_tests.run(client, BASE, ctx=ctx)
    assert result["test_id"] == "T03"
    assert result["finding_candidate"] is False
    assert result["observations"]["mode"] == "engagement_session"
    assert result["observations"]["login_works"] is True
    assert result["observations"]["unauthorized_blocked"] is True
    assert result["observations"]["account_enumeration"]["skipped"] is True


def test_t03_engagement_flags_unauth_same_body():
    client = TestClient(_make_app(unauth_same=True), base_url=BASE)
    ctx = _ctx(client, _session_auth=_auth(TOKEN_A))
    result = authentication_tests.run(client, BASE, ctx=ctx)
    assert result["finding_candidate"] is True
    assert result["observations"]["settings_open_without_auth"] is True
    # Evidence must not echo the bearer token.
    for pair in result.get("evidence_pairs") or []:
        blob = json.dumps(pair.request_headers or {})
        assert TOKEN_A not in blob
        assert "Bearer" not in blob or "[REDACTED]" in blob


def test_t03_skips_plain_httpx_without_session():
    raw = httpx.Client()
    try:
        result = authentication_tests.run(raw, "https://example.test/")
        assert result.get("status_hint") == "SKIPPED"
        assert result["skip_reason"] == SKIP_NO_AUTH_SESSION
        assert result["finding_candidate"] is False
    finally:
        raw.close()


def test_t04_t05_t06_rolediff_skip_without_second_role(client):
    ctx = _ctx(client, _session_auth=_auth(TOKEN_A))
    for mod, tid in (
        (idor_bola_tests, "T04"),
        (authorization_tests, "T05"),
        (tenant_isolation_tests, "T06"),
        (role_diff_tests, "ROLEDIFF"),
    ):
        result = mod.run(client, BASE, ctx=ctx)
        assert result["test_id"] == tid
        assert result.get("skip_reason") == SKIP_NO_SECOND_ROLE
        assert result["finding_candidate"] is False


def test_t04_engagement_with_two_sessions_flags_secret_keys():
    client = TestClient(_make_app(leak_secrets=True), base_url=BASE)
    ctx = _ctx(
        client,
        _session_auth=_auth(TOKEN_A),
        _secondary_session_auth=_auth(TOKEN_B, profile_id=2),
    )
    result = idor_bola_tests.run(client, BASE, ctx=ctx)
    assert result.get("skip_reason") is None
    assert result["finding_candidate"] is True
    assert "password" in result["observations"]["secret_key_names"]
    for pair in result.get("evidence_pairs") or []:
        blob = json.dumps(pair.request_headers or {}) + (pair.response_body or "")
        assert TOKEN_A not in blob and TOKEN_B not in blob


def test_t07_engagement_missing_auth_enforced(client):
    ctx = _ctx(client, _session_auth=_auth(TOKEN_A))
    result = api_security_tests.run(client, BASE, ctx=ctx)
    assert result["finding_candidate"] is False
    assert result["observations"]["missing_auth_enforced"] is True
    assert result["observations"]["mode"] == "engagement_session"


def test_biz_engagement_owner_access(client):
    ctx = _ctx(client, _session_auth=_auth(TOKEN_A))
    result = business_logic_tests.run(client, BASE, ctx=ctx)
    assert result.get("skip_reason") is None
    assert result["observations"]["owner_access_ok"] is True
    assert result["finding_candidate"] is False


def test_rolediff_engagement_with_two_sessions(client):
    ctx = _ctx(
        client,
        _session_auth=_auth(TOKEN_A),
        _secondary_session_auth=_auth(TOKEN_B, profile_id=2),
    )
    result = role_diff_tests.run(client, BASE, ctx=ctx)
    assert result.get("skip_reason") is None
    assert result["observations"]["mode"] == "engagement_session"
    assert result["observations"]["account_a_ok"] is True
    assert result["observations"]["account_b_ok"] is True


def test_session_inspects_alg_none_without_lab_login(client):
    # Classic unsigned JWT structure for alg=none observation only — not a live secret.
    unsigned = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ4In0."
    auth = SessionAuth(
        profile_id=1,
        status="ready",
        note="test",
        headers={"Authorization": f"Bearer {unsigned}"},
        redact_values=(unsigned,),
    )
    ctx = _ctx(client, _session_auth=auth)
    result = session_security_tests.run(client, BASE, ctx=ctx)
    assert result["observations"]["mode"] == "engagement_session"
    assert result["observations"]["jwt_present"] is True
    assert result["observations"]["jwt_alg_none"] is True
    assert result["finding_candidate"] is True


def test_orchestrator_session_sets_include_authz_modules():
    from attestra.automated_vapt.core import orchestrator as orch

    needed = {
        "T03", "T04", "T05", "T06", "T07",
        "SESSION", "INJ", "XSS", "XSSDOM", "XSSSTORE", "FILE",
        "BIZ", "ROLEDIFF", "SSRF", "UPLOAD",
    }
    assert needed <= set(orch._SESSION_AUTH_CASES)
    assert needed <= set(orch._SESSION_DEPENDENT)
    assert "T01" in orch._SESSION_AUTH_CASES
    assert "T01" not in orch._SESSION_DEPENDENT
    assert "T02" in orch._SESSION_AUTH_CASES
    assert "T02" not in orch._SESSION_DEPENDENT


def test_run_authz_module_skips_plain_httpx_without_session():
    from attestra.automated_vapt.core import orchestrator as orch

    raw = httpx.Client()
    try:
        ctx = _test_context.TestContext(
            engagement_id=1,
            tenant_id=1,
            asset_id=1,
            target_base_url="https://example.test/",
            test_case_ids=["T03"],
            profile="baseline",
            actor="tester",
            allow_private=False,
            extra={"httpx_client": raw},
        )
        out = orch._run_authz_module("T03", ctx, "authentication")
        assert out["status"] == "SKIPPED"
        assert out["skip_reason"] == SKIP_NO_AUTH_SESSION
    finally:
        raw.close()
