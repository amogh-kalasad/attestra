"""FND-04 / D-workstream: a WAF 403 or challenge never makes T03/T07 PASS."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from attestra.automated_vapt.core import test_context as _test_context
from attestra.automated_vapt.core.session_auth import SessionAuth
from attestra.automated_vapt.testing import api_security_tests, authentication_tests

BASE = "http://app.test/"
TOKEN = "test-session-waf"
FIX = Path(__file__).parent / "fixtures" / "waf"
CF_BLOCK = (FIX / "cf_block_403.html").read_text(encoding="utf-8")
CF_CHALLENGE = (FIX / "cf_challenge.html").read_text(encoding="utf-8")


def _app(mode: str):
    """mode: waf_unauth (WAF answers unauth, app answers authed), challenge_all, app_401."""

    def handler(request: Request):
        authed = (request.headers.get("authorization") or "") == f"Bearer {TOKEN}"
        if mode == "challenge_all":
            return HTMLResponse(CF_CHALLENGE, status_code=403, headers={"server": "cloudflare", "cf-mitigated": "challenge"})
        if not authed:
            if mode == "waf_unauth":
                return HTMLResponse(CF_BLOCK, status_code=403, headers={"server": "cloudflare"})
            return JSONResponse({"detail": "auth required"}, status_code=401)
        return JSONResponse({"id": "me", "role": "user"})

    paths = ["/dashboard", "/api/me", "/api/items/1"]
    return Starlette(routes=[Route(p, handler, methods=["GET"]) for p in paths])


def _ctx(client):
    auth = SessionAuth(profile_id=1, status="ready", note="t", headers={"Authorization": f"Bearer {TOKEN}"}, redact_values=(TOKEN,))
    return _test_context.TestContext(
        engagement_id=1, tenant_id=1, asset_id=1, target_base_url=BASE, test_case_ids=["T03", "T07"],
        profile="baseline", actor="tester", allow_private=True,
        extra={
            "httpx_client": client,
            "_capture_urls": [BASE + "dashboard"],
            "_capture_api_urls": [BASE + "api/me", BASE + "api/items/1"],
            "_session_auth": auth,
        },
    )


def _run(mod, mode):
    client = TestClient(_app(mode), base_url=BASE)
    return mod.run(client, BASE, ctx=_ctx(client))


# @lat: [[run-validity-and-policy#Response classifier]]
@pytest.mark.parametrize("mod", [authentication_tests, api_security_tests])
def test_waf_403_on_unauth_is_blocked_not_pass(mod):
    r = _run(mod, "waf_unauth")
    assert r["finding_candidate"] is False
    assert r.get("status_hint") in ("BLOCKED", "INCONCLUSIVE")
    assert r.get("skip_reason")  # pre-FND-06 orchestrators map this to SKIPPED, never PASSED
    if mod is authentication_tests:
        assert r["observations"].get("auth_required_ok") is not True


@pytest.mark.parametrize("mod", [authentication_tests, api_security_tests])
def test_challenge_everywhere_is_blocked(mod):
    r = _run(mod, "challenge_all")
    assert r["finding_candidate"] is False
    assert r.get("status_hint") == "BLOCKED"
    assert r.get("skip_reason") == "challenge_detected" or r.get("skip_reason")
    assert any(s.get("cls") == "challenge" for s in r.get("validity_samples") or [])


@pytest.mark.parametrize("mod", [authentication_tests, api_security_tests])
def test_application_401_still_passes(mod):
    r = _run(mod, "app_401")
    assert r["finding_candidate"] is False
    assert r.get("status_hint") in (None, "PASSED")
    assert r.get("skip_reason") is None


def test_evidence_never_contains_token():
    r = _run(authentication_tests, "waf_unauth")
    assert TOKEN not in repr(r.get("observations"))
