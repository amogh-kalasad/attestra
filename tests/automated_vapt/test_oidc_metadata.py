"""D-03 passive OIDC discovery review (OIDCMETA)."""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from attestra.automated_vapt.testing import oidc_metadata_tests as om

BASE = "http://idp.test/"
GOOD = {
    "issuer": "http://idp.test",
    "authorization_endpoint": "https://idp.test/auth",
    "token_endpoint": "https://idp.test/token",
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "code_challenge_methods_supported": ["S256"],
    "id_token_signing_alg_values_supported": ["RS256"],
}


def _client(doc=None, *, status=200, waf=False):
    calls: list[str] = []

    def h(request):
        calls.append(f"{request.method} {request.url.path}")
        if waf:
            return HTMLResponse("<title>Just a moment...</title>Verifying you are human", status_code=403, headers={"cf-mitigated": "challenge"})
        if doc is None:
            return JSONResponse({"detail": "not found"}, status_code=404)
        return JSONResponse(doc, status_code=status)

    app = Starlette(routes=[Route("/{p:path}", h, methods=["GET", "POST"])])
    c = TestClient(app, base_url=BASE)
    return c, calls


# @lat: [[run-validity-and-policy#OIDC metadata]]
def test_review_flags_weak_metadata():
    bad = dict(GOOD, response_types_supported=["code", "id_token token", "token"], grant_types_supported=["password", "implicit"],
               code_challenge_methods_supported=["plain"], redirect_uris=["https://*.example.test/cb"])
    codes = {i["code"] for i in om.review_metadata(bad)["issues"]}
    assert {"implicit_flow_advertised", "ropc_grant_advertised", "implicit_grant_advertised",
            "pkce_s256_not_advertised", "pkce_plain_allowed", "wildcard_redirect_metadata"} <= codes


def test_review_good_metadata_has_no_finding():
    assert om.review_metadata(dict(GOOD, issuer="https://idp.test"))["finding"] is False


def test_non_tls_endpoint_flagged():
    codes = {i["code"] for i in om.review_metadata(dict(GOOD, token_endpoint="http://idp.example/token"))["issues"]}
    assert "non_tls_endpoint" in codes


def test_run_single_get_and_finding():
    c, calls = _client(dict(GOOD, grant_types_supported=["password"]))
    r = om.run(c, BASE)
    assert r["finding_candidate"] is True
    assert calls == ["GET /.well-known/openid-configuration"]


def test_absent_discovery_is_not_tested():
    c, _ = _client(None)
    r = om.run(c, BASE)
    assert r["status_hint"] == "NOT_TESTED" and r["skip_reason"] == om.SKIP_ABSENT


def test_challenge_is_blocked():
    c, _ = _client(GOOD, waf=True)
    r = om.run(c, BASE)
    assert r["status_hint"] == "BLOCKED" and r["finding_candidate"] is False


def test_offsite_discovery_url_refused():
    c, calls = _client(GOOD)
    ctx = SimpleNamespace(extra={"_oidc_discovery_url": "https://evil.example/.well-known/openid-configuration"})
    r = om.run(c, BASE, ctx=ctx)
    assert r["skip_reason"] == om.SKIP_OUT_OF_SCOPE and calls == []
