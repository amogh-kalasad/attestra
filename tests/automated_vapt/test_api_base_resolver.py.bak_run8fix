"""API base resolution for automated API tests (no Mongo, no network)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from attestra.automated_vapt.core import api_base as ab
from attestra.automated_vapt.core import js_api_discovery as jsd
from attestra.automated_vapt.core import replay_checks as rc
from attestra.automated_vapt.core.session_auth import SessionAuth
from attestra.automated_vapt.testing._session import probe_urls

FRONT = "https://app.example.test/"
API = "https://api.example.test"


def test_normalize_strips_trailing_slash_and_adds_scheme():
    assert ab.normalize_api_base("https://api.example.test/") == API
    assert ab.normalize_api_base("api.example.test") == API
    assert ab.normalize_api_base("https://API.example.test:443/v1/") == API + "/v1"
    assert ab.normalize_api_base("http://10.0.0.5:8080/") == "http://10.0.0.5:8080"
    assert ab.normalize_api_base("") == ""
    assert ab.normalize_api_base("   ") == ""


@pytest.mark.parametrize("bad", ["ftp://api.example.test", "https://user:pw@api.example.test",
                                 "https://api.example.test/?x=1", "https://"])
def test_normalize_rejects_bad(bad):
    with pytest.raises(ab.ApiBaseError):
        ab.normalize_api_base(bad)


def test_absolute_url_unchanged():
    u = "https://other.example.test/api/x?id=1"
    assert ab.resolve_api_url(u, API, FRONT) == u


def test_relative_with_asset_api_base():
    base, src = ab.resolve_api_base(asset_api_base=API + "/", refresh_url="https://auth.example.test/r",
                                    target_base_url=FRONT)
    assert (base, src) == (API, ab.SOURCE_ASSET)
    assert ab.resolve_api_url("/api/admin/get-admin-details", base, FRONT) == API + "/api/admin/get-admin-details"


def test_relative_with_base_path_kept():
    assert ab.resolve_api_url("/api/x", API + "/v1", FRONT) == API + "/v1/api/x"


def test_relative_falls_back_to_refresh_origin():
    base, src = ab.resolve_api_base(asset_api_base="", refresh_url=API + "/api/auth/refresh-token",
                                    target_base_url=FRONT)
    assert (base, src) == (API, ab.SOURCE_REFRESH)
    assert ab.resolve_api_url("/api/users", base, FRONT) == API + "/api/users"


def test_refresh_origin_on_other_site_is_ignored():
    base, src = ab.resolve_api_base(asset_api_base="", refresh_url="https://tenant.idp-provider.test/oauth/token",
                                    target_base_url=FRONT)
    assert (base, src) == (FRONT, ab.SOURCE_TARGET)


def test_relative_neither_uses_frontend_target():
    base, src = ab.resolve_api_base(asset_api_base="", refresh_url="", target_base_url=FRONT)
    assert (base, src) == (FRONT, ab.SOURCE_TARGET)
    assert ab.resolve_api_url("/api/users", base, FRONT) == "https://app.example.test/api/users"


def test_invalid_asset_base_falls_through():
    base, src = ab.resolve_api_base(asset_api_base="ftp://x", refresh_url="", target_base_url=FRONT)
    assert src == ab.SOURCE_TARGET


def _ctx(asset_base="", refresh_origin=""):
    auth = SessionAuth(profile_id=1, status="ready", headers={"Authorization": "Bearer T"},
                       refresh_origin=refresh_origin)
    return SimpleNamespace(
        target_base_url=FRONT,
        extra={
            "_session_auth": auth,
            "_capture_urls": [FRONT, "https://app.example.test/api/me", "https://app.example.test/project",
                              "https://app.example.test/admin"],
            "_capture_api_urls": ["https://app.example.test/api/me"],
        },
    ), SimpleNamespace(api_base_url=asset_base)


def test_apply_rebases_api_urls_only_pages_stay_on_frontend():
    ctx, asset = _ctx(asset_base=API)
    info = ab.apply_to_ctx(ctx, asset=asset)
    assert info == {"url": API, "source": "asset"}
    assert ctx.extra["_capture_api_urls"] == [API + "/api/me"]
    # T01/T02 page URLs are not rewritten
    assert ctx.extra["_capture_urls"] == [FRONT, API + "/api/me", "https://app.example.test/project",
                                          "https://app.example.test/admin"]


def test_apply_uses_refresh_origin_and_sends_auth_there():
    ctx, asset = _ctx(refresh_origin=API)
    ab.apply_to_ctx(ctx, asset=asset)
    auth = ctx.extra["_session_auth"]
    assert ctx.extra["_api_base_url"] == API
    assert auth.headers_for(API + "/api/me", FRONT) == {"Authorization": "Bearer T"}
    assert auth.headers_for(FRONT + "project", FRONT) == {"Authorization": "Bearer T"}
    assert auth.headers_for("https://evil.test/api/me", FRONT) == {}


def test_apply_no_base_no_refresh_unchanged():
    ctx, asset = _ctx()
    before = dict(ctx.extra)
    info = ab.apply_to_ctx(ctx, asset=asset)
    assert info["source"] == "target"
    assert ctx.extra["_capture_urls"] == before["_capture_urls"]
    assert ctx.extra["_capture_api_urls"] == before["_capture_api_urls"]
    assert ctx.extra["_session_auth"].extra_origins == ()


def test_rebase_leaves_other_origins():
    assert ab.rebase_to_api("https://cdn.example.test/a.js", FRONT, API) == "https://cdn.example.test/a.js"
    assert ab.rebase_to_api("https://app.example.test/api/x?a=1", FRONT, API) == API + "/api/x?a=1"


def test_replay_checks_and_probe_urls_use_api_root():
    ep = jsd.ApiEndpoint.from_dict({"path": "/api/admin/get-admin-details", "capture_safe": True})
    ctx = SimpleNamespace(target_base_url=FRONT, extra={"_api_base_url": API,
                                                        "_js_api": {"endpoints_list": [ep.to_dict()]}})
    assert rc._abs(rc._api_root(ctx), ep.path) == API + "/api/admin/get-admin-details"
    urls = probe_urls(FRONT, {"ctx": ctx}, api=True)
    assert urls == [API + "/api/admin/get-admin-details"]
    # without a resolved base: unchanged frontend behaviour
    ctx2 = SimpleNamespace(target_base_url=FRONT, extra={"_js_api": {"endpoints_list": [ep.to_dict()]}})
    assert probe_urls(FRONT, {"ctx": ctx2}, api=True) == ["https://app.example.test/api/admin/get-admin-details"]
