"""JSON / cookie mid-scan session refresh (header and cookie auth profiles)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from attestra.auth_web import otp as otp_mod
from attestra.auth_web import scan_auth as sa
from attestra.auth_web import session_guard as sg


def _probe_ok(url, headers):
    return 200, '{"ok":true}'


def _http_request_factory(replies, calls):
    def _request(url, *, method="POST", body=b"", headers=None, cookies=None):
        calls.append(
            {
                "url": url,
                "method": method,
                "body": body,
                "headers": dict(headers or {}),
                "cookies": dict(cookies or {}),
            }
        )
        item = replies.pop(0)
        if callable(item):
            return item()
        return item

    return _request


def _harmony_cfg(**extra):
    cfg = {
        "header_name": "Authorization",
        "verify_url": "https://app.example.com/api/me",
        "refresh_url": "https://api.example.com/api/auth/refresh-token",
        "refresh_method": "POST",
        "refresh_body": {},
        "refresh_content_type": "json",
        "refresh_cookies": ["refreshToken"],
        "refresh_headers": {
            "Origin": "https://app.example.com",
            "Referer": "https://app.example.com/",
            "User-Agent": "Mozilla/5.0",
            "x-portal-host": "app.example.com",
        },
        "refresh_token_json_path": "accessToken",
        "refresh_apply_as": "bearer",
    }
    cfg.update(extra)
    return cfg


def test_json_refresh_replaces_authorization_and_rotates_cookie():
    calls: list[dict] = []
    replies = [
        otp_mod.HttpReply(
            status=200,
            body=json.dumps(
                {
                    "accessToken": "NEW_ACCESS_TOKEN_AAA",
                    "user": {"email": "hidden@example.com", "roles": ["admin"], "profile": "x" * 200},
                }
            ),
            cookies={"refreshToken": "ROTATED_REFRESH_BBB"},
            headers={"content-type": "application/json"},
        ),
        otp_mod.HttpReply(
            status=200,
            body=json.dumps({"accessToken": "NEWER_ACCESS_TOKEN_CCC"}),
            cookies={"refreshToken": "ROTATED_REFRESH_CCC"},
            headers={"content-type": "application/json"},
        ),
    ]

    def probe(url, headers):
        auth = headers.get("Authorization") or headers.get("authorization") or ""
        if auth in ("Bearer NEW_ACCESS_TOKEN_AAA", "Bearer NEWER_ACCESS_TOKEN_CCC"):
            return 200, '{"ok":true}'
        return 401, ""

    cfg = _harmony_cfg()
    mat = sg.attempt_relogin(
        "header",
        cfg,
        "OLD_ACCESS_TOKEN_ZZZ",
        http_post=None,
        http_request=_http_request_factory(replies, calls),
        login_probe=probe,
        extra_cookies=[("refreshToken", "REFRESH_TOKEN_V1")],
        current_cookies={"sid": "keep", "refreshToken": "REFRESH_TOKEN_V1"},
        failure_note={},
    )
    assert mat is not None
    auth_keys = [k for k in mat.headers if k.lower() == "authorization"]
    assert auth_keys == ["Authorization"]
    assert mat.headers["Authorization"] == "Bearer NEW_ACCESS_TOKEN_AAA"
    assert mat.headers["Authorization"].count("Bearer ") == 1
    assert "OLD_ACCESS_TOKEN_ZZZ" not in mat.headers["Authorization"]
    assert mat.cookies["refreshToken"] == "ROTATED_REFRESH_BBB"
    assert "NEW_ACCESS_TOKEN_AAA" in mat.redact_values
    assert "ROTATED_REFRESH_BBB" in mat.redact_values
    assert "session refreshed via refresh_url" in mat.note
    assert "hidden@example.com" not in mat.note
    assert "NEW_ACCESS_TOKEN_AAA" not in mat.note
    assert calls[0]["url"] == cfg["refresh_url"]
    assert calls[0]["method"] == "POST"
    assert calls[0]["cookies"]["refreshToken"] == "REFRESH_TOKEN_V1"
    assert calls[0]["headers"]["Origin"] == "https://app.example.com"
    assert calls[0]["headers"]["x-portal-host"] == "app.example.com"
    assert calls[0]["headers"]["Content-Type"] == "application/json"
    assert calls[0]["body"] == b"{}"

    mat2 = sg.attempt_relogin(
        "header",
        cfg,
        "OLD_ACCESS_TOKEN_ZZZ",
        http_post=None,
        http_request=_http_request_factory(replies, calls),
        login_probe=probe,
        extra_cookies=[("refreshToken", "REFRESH_TOKEN_V1")],
        current_cookies=mat.cookies,
        failure_note={},
    )
    assert mat2 is not None
    assert mat2.headers["Authorization"] == "Bearer NEWER_ACCESS_TOKEN_CCC"
    assert calls[1]["cookies"]["refreshToken"] == "ROTATED_REFRESH_BBB"
    assert "NEWER_ACCESS_TOKEN_CCC" in mat2.redact_values


def test_json_refresh_401_returns_none():
    fail: dict[str, str] = {}
    calls: list[dict] = []
    replies = [
        otp_mod.HttpReply(status=401, body='{"error":"invalid_grant","token":"should-not-leak"}', cookies={}, headers={})
    ]
    mat = sg.attempt_relogin(
        "header",
        _harmony_cfg(),
        "OLD_ACCESS_TOKEN_ZZZ",
        http_post=lambda *a: (_ for _ in ()).throw(AssertionError("legacy http_post must not be used")),
        http_request=_http_request_factory(replies, calls),
        login_probe=_probe_ok,
        extra_cookies=[("refreshToken", "REFRESH_TOKEN_V1")],
        current_cookies={"refreshToken": "REFRESH_TOKEN_V1"},
        failure_note=fail,
    )
    assert mat is None
    assert fail.get("note") == "refresh failed (HTTP 401)"
    assert "should-not-leak" not in fail.get("note", "")


def test_json_refresh_challenge_returns_none_with_waf_note():
    fail: dict[str, str] = {}
    replies = [
        otp_mod.HttpReply(
            status=403,
            body="<!doctype html><html><title>Just a moment...</title><body>cdn-cgi/challenge-platform</body></html>",
            cookies={},
            headers={"cf-mitigated": "challenge"},
        )
    ]
    mat = sg.attempt_relogin(
        "header",
        _harmony_cfg(),
        "OLD_ACCESS_TOKEN_ZZZ",
        http_post=None,
        http_request=_http_request_factory(replies, []),
        login_probe=_probe_ok,
        extra_cookies=[("refreshToken", "REFRESH_TOKEN_V1")],
        current_cookies={"refreshToken": "REFRESH_TOKEN_V1"},
        failure_note=fail,
    )
    assert mat is None
    assert fail.get("note") == sg.REFRESH_WAF_NOTE

    # Bounded retries then BLOCKED carry the same value-free note.
    def relogin():
        bag: dict[str, str] = {}
        result = sg.attempt_relogin(
            "header",
            _harmony_cfg(),
            "OLD_ACCESS_TOKEN_ZZZ",
            http_post=None,
            http_request=_http_request_factory(
                [
                    otp_mod.HttpReply(
                        status=403,
                        body="<title>Just a moment...</title>",
                        headers={"cf-mitigated": "challenge"},
                    )
                ],
                [],
            ),
            login_probe=_probe_ok,
            extra_cookies=[("refreshToken", "REFRESH_TOKEN_V1")],
            current_cookies={"refreshToken": "REFRESH_TOKEN_V1"},
            failure_note=bag,
        )
        guard.last_relogin_note = bag.get("note", "")
        return result

    guard = sg.SessionGuard(
        verify=lambda h, c: (False, "HTTP 401"),
        relogin=relogin,
        headers={"Authorization": "Bearer OLD_ACCESS_TOKEN_ZZZ"},
        method="header",
        max_relogins=1,
        min_interval_s=0,
    )
    assert guard.recover("HTTP 401") is False
    assert guard.lost
    assert sg.REFRESH_WAF_NOTE in guard.lost_reason
    assert "re-login failed" in guard.lost_reason


def test_legacy_cookie_refresh_url_still_works():
    refreshed = sg.attempt_relogin(
        "cookie",
        {"cookie_name": "sid", "refresh_url": "https://app.example.com/api/session/refresh"},
        "OLD",
        http_post=lambda u, d, c: otp_mod.HttpReply(
            status=200, body="", cookies={"sid": "ROTATED"}, final_url=u
        ),
        login_probe=_probe_ok,
        current_cookies={"sid": "OLD"},
    )
    assert refreshed is not None
    assert refreshed.cookies["sid"] == "ROTATED"
    assert "refresh_url" in refreshed.note

    # No refresh_url still means no renewal.
    assert (
        sg.attempt_relogin(
            "header",
            {},
            "TOKEN",
            http_post=lambda *a: otp_mod.HttpReply(status=200, cookies={"x": "y"}),
            login_probe=_probe_ok,
        )
        is None
    )


def test_sanitize_refresh_apply_as_and_secret_rejection():
    assert sg.validate_refresh_apply_as("bearer") == "bearer"
    assert sg.validate_refresh_apply_as("header:X-Auth-Token") == "header:X-Auth-Token"
    assert sg.validate_refresh_apply_as("cookie:sid") == "cookie:sid"
    with pytest.raises(ValueError, match="refresh_apply_as"):
        sg.validate_refresh_apply_as("basic")
    with pytest.raises(ValueError, match="config_json"):
        sg.sanitize_refresh_config({"refresh_token": "nope"})
    cfg = sg.sanitize_refresh_config(
        {
            "refresh_url": "https://api.example.com/api/auth/refresh-token",
            "refresh_token_json_path": "accessToken",
            "refresh_cookies": "refreshToken",
        }
    )
    assert cfg["refresh_apply_as"] == "bearer"
    assert cfg["refresh_cookies"] == ["refreshToken"]


def test_live_refresh_http_json_and_set_cookie():
    seen: dict[str, object] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            seen["body"] = self.rfile.read(length)
            seen["cookie"] = self.headers.get("Cookie")
            seen["ctype"] = self.headers.get("Content-Type")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "refreshToken=ROTATED_REFRESH_BBB; Path=/; HttpOnly")
            self.end_headers()
            self.wfile.write(b'{"accessToken":"NEW_ACCESS_TOKEN_AAA"}')

        def log_message(self, *args):  # noqa: ARG002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _host, port = server.server_address
        url = f"http://127.0.0.1:{port}/api/auth/refresh-token"
        request = sa.live_refresh_http({"127.0.0.1"})
        reply = request(
            url,
            method="POST",
            body=b"{}",
            headers={"Content-Type": "application/json", "Origin": "https://app.example.com"},
            cookies={"refreshToken": "REFRESH_TOKEN_V1"},
        )
        assert reply.status == 200
        assert reply.cookies.get("refreshToken") == "ROTATED_REFRESH_BBB"
        assert json.loads(reply.body)["accessToken"] == "NEW_ACCESS_TOKEN_AAA"
        assert seen["cookie"] == "refreshToken=REFRESH_TOKEN_V1"
        assert seen["ctype"] == "application/json"
        with pytest.raises(sa.ScanAuthError, match="not in scope"):
            request("https://evil.example.com/refresh", method="POST", body=b"{}", headers={}, cookies={})
    finally:
        server.shutdown()
        server.server_close()
