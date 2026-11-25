"""Form login on token apps (JSON body + JWT in the reply, no cookie), e.g. OWASP Juice Shop.

The cookie path must behave exactly as before; a token-only reply becomes header auth
(``Authorization: Bearer <token>``) for ZAP / Nuclei / automated tests and mid-scan re-login.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from attestra.auth_web import otp as otp_mod
from attestra.auth_web import scan_auth
from attestra.auth_web import session_guard as sg

JUICE_CFG = {
    "login_url": "http://shop.test/rest/user/login",
    "username": "admin@juice-sh.op",
    "login_body_format": "json",
    "token_json_path": "authentication.token",
    "verify_url": "http://shop.test/rest/user/whoami",
}


def _juice_reply(token: str) -> str:
    return json.dumps({"authentication": {"token": token, "bid": 1, "umail": "admin@juice-sh.op"}})


# ------------------------------------------------------------- JSON login -> Bearer


def test_json_login_token_becomes_bearer_header():
    calls = []

    def http_post(url, data, cookies, *, json_body=False):
        calls.append((url, dict(data), json_body))
        return otp_mod.HttpReply(status=200, body=_juice_reply("eyJhbGciOi.tok.sig"), cookies={})

    headers, cookies, note = scan_auth.session_material("form", JUICE_CFG, "pw", http_post=http_post)
    assert headers == {"Authorization": "Bearer eyJhbGciOi.tok.sig"}
    assert cookies == {}
    assert "token" in note and "eyJ" not in note  # never leaks the token
    url, data, json_body = calls[0]
    assert json_body is True
    assert data == {"email": "admin@juice-sh.op", "password": "pw"}  # JSON defaults


def test_token_auto_detect_and_custom_header_prefix():
    def http_post(url, data, cookies, *, json_body=False):
        return otp_mod.HttpReply(status=200, body=json.dumps({"data": {"token": "T1"}}))

    cfg = {**JUICE_CFG, "token_json_path": "", "token_header_name": "X-Auth", "token_prefix": ""}
    headers, cookies, _ = scan_auth.session_material("form", cfg, "pw", http_post=http_post)
    assert headers == {"X-Auth": "T1"} and cookies == {}

    for key in ("token", "access_token", "accessToken", "jwt", "id_token"):
        assert scan_auth.extract_login_token(json.dumps({key: "V"})) == "V"
    assert scan_auth.extract_login_token("<html>no</html>") == ""


def test_json_field_names_from_config():
    seen = {}

    def http_post(url, data, cookies, *, json_body=False):
        seen.update(data)
        return otp_mod.HttpReply(status=200, body=_juice_reply("T"))

    cfg = {**JUICE_CFG, "json_username_field": "login", "json_password_field": "pass"}
    scan_auth.session_material("form", cfg, "pw", http_post=http_post)
    assert seen == {"login": "admin@juice-sh.op", "pass": "pw"}


def test_form_body_reply_with_token_and_no_cookie_also_works():
    """Token pickup is not limited to JSON bodies: a urlencoded login can return a JWT too."""

    def http_post(url, data, cookies):  # legacy 3-arg transport: no json_body kwarg used
        return otp_mod.HttpReply(status=200, body=json.dumps({"access_token": "A"}))

    cfg = {"login_url": "https://app/login", "username": "u"}
    headers, cookies, _ = scan_auth.session_material("form", cfg, "pw", http_post=http_post)
    assert headers == {"Authorization": "Bearer A"} and cookies == {}


# ------------------------------------------------------------- cookie path unchanged


def test_cookie_path_unchanged():
    posts = []

    def http_post(url, data, cookies):  # 3-arg fake: legacy call signature must still work
        posts.append((url, dict(data)))
        return otp_mod.HttpReply(status=200, body=json.dumps({"token": "ignored"}), cookies={"JSESSIONID": "ABC"})

    cfg = {"login_url": "https://app/login", "username": "u"}
    headers, cookies, note = scan_auth.session_material("form", cfg, "pw", http_post=http_post)
    assert headers == {}
    assert cookies == {"JSESSIONID": "ABC"}
    assert note == "form login ok"
    assert posts == [("https://app/login", {"username": "u", "password": "pw"})]


def test_cookie_plus_explicit_token_path_adds_header():
    def http_post(url, data, cookies, *, json_body=False):
        return otp_mod.HttpReply(status=200, body=_juice_reply("TK"), cookies={"lang": "en"})

    headers, cookies, _ = scan_auth.session_material("form", JUICE_CFG, "pw", http_post=http_post)
    assert headers == {"Authorization": "Bearer TK"} and cookies == {"lang": "en"}


# ------------------------------------------------------------- neither -> failure


def test_no_cookie_no_token_fails():
    def http_post(url, data, cookies, **kw):
        return otp_mod.HttpReply(status=200, body=json.dumps({"status": "ok"}), cookies={})

    with pytest.raises(scan_auth.ScanAuthError, match="no session cookie was set"):
        scan_auth.session_material(
            "form", {"login_url": "https://a", "username": "u"}, "pw", http_post=http_post
        )
    with pytest.raises(scan_auth.ScanAuthError, match="no token was found at token_json_path"):
        scan_auth.session_material("form", JUICE_CFG, "pw", http_post=http_post)


def test_http_error_still_fails_before_token_lookup():
    def http_post(url, data, cookies, **kw):
        return otp_mod.HttpReply(status=401, body=_juice_reply("T"))

    with pytest.raises(scan_auth.ScanAuthError, match="HTTP 401"):
        scan_auth.session_material("form", JUICE_CFG, "pw", http_post=http_post)


# ------------------------------------------------------------- live transport (fake server)


class _JuiceHandler(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8")
        type(self).received.append((self.headers.get("Content-Type"), raw))
        try:
            data = json.loads(raw)
        except ValueError:
            data = {}
        if data.get("email") == "admin@juice-sh.op" and data.get("password") == "pw":
            body, code = _juice_reply("eyJlive.tok.sig").encode(), 200
        else:
            body, code = b"Invalid email or password.", 401
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # keep test output quiet
        pass


@pytest.fixture()
def juice_server():
    _JuiceHandler.received = []
    srv = HTTPServer(("127.0.0.1", 0), _JuiceHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_live_http_post_sends_json_and_returns_bearer(juice_server):
    post = scan_auth.live_http_post({"127.0.0.1"})
    cfg = {**JUICE_CFG, "login_url": f"{juice_server}/rest/user/login"}
    headers, cookies, _ = scan_auth.session_material("form", cfg, "pw", http_post=post)
    assert headers == {"Authorization": "Bearer eyJlive.tok.sig"} and cookies == {}
    ctype, raw = _JuiceHandler.received[0]
    assert ctype == "application/json"
    assert json.loads(raw) == {"email": "admin@juice-sh.op", "password": "pw"}


def test_live_http_post_form_body_unchanged(juice_server):
    post = scan_auth.live_http_post({"127.0.0.1"})
    reply = post(f"{juice_server}/login", {"username": "u", "password": "p"}, {})
    ctype, raw = _JuiceHandler.received[0]
    assert ctype == "application/x-www-form-urlencoded"
    assert raw == "username=u&password=p"
    assert reply.status == 401


# ------------------------------------------------------------- consumers + re-login


def test_token_session_reaches_zap_and_nuclei_files(tmp_path):
    headers = scan_auth.token_header({}, "TOKVALUE")
    hook = json.loads(open(scan_auth.write_zap_hook(tmp_path, headers, {}, target_url="http://h:3000"), encoding="utf-8").read())
    assert hook["headers"] == {"Authorization": "Bearer TOKVALUE"}
    import yaml

    doc = yaml.safe_load(open(scan_auth.write_nuclei_secret_file(tmp_path, "http://h:3000", headers, {}), encoding="utf-8").read())
    assert doc["static"][0]["headers"] == [{"key": "Authorization", "value": "Bearer TOKVALUE"}]
    # Redaction covers the bare token too.
    assert "TOKVALUE" in scan_auth._redaction_values("pw", headers, {})


def test_midscan_relogin_gets_fresh_token_and_respects_budget():
    tokens = iter(["T0", "T1", "T2", "T3"])

    def http_post(url, data, cookies, *, json_body=False):
        return otp_mod.HttpReply(status=200, body=_juice_reply(next(tokens)))

    live = {"tok": "T0"}

    def probe(url, headers):
        return (200, "{}") if headers.get("Authorization") == f"Bearer {live['tok']}" else (401, "")

    headers, cookies, _ = scan_auth.session_material("form", JUICE_CFG, "pw", http_post=http_post)
    assert headers["Authorization"] == "Bearer T0"
    renewed = []
    guard = sg.build_guard(
        method="form", cfg=JUICE_CFG, secret="pw", headers=headers, cookies=cookies,
        http_post=http_post, login_probe=probe, enabled=True, max_relogins=1,
    )
    guard.min_interval_s = 0
    guard.on_renew.append(lambda m: renewed.append(dict(m.headers)))
    live["tok"] = "T1"  # server-side expiry: old token no longer accepted
    ok, _ = guard.check_and_recover()
    assert ok and guard.relogins == 1
    assert guard.headers["Authorization"] == "Bearer T1"
    assert renewed == [{"Authorization": "Bearer T1"}]
    live["tok"] = "never"  # budget (ATTESTRA_AUTH_RELOGIN_MAX=1) is now spent
    ok, _ = guard.check_and_recover()
    assert not ok and guard.lost


# ------------------------------------------------------------- config validation


def test_sanitize_login_token_config():
    out = scan_auth.sanitize_login_token_config(
        {"login_body_format": "JSON", "token_json_path": "$.authentication.token", "token_prefix": "bearer",
         "token_header_name": "Authorization", "json_username_field": ""}
    )
    assert out["login_body_format"] == "json"
    assert out["token_json_path"] == "authentication.token"
    assert out["token_prefix"] == "Bearer "
    assert "json_username_field" not in out
    assert scan_auth.sanitize_login_token_config({"token_prefix": "none"})["token_prefix"] == ""
    assert scan_auth.sanitize_login_token_config({"token_prefix": "Token"})["token_prefix"] == "Token "
    for bad in (
        {"login_body_format": "xml"},
        {"token_json_path": "a..b"},
        {"token_header_name": "Cookie"},
        {"token_header_name": "Bad Header"},
        {"token_prefix": "Bearer\r\nX: y"},
        {"json_username_field": "#email input"},
    ):
        with pytest.raises(ValueError):
            scan_auth.sanitize_login_token_config(bad)
    # Legacy configs pass through untouched.
    legacy = {"login_url": "https://a", "username": "u", "username_field": "user"}
    assert scan_auth.sanitize_login_token_config(legacy) == legacy


def test_profile_service_validates_new_keys():
    from attestra import services
    from attestra.auth_web import profiles

    assert profiles._sanitize_profile_config({"login_body_format": "json"})["login_body_format"] == "json"
    with pytest.raises(services.ServiceError):
        profiles._sanitize_profile_config({"login_body_format": "xml"})


def test_api_model_merges_top_level_fields_into_config():
    from attestra.auth_web import routes

    body = routes.ProfileCreateIn(label="x", login_body_format="json", token_json_path="authentication.token",
                                  config={"username": "u"})
    cfg = routes._config_with_login_token_fields(body)
    assert cfg == {"username": "u", "login_body_format": "json", "token_json_path": "authentication.token"}
    assert routes._config_with_login_token_fields(routes.ProfileCreateIn(label="x")) is None
