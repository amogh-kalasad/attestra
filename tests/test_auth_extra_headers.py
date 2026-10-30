"""Generic per-profile Extra Headers: parsing, validation, injection everywhere the
session is applied (verify / ZAP / Nuclei / form login), and clearer verify errors."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
import yaml

from attestra.auth_web import extra_headers as xh
from attestra.auth_web import scan_auth

# ------------------------------------------------------------------ parsing


def test_parse_basic_lines_comments_and_blanks():
    text = "x-portal-host: stage.example.com\n\n# a comment\r\nX-Tenant-Id:abc  \n"
    assert xh.parse_extra_headers(text) == [("x-portal-host", "stage.example.com"), ("X-Tenant-Id", "abc")]


def test_value_may_contain_colons():
    assert xh.parse_extra_headers("X-Ref: https://a.example.com:8443/x") == [
        ("X-Ref", "https://a.example.com:8443/x")
    ]


def test_empty_is_empty():
    assert xh.parse_extra_headers("") == []
    assert xh.parse_extra_headers(None) == []
    assert xh.normalize_extra_headers("  a-b :  c ") == "a-b: c"


@pytest.mark.parametrize(
    "text",
    [
        "no colon here",
        ": value",
        "bad name: v",
        "x(y): v",
        "x\u00e9: v",
        "X-A: v\x00w",
        "X-A: v\x07",
    ],
)
def test_invalid_lines_rejected(text):
    with pytest.raises(xh.ExtraHeadersError):
        xh.parse_extra_headers(text)


def test_cr_cannot_smuggle_a_header():
    # A bare CR splits into its own line, which is then validated separately.
    out = xh.parse_extra_headers("X-A: v\rX-B: w")
    assert out == [("X-A", "v"), ("X-B", "w")]
    for _, v in out:
        assert "\r" not in v and "\n" not in v


@pytest.mark.parametrize("name", ["Authorization", "cookie", "HOST", "Content-Length", "Proxy-Authorization"])
def test_forbidden_names(name):
    with pytest.raises(xh.ExtraHeadersError) as ei:
        xh.parse_extra_headers(f"{name}: x")
    assert "not allowed" in str(ei.value)


def test_own_header_name_rejected_and_duplicates():
    with pytest.raises(xh.ExtraHeadersError):
        xh.parse_extra_headers("X-Api-Key: 1", own_header_name="x-api-key")
    with pytest.raises(xh.ExtraHeadersError):
        xh.parse_extra_headers("X-A: 1\nx-a: 2")


def test_max_ten_lines():
    ok = "\n".join(f"X-H{i}: v" for i in range(10))
    assert len(xh.parse_extra_headers(ok)) == 10
    with pytest.raises(xh.ExtraHeadersError):
        xh.parse_extra_headers(ok + "\nX-H10: v")


def test_error_messages_never_echo_values():
    with pytest.raises(xh.ExtraHeadersError) as ei:
        xh.parse_extra_headers("X-A: SUPERSECRETVALUE\x01")
    assert "SUPERSECRETVALUE" not in str(ei.value)


def test_merge_session_header_wins():
    merged = xh.merge_extra_headers({"Authorization": "Bearer T"}, [("authorization", "nope"), ("X-P", "h")])
    assert merged == {"Authorization": "Bearer T", "X-P": "h"}


def test_own_header_name_helper():
    assert xh.own_header_name("header", {}) == "Authorization"
    assert xh.own_header_name("header", {"header_name": "X-Key"}) == "X-Key"
    assert xh.own_header_name("cookie", {"header_name": "X-Key"}) is None


# ------------------------------------------------------------ verify error detail


@pytest.mark.parametrize(
    "body,expect",
    [
        (json.dumps({"success": False, "code": "SESSION_EXPIRED", "message": "Session expired."}), "SESSION_EXPIRED"),
        (json.dumps({"message": "Session expired. Please login again."}), "Session expired. Please login again."),
        (json.dumps({"error": {"code": "TOKEN_INVALID"}}), "TOKEN_INVALID"),
        (json.dumps({"error": "invalid_token"}), "invalid_token"),
        ("<html>Unauthorized</html>", ""),
        ("", ""),
        (json.dumps([1, 2]), ""),
    ],
)
def test_server_error_detail(body, expect):
    assert scan_auth.server_error_detail(body) == expect


def test_server_error_detail_redacts_and_truncates():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEyMyJ9.c2lnbmF0dXJlc2lnbmF0dXJl"
    d = scan_auth.server_error_detail(json.dumps({"message": f"bad token {jwt} for Bearer abc.def"}))
    assert "eyJ" not in d and "abc.def" not in d and "[redacted]" in d
    long = scan_auth.server_error_detail(json.dumps({"message": "word " * 60}))
    assert len(long) <= 80 and long.endswith("...")
    opaque = scan_auth.server_error_detail(json.dumps({"message": "sess " + "a1B2" * 10}))
    assert "a1B2a1B2" not in opaque


def test_verify_401_message_includes_server_code():
    cfg = {"verify_url": "https://api.example.com/me"}
    body = json.dumps({"code": "SESSION_EXPIRED", "message": "Session expired. Please login again."})
    ok, note = scan_auth.verify_logged_in(cfg, {"Authorization": "Bearer T"}, {}, login_probe=lambda u, h: (401, body))
    assert ok is False
    assert note == "login check got HTTP 401 (SESSION_EXPIRED)"


def test_verify_401_without_json_keeps_old_message():
    ok, note = scan_auth.verify_logged_in(
        {"verify_url": "https://a/x"}, {}, {}, login_probe=lambda u, h: (401, "<html/>")
    )
    assert ok is False and note == "login check got HTTP 401 (not authenticated)"


# --------------------------------------------------------- prepare_for_run wiring


class _FakeSession:
    def __init__(self, profile):
        self._p = profile

    def get(self, _model, pid):
        return self._p if pid == self._p.id else None


def _profile(**kw):
    base = dict(
        id=7, engagement_id=1, status="valid", method="header", label="p", role_name="",
        secret_ref="ref-1", login_url="", username_selector="", password_selector="",
        submit_selector="", success_url_contains="",
        config_json={"verify_url": "https://api.example.com/me"},
        extra_headers="x-portal-host: stage.example.com\nX-Tenant-Id: t1",
    )
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture
def secret(monkeypatch):
    from attestra import credentials

    monkeypatch.setattr(credentials, "get_secret", lambda ref: "TOKENVALUE123")


def _run():
    return SimpleNamespace(id=99, engagement_id=1, auth_profile_id=7)


def test_prepare_injects_extra_headers_in_verify_and_zap(tmp_path, secret):
    seen = {}

    def probe(url, headers):
        seen.update(headers)
        return 200, "{}"

    plan = scan_auth.prepare_for_run(
        _FakeSession(_profile()), _run(), tmp_path / "raw", tool="zap",
        target_url="https://api.example.com/", login_probe=probe, secret_dir=tmp_path / "sec",
    )
    assert seen["x-portal-host"] == "stage.example.com"
    assert seen["X-Tenant-Id"] == "t1"
    assert seen["Authorization"] == "Bearer TOKENVALUE123"
    data = json.loads(open(plan.zap_auth_opts["headers_file"]).read())
    assert data["headers"]["x-portal-host"] == "stage.example.com"
    assert data["headers"]["Authorization"] == "Bearer TOKENVALUE123"
    assert data["url_regex"]  # scoped to the target host only
    assert "x-portal-host" in plan.injected_names
    # Non-secret extras are not in the redaction list (session token is).
    assert "stage.example.com" not in plan.redact_values
    assert "TOKENVALUE123" in plan.redact_values


def test_prepare_injects_extra_headers_in_nuclei_authx_list(tmp_path, secret):
    plan = scan_auth.prepare_for_run(
        _FakeSession(_profile()), _run(), tmp_path / "raw", tool="nuclei",
        target_url="https://api.example.com/", login_probe=lambda u, h: (200, "{}"), secret_dir=tmp_path / "sec",
    )
    entry = yaml.safe_load(open(plan.nuclei_secret_file))["static"][0]
    assert isinstance(entry["headers"], list)
    assert {"key": "x-portal-host", "value": "stage.example.com"} in entry["headers"]
    assert {"key": "Authorization", "value": "Bearer TOKENVALUE123"} in entry["headers"]
    assert entry["domains"] == ["api.example.com"]


def test_prepare_without_extra_headers_unchanged(tmp_path, secret):
    seen = {}
    scan_auth.prepare_for_run(
        _FakeSession(_profile(extra_headers="")), _run(), tmp_path / "raw", tool="zap",
        target_url="https://api.example.com/",
        login_probe=lambda u, h: (seen.update(h), (200, "{}"))[1], secret_dir=tmp_path / "sec",
    )
    assert "x-portal-host" not in seen and seen["Authorization"] == "Bearer TOKENVALUE123"


def test_prepare_invalid_stored_extra_headers_fails_clearly(tmp_path, secret):
    with pytest.raises(scan_auth.ScanAuthError) as ei:
        scan_auth.prepare_for_run(
            _FakeSession(_profile(extra_headers="Cookie: x=1")), _run(), tmp_path / "raw", tool="zap",
            target_url="https://api.example.com/", login_probe=lambda u, h: (200, "{}"),
            secret_dir=tmp_path / "sec",
        )
    assert "extra headers" in str(ei.value)


def test_prepare_verify_failure_reports_server_code(tmp_path, secret):
    body = json.dumps({"code": "SESSION_EXPIRED"})
    with pytest.raises(scan_auth.ScanAuthError) as ei:
        scan_auth.prepare_for_run(
            _FakeSession(_profile()), _run(), tmp_path / "raw", tool="zap",
            target_url="https://api.example.com/", login_probe=lambda u, h: (401, body),
            secret_dir=tmp_path / "sec",
        )
    assert str(ei.value) == "login check got HTTP 401 (SESSION_EXPIRED)"
    assert "TOKENVALUE123" not in str(ei.value)


def test_live_http_post_adds_extra_headers(monkeypatch):
    import urllib.request

    captured = {}

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b""

        def geturl(self):
            return "https://app.example.com/login"

    class _Opener:
        def open(self, req, timeout=None):
            captured.update({k.lower(): v for k, v in req.header_items()})
            return _Resp()

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _Opener())
    post = scan_auth.live_http_post({"app.example.com"}, extra_headers=[("X-Tenant-Id", "t1"), ("User-Agent", "evil")])
    post("https://app.example.com/login", {"u": "1"}, {})
    assert captured["x-tenant-id"] == "t1"
    assert captured["user-agent"].startswith("attestra-auth-web")  # client header wins
