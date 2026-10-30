"""Generic per-profile ENCRYPTED Extra Cookies: parsing/validation and injection everywhere
the session is applied (verify / ZAP / Nuclei / form login), plus redaction."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
import yaml

from attestra.auth_web import extra_cookies as xc
from attestra.auth_web import scan_auth

# ------------------------------------------------------------------ parsing


def test_parse_semicolons_lines_and_cookie_prefix():
    text = "Cookie: refreshToken=abc.def; cf_clearance=x-1\n\n# note\nb=2"
    assert xc.parse_extra_cookies(text) == [("refreshToken", "abc.def"), ("cf_clearance", "x-1"), ("b", "2")]
    assert xc.normalize_extra_cookies(" a = 1 ;; b=2 ") == "a=1; b=2"


def test_value_may_contain_equals():
    assert xc.parse_extra_cookies("t=YWJj==") == [("t", "YWJj==")]


def test_empty_is_empty():
    assert xc.parse_extra_cookies("") == [] and xc.parse_extra_cookies(None) == []


@pytest.mark.parametrize("text", ["novalue", "=v", "bad name=v", "x(y)=v", "a=", "a=v\x00w", "a=v\x7f", "a=1; a=2"])
def test_invalid_rejected(text):
    with pytest.raises(xc.ExtraCookiesError):
        xc.parse_extra_cookies(text)


def test_cr_lf_and_semicolon_are_separators_never_in_values():
    for _, v in xc.parse_extra_cookies("a=1\rb=2\nc=3;d=4"):
        assert not any(c in v for c in "\r\n;")


def test_max_ten():
    ok = "; ".join(f"c{i}=v" for i in range(10))
    assert len(xc.parse_extra_cookies(ok)) == 10
    with pytest.raises(xc.ExtraCookiesError):
        xc.parse_extra_cookies(ok + "; c10=v")


def test_error_messages_never_echo_values():
    with pytest.raises(xc.ExtraCookiesError) as ei:
        xc.parse_extra_cookies("tok=SUPERSECRETVALUE\x01")
    assert "SUPERSECRETVALUE" not in str(ei.value)


def test_merge_session_cookie_wins():
    assert xc.merge_cookies({"session": "S"}, [("session", "no"), ("refreshToken", "R")]) == {
        "session": "S", "refreshToken": "R",
    }


# --------------------------------------------------------- prepare_for_run wiring

SECRETS = {"ref-1": "TOKENVALUE123", "xc-ref": "refreshToken=REFRESHSECRET456; other=OTHERVAL789"}


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
        extra_headers="", extra_cookies_ref="xc-ref", extra_cookie_names="refreshToken, other",
    )
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture
def secrets(monkeypatch):
    from attestra import credentials

    monkeypatch.setattr(credentials, "get_secret", lambda ref: SECRETS[ref])


def _run():
    return SimpleNamespace(id=99, engagement_id=1, auth_profile_id=7)


def _prep(profile, tmp_path, tool="zap", probe=None):
    return scan_auth.prepare_for_run(
        _FakeSession(profile), _run(), tmp_path / "raw", tool=tool, target_url="https://api.example.com/",
        login_probe=probe or (lambda u, h: (200, "{}")), secret_dir=tmp_path / "sec",
    )


def test_header_profile_sends_bearer_and_cookie_on_verify_and_zap(tmp_path, secrets):
    seen = {}
    plan = _prep(_profile(), tmp_path, probe=lambda u, h: (seen.update(h), (200, "{}"))[1])
    assert seen["Authorization"] == "Bearer TOKENVALUE123"
    assert seen["Cookie"] == "refreshToken=REFRESHSECRET456; other=OTHERVAL789"
    data = json.loads(open(plan.zap_auth_opts["headers_file"]).read())
    assert data["headers"]["Cookie"] == "refreshToken=REFRESHSECRET456; other=OTHERVAL789"
    assert data["headers"]["Authorization"] == "Bearer TOKENVALUE123"
    assert data["url_regex"]  # target host only
    assert "Cookie" in plan.injected_names
    for v in ("TOKENVALUE123", "REFRESHSECRET456", "OTHERVAL789"):
        assert v in plan.redact_values
    assert "REFRESHSECRET456" not in repr(plan)


def test_nuclei_authx_header_list_carries_single_cookie_header(tmp_path, secrets):
    plan = _prep(_profile(), tmp_path, tool="nuclei")
    entry = yaml.safe_load(open(plan.nuclei_secret_file))["static"][0]
    assert {"key": "Cookie", "value": "refreshToken=REFRESHSECRET456; other=OTHERVAL789"} in entry["headers"]
    assert {"key": "Authorization", "value": "Bearer TOKENVALUE123"} in entry["headers"]
    assert [h["key"] for h in entry["headers"]].count("Cookie") == 1
    assert entry["domains"] == ["api.example.com"]
    assert set(plan.nuclei_kwargs()["redact_values"]) >= {"REFRESHSECRET456", "OTHERVAL789"}


def test_cookie_profile_merges_into_one_cookie_header_session_wins(tmp_path, secrets, monkeypatch):
    SECRETS2 = dict(SECRETS, **{"ref-1": "sid=SESSIONVAL; refreshToken=FROMSESSION"})
    from attestra import credentials

    monkeypatch.setattr(credentials, "get_secret", lambda ref: SECRETS2[ref])
    seen = {}
    _prep(_profile(method="cookie"), tmp_path, probe=lambda u, h: (seen.update(h), (200, "{}"))[1])
    assert seen["Cookie"] == "sid=SESSIONVAL; refreshToken=FROMSESSION; other=OTHERVAL789"
    assert "Authorization" not in seen


def test_no_extra_cookies_unchanged(tmp_path, secrets):
    seen = {}
    _prep(_profile(extra_cookies_ref=""), tmp_path, probe=lambda u, h: (seen.update(h), (200, "{}"))[1])
    assert "Cookie" not in seen and seen["Authorization"] == "Bearer TOKENVALUE123"


def test_undecryptable_extra_cookies_fail_clearly(tmp_path, monkeypatch):
    from attestra import credentials

    def _get(ref):
        if ref == "xc-ref":
            raise credentials.SecretsError("secret not found")
        return "TOKENVALUE123"

    monkeypatch.setattr(credentials, "get_secret", _get)
    with pytest.raises(scan_auth.ScanAuthError) as ei:
        _prep(_profile(), tmp_path)
    assert "extra cookies" in str(ei.value)


def test_verify_failure_never_leaks_cookie(tmp_path, secrets):
    with pytest.raises(scan_auth.ScanAuthError) as ei:
        _prep(_profile(), tmp_path, probe=lambda u, h: (401, json.dumps({"code": "SESSION_EXPIRED"})))
    assert str(ei.value) == "login check got HTTP 401 (SESSION_EXPIRED)"
    assert "REFRESHSECRET456" not in str(ei.value)


def test_redact_text_masks_extra_cookie_values_in_logs(tmp_path, secrets):
    from attestra.runner.scanners.base import redact_text

    plan = _prep(_profile(), tmp_path)
    log = "nuclei: GET /x refreshToken REFRESHSECRET456 and OTHERVAL789"
    out = redact_text(log, plan.redact_values)
    assert "REFRESHSECRET456" not in out and "OTHERVAL789" not in out


def test_secret_dir_cleanup_removes_cookie_files(tmp_path, secrets):
    plan = _prep(_profile(), tmp_path)
    sdir = plan.secret_dir
    assert sdir and "REFRESHSECRET456" in open(plan.zap_auth_opts["headers_file"]).read()
    assert plan.cleanup()
    import os

    assert not os.path.exists(sdir)
    assert not list((tmp_path / "raw").glob("**/*")) if (tmp_path / "raw").exists() else True


def test_live_http_post_adds_extra_cookies_flow_cookie_wins(monkeypatch):
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
    post = scan_auth.live_http_post(
        {"app.example.com"}, extra_cookies=[("refreshToken", "R1"), ("csrf", "from-extra")]
    )
    post("https://app.example.com/login", {"u": "1"}, {"csrf": "from-flow"})
    assert captured["cookie"] == "csrf=from-flow; refreshToken=R1"
