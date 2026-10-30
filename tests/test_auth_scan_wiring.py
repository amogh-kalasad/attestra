"""Per-scanner authentication wiring: session material, ZAP hook, Nuclei secret file,
pre-scan login check, and the guarantee that secrets never reach a scanner argv."""
from __future__ import annotations

import json
import stat

import os
import pytest
import yaml

from attestra.auth_web import scan_auth
from attestra.runner.authorization import assert_safe_cli_arg
from attestra.runner.scanners.nuclei import NucleiAdapter


# --------------------------------------------------------------- session material


def test_header_material_defaults_to_authorization_bearer():
    headers, cookies, note = scan_auth.session_material("header", {}, "tok123")
    assert headers == {"Authorization": "Bearer tok123"}
    assert cookies == {}


def test_header_material_respects_named_header_no_prefix():
    headers, _, _ = scan_auth.session_material("header", {"header_name": "X-Api-Key"}, "k")
    assert headers == {"X-Api-Key": "k"}


def test_cookie_material_single_and_string():
    _, cookies, _ = scan_auth.session_material("cookie", {"cookie_name": "sid"}, "abc")
    assert cookies == {"sid": "abc"}
    _, cookies2, _ = scan_auth.session_material("cookie", {}, "a=1; b=2")
    assert cookies2 == {"a": "1", "b": "2"}


def test_sso_bootstrap_blocked():
    with pytest.raises(scan_auth.ScanAuthError):
        scan_auth.session_material("sso_bootstrap", {}, "x")


def test_form_material_captures_cookie():
    posts = []

    def http_post(url, data, cookies):
        posts.append((url, data))
        return scan_auth.otp_mod.HttpReply(status=200, cookies={"JSESSIONID": "ABC"})

    cfg = {"login_url": "https://app/login", "username": "u"}
    _, cookies, _ = scan_auth.session_material("form", cfg, "pw", http_post=http_post)
    assert cookies == {"JSESSIONID": "ABC"}
    assert posts[0][1]["password"] == "pw"


def test_form_material_fails_without_cookie():
    def http_post(url, data, cookies):
        return scan_auth.otp_mod.HttpReply(status=200, cookies={})

    with pytest.raises(scan_auth.ScanAuthError):
        scan_auth.session_material("form", {"login_url": "https://a", "username": "u"}, "pw", http_post=http_post)


# ------------------------------------------------------------------- ZAP hook


def test_write_zap_hook_writes_scoped_header_data(tmp_path):
    path = scan_auth.write_zap_hook(
        tmp_path, {"Authorization": "Bearer T"}, {"sid": "S"}, target_url="https://shop.example.com/"
    )
    assert path.endswith("attestra-zap-hook-data.json")
    data = json.loads(open(path).read())
    assert data["headers"]["Authorization"] == "Bearer T"
    assert data["headers"]["Cookie"] == "sid=S"
    import re

    rx = re.compile(data["url_regex"])
    assert rx.match("https://shop.example.com/a?b=1")
    assert rx.match("https://shop.example.com:8443/")
    assert not rx.match("https://login.microsoftonline.com/x")
    assert not rx.match("https://shop.example.com.evil.net/")
    if os.name != "nt":  # NTFS can't represent POSIX 0600; chmod is honored on Linux/containers
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_single_zap_hook_installs_auth_replacer_rules():
    """ZAP accepts only ONE --hook; the crawl hook must carry the auth injection."""
    from attestra.runner.scanners import zap_crawl

    src = zap_crawl.HOOK_SOURCE
    assert "replacer.add_rule" in src and "REQ_HEADER" in src
    assert zap_crawl.ZAP_SECRETS + "/" + zap_crawl.AUTH_DATA_NAME in src
    assert "url=url_rx" in src  # scoped to the target host


# ---------------------------------------------------------------- Nuclei file


def test_write_nuclei_secret_file_is_authx_header(tmp_path):
    path = scan_auth.write_nuclei_secret_file(
        tmp_path, "https://shop.example.com/", {"Authorization": "Bearer T"}, {"sid": "S"}
    )
    doc = yaml.safe_load(open(path))
    entry = doc["static"][0]
    assert entry["type"] == "header"
    # nuclei authx v3 schema: headers is a list of {key, value} (a map makes nuclei exit [FTL])
    assert isinstance(entry["headers"], list)
    assert {"key": "Authorization", "value": "Bearer T"} in entry["headers"]
    assert {"key": "Cookie", "value": "sid=S"} in entry["headers"]
    assert entry["domains"] == ["shop.example.com"]
    if os.name != "nt":  # NTFS can't represent POSIX 0600; chmod is honored on Linux/containers
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_cookie_secret_never_reaches_nuclei_argv():
    """A cookie with ';' would be rejected by assert_safe_cli_arg; it must ride in the
    mounted secret file, so the argv stays clean and safe."""
    adapter = NucleiAdapter()
    argv = adapter.build_argv(
        "https://shop.example.com/", out_file=__import__("pathlib").Path("/tmp/o.jsonl"),
        auth_secret_file="/tmp/secrets/attestra-nuclei-auth.yaml",
    )
    assert "-sf" in argv and "/tmp/secrets/attestra-nuclei-auth.yaml" in argv
    # The session value is nowhere on argv, only the file path is.
    joined = " ".join(argv)
    assert "SECRET" not in joined
    for a in argv:
        assert_safe_cli_arg(a)  # must not raise


# ---------------------------------------------------------- pre-scan login check


def test_verify_logged_in_requires_indicator():
    cfg = {"verify_url": "https://app/account", "logged_in_indicator": "Sign out"}
    ok, _ = scan_auth.verify_logged_in(cfg, {}, {"sid": "x"}, login_probe=lambda u, h: (200, "Welcome, Sign out"))
    assert ok is True
    bad, note = scan_auth.verify_logged_in(cfg, {}, {"sid": "x"}, login_probe=lambda u, h: (200, "Please log in"))
    assert bad is False and "indicator" in note


def test_verify_logged_in_detects_401():
    cfg = {"verify_url": "https://app/account"}
    ok, note = scan_auth.verify_logged_in(cfg, {}, {}, login_probe=lambda u, h: (401, ""))
    assert ok is False and "401" in note


def test_verify_logged_in_detects_logged_out_indicator():
    cfg = {"verify_url": "https://app/x", "logged_out_indicator": "Please sign in"}
    ok, _ = scan_auth.verify_logged_in(cfg, {}, {}, login_probe=lambda u, h: (200, "Please sign in"))
    assert ok is False
