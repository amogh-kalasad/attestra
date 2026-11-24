"""Tests for AASI V5.1 native target-bound egress helpers."""
from __future__ import annotations

import pytest

from attestra.runner.authorization import AuthorizationError
from attestra.runner.dns_pin import PinnedTarget
from attestra.scanner_runtime.egress import assert_target_egress_allowed, scanner_process_env

# @lat: [[tests#AASI V5.1 native egress]]


def _pin(host: str = "llm.example.com", ip: str = "93.184.216.34") -> PinnedTarget:
    return PinnedTarget(host=host, ip=ip, port=443, scheme="https")


# --- assert_target_egress_allowed -------------------------------------------------


def test_assert_allows_public_pin():
    assert_target_egress_allowed(_pin(), allow_private=False)


def test_assert_refuses_missing_pin():
    with pytest.raises(AuthorizationError, match="pinned target missing"):
        assert_target_egress_allowed(None, allow_private=False)  # type: ignore[arg-type]


def test_assert_refuses_empty_ip():
    bad = PinnedTarget(host="llm.example.com", ip="  ", port=443, scheme="https")
    with pytest.raises(AuthorizationError, match="pinned target missing"):
        assert_target_egress_allowed(bad, allow_private=False)


def test_assert_refuses_empty_host():
    bad = PinnedTarget(host="", ip="93.184.216.34", port=443, scheme="https")
    with pytest.raises(AuthorizationError, match="pinned target missing"):
        assert_target_egress_allowed(bad, allow_private=False)


def test_assert_blocks_cloud_metadata_ip():
    meta = _pin(ip="169.254.169.254")
    with pytest.raises(AuthorizationError, match="blocked IP"):
        assert_target_egress_allowed(meta, allow_private=False)


def test_assert_blocks_metadata_even_when_private_allowed():
    meta = _pin(ip="169.254.169.254")
    with pytest.raises(AuthorizationError, match="blocked IP"):
        assert_target_egress_allowed(meta, allow_private=True)


def test_assert_blocks_cgnat():
    with pytest.raises(AuthorizationError, match="blocked IP"):
        assert_target_egress_allowed(_pin(ip="100.64.0.1"), allow_private=True)


def test_assert_blocks_private_when_not_allowed():
    with pytest.raises(AuthorizationError, match="non-global"):
        assert_target_egress_allowed(_pin(ip="10.0.0.5"), allow_private=False)


def test_assert_allows_private_when_flag_set():
    assert_target_egress_allowed(_pin(ip="10.0.0.5"), allow_private=True)


# --- scanner_process_env ----------------------------------------------------------


def test_scanner_env_sets_job_marker():
    env = scanner_process_env(base={"PATH": "/usr/bin"})
    assert env["ATTESTRA_SCANNER_JOB"] == "1"
    assert env["PATH"] == "/usr/bin"


def test_scanner_env_strips_aws_mongo_session():
    base = {
        "PATH": "/bin",
        "AWS_ACCESS_KEY_ID": "AKIA...",
        "AWS_SECRET_ACCESS_KEY": "secret",
        "AWS_SESSION_TOKEN": "tok",
        "MONGO_URI": "mongodb://localhost/attestra",
        "MONGODB_URI": "mongodb://x",
        "ATTESTRA_SESSION_SECRET": "sess",
        "ATTESTRA_SESSION": "cookie",
        "ATTESTRA_IMAGE_GARAK": "garak@sha256:abc",
    }
    env = scanner_process_env(base=base)
    assert "AWS_ACCESS_KEY_ID" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "AWS_SESSION_TOKEN" not in env
    assert "MONGO_URI" not in env
    assert "MONGODB_URI" not in env
    assert "ATTESTRA_SESSION_SECRET" not in env
    assert "ATTESTRA_SESSION" not in env
    assert env["ATTESTRA_IMAGE_GARAK"] == "garak@sha256:abc"
    assert env["ATTESTRA_SCANNER_JOB"] == "1"


def test_scanner_env_strips_secret_shaped_keys():
    base = {
        "PATH": "/bin",
        "ATTESTRA_API_KEY": "nope",
        "MY_PASSWORD": "x",
        "HOME": "/home/scanner",
    }
    env = scanner_process_env(base=base)
    assert "ATTESTRA_API_KEY" not in env
    assert "MY_PASSWORD" not in env
    assert env["HOME"] == "/home/scanner"


def test_scanner_env_extra_merges_but_not_secrets():
    env = scanner_process_env(
        base={"PATH": "/bin"},
        extra={"FOO": "bar", "AWS_ACCESS_KEY_ID": "leak", "ATTESTRA_SCANNER_JOB": "0"},
    )
    assert env["FOO"] == "bar"
    assert "AWS_ACCESS_KEY_ID" not in env
    assert env["ATTESTRA_SCANNER_JOB"] == "1"


def test_scanner_env_does_not_pass_http_proxy_by_default():
    """HTTP_PROXY is not an essential; helpers must not imply proxy equals isolation."""
    env = scanner_process_env(base={"PATH": "/bin", "HTTP_PROXY": "http://127.0.0.1:8080"})
    assert "HTTP_PROXY" not in env
    assert env["ATTESTRA_SCANNER_JOB"] == "1"
