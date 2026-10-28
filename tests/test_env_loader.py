"""Tests for the built-in .env loader (attestra/env_loader.py)."""

from __future__ import annotations

import os

import pytest

from attestra import config
from attestra.env_loader import find_env_file, load_env_file, parse_env_text

ZAP = "ghcr.io/zaproxy/zaproxy@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2"


def test_parse_basic_syntax():
    text = "\n".join(
        [
            "# comment",
            "",
            "APP_ENV=local",
            "export SUBSCRIPTION_SERVICE=OFF",
            'QUOTED="hello world"',
            "SINGLE='a # not a comment'",
            "INLINE=value # trailing comment",
            f"ATTESTRA_IMAGE_ZAP={ZAP}",
            "WITH_EQ=postgresql://u:p@h/db?a=b=c",
            "  SPACED  =  padded  ",
            "EMPTY=",
            "not a valid line",
            "1BAD=x",
        ]
    )
    env = parse_env_text(text)
    assert env["APP_ENV"] == "local"
    assert env["SUBSCRIPTION_SERVICE"] == "OFF"
    assert env["QUOTED"] == "hello world"
    assert env["SINGLE"] == "a # not a comment"
    assert env["INLINE"] == "value"
    assert env["ATTESTRA_IMAGE_ZAP"] == ZAP
    assert env["WITH_EQ"] == "postgresql://u:p@h/db?a=b=c"
    assert env["SPACED"] == "padded"
    assert env["EMPTY"] == ""
    assert "1BAD" not in env
    assert len(env) == 9


def test_real_env_wins(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text("ATTESTRA_TEST_A=from_file\nATTESTRA_TEST_B=from_file\n", encoding="utf-8")
    monkeypatch.setenv("ATTESTRA_TEST_A", "from_shell")
    os.environ.pop("ATTESTRA_TEST_B", None)
    applied = load_env_file(f)
    assert os.environ["ATTESTRA_TEST_A"] == "from_shell"
    assert os.environ["ATTESTRA_TEST_B"] == "from_file"
    assert applied == {"ATTESTRA_TEST_B": "from_file"}
    os.environ.pop("ATTESTRA_TEST_B", None)


def test_attestra_env_file_override(tmp_path, monkeypatch):
    f = tmp_path / "custom.env"
    f.write_text("ATTESTRA_TEST_C=custom\n", encoding="utf-8")
    monkeypatch.setenv("ATTESTRA_ENV_FILE", str(f))
    os.environ.pop("ATTESTRA_TEST_C", None)
    monkeypatch.delenv("ATTESTRA_DOTENV", raising=False)
    assert find_env_file() == f
    load_env_file()
    assert os.environ["ATTESTRA_TEST_C"] == "custom"
    os.environ.pop("ATTESTRA_TEST_C", None)


def test_disable_switch(tmp_path, monkeypatch):
    f = tmp_path / "custom.env"
    f.write_text("ATTESTRA_TEST_D=x\n", encoding="utf-8")
    monkeypatch.setenv("ATTESTRA_ENV_FILE", str(f))
    monkeypatch.setenv("ATTESTRA_DOTENV", "0")
    os.environ.pop("ATTESTRA_TEST_D", None)
    assert load_env_file() == {}
    assert "ATTESTRA_TEST_D" not in os.environ


def test_missing_file_is_noop(tmp_path):
    assert load_env_file(tmp_path / "nope.env") == {}


_BYPASS_KEYS = ("APP_ENV", "BYPASS_TARGET_OWNERSHIP_VERIFICATION", "BYPASS_SIGNED_AUTHORIZATION_VERIFICATION")


def test_bypass_still_requires_allowlisted_app_env(tmp_path, monkeypatch):
    """Loading BYPASS_* from .env must not weaken the APP_ENV allowlist.

    Keys are removed with os.environ.pop (not monkeypatch) because the loader
    writes os.environ directly; monkeypatch would otherwise restore them.
    """
    f = tmp_path / ".env"
    f.write_text(
        "APP_ENV=production\n"
        "BYPASS_TARGET_OWNERSHIP_VERIFICATION=true\n"
        "BYPASS_SIGNED_AUTHORIZATION_VERIFICATION=true\n",
        encoding="utf-8",
    )
    saved = {k: os.environ.pop(k) for k in _BYPASS_KEYS if k in os.environ}
    load_env_file(f)
    try:
        assert config.ownership_bypass_active() is False
        assert config.signed_authorization_bypass_active() is False
        with pytest.raises(config.ConfigurationError):
            config.validate_runtime_config()
        os.environ["APP_ENV"] = "local"
        assert config.ownership_bypass_active() is True
        assert config.signed_authorization_bypass_active() is True
    finally:
        for k in ("APP_ENV", "BYPASS_TARGET_OWNERSHIP_VERIFICATION", "BYPASS_SIGNED_AUTHORIZATION_VERIFICATION"):
            os.environ.pop(k, None)
        os.environ.update(saved)
        config.validate_runtime_config()
