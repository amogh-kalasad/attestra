"""Unit tests for the AASI Phase 2 Garak scanner adapter (no real Docker)."""
# @lat: [[aasi#Phase 2 Garak adapter]]

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest

from attestra.runner.authorization import AuthorizationError, AuthorizedScope
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT
from attestra.runner.scanners.garak import (
    GARAK_REPORT_NAME,
    GENERATOR_CONFIG_NAME,
    GarakAdapter,
    RUN_CONFIG_NAME,
)
from attestra.runner.scanners import sdk

_METACHAR = re.compile(r"[;|&`$]|\$\(|\n|\r")

PIN = PinnedTarget(host="llm.example.com", ip="93.184.216.34", port=443, scheme="https")


def _has_metachar(argv: list[str]) -> list[str]:
    return [a for a in argv if _METACHAR.search(a)]


def test_meta_problems_empty():
    assert GarakAdapter().meta.problems() == []


def test_image_key_and_import_tool():
    a = GarakAdapter()
    assert a.name == "garak"
    assert a.image_key == "garak"
    assert a.import_tool == "garak"
    assert a.out_name == "garak-report.jsonl"
    assert a.meta.image_ref_env == "ATTESTRA_IMAGE_GARAK"
    assert a.meta.capabilities == ("ai_llm_probe",)
    assert a.meta.asset_kinds == ("ai_app",)
    assert a.meta.safety_tier == "T2"
    assert a.meta.network_egress == "target"
    assert a.meta.licence == "Apache-2.0"
    assert a.meta.output_schema == "garak-jsonl"


def test_contract_problems_empty(tmp_path: Path):
    assert sdk.contract_problems(GarakAdapter(), tmp_dir=tmp_path) == []


def test_docker_args_contain_out_path_and_no_metacharacters(tmp_path: Path):
    out = tmp_path / "garak-report.jsonl"
    args = GarakAdapter().docker_args(PIN, out_file=out)
    assert args[:2] == ["-m", "garak"]
    assert "--target_type" in args
    assert args[args.index("--target_type") + 1] == "rest"
    assert f"{CONTAINER_OUT}/{GENERATOR_CONFIG_NAME}" in args
    assert f"{CONTAINER_OUT}/{RUN_CONFIG_NAME}" in args
    assert _has_metachar(args) == []
    gen = (tmp_path / GENERATOR_CONFIG_NAME).read_text(encoding="utf-8")
    assert "https://llm.example.com/" in gen
    assert "RestGenerator" in gen
    run = (tmp_path / RUN_CONFIG_NAME).read_text(encoding="utf-8")
    assert f"report_dir: {CONTAINER_OUT}" in run
    assert "report_prefix: garak-report" in run


def test_build_argv_rejects_unpinned_target(tmp_path: Path):
    with pytest.raises(ValueError, match="DNS-pinned"):
        GarakAdapter().build_argv("https://llm.example.com/", out_file=tmp_path / "o.jsonl")


def test_unavailable_reason_mentions_image_env_when_docker_present(monkeypatch):
    from attestra import config

    a = GarakAdapter()
    monkeypatch.setattr("attestra.runner.scanners.base.docker_available", lambda: True)
    monkeypatch.setattr("attestra.runner.scanners.base.which", lambda _n: None)
    # Ensure image is unset / not configured.
    monkeypatch.setitem(config.SCANNER_IMAGES, "garak", "")
    monkeypatch.delenv("ATTESTRA_IMAGE_GARAK", raising=False)
    # configured_image falls through to env when key missing from SCANNER_IMAGES
    if "garak" in config.SCANNER_IMAGES:
        monkeypatch.setitem(config.SCANNER_IMAGES, "garak", "")
    reason = a.unavailable_reason()
    assert "ATTESTRA_IMAGE_GARAK" in reason


def test_authorize_rejects_off_scope(tmp_path: Path):
    scope = AuthorizedScope(
        name="t",
        allowed_hosts=frozenset({"other.example.com"}),
        allowed_urls=("https://other.example.com/",),
        allowed_paths=(),
        allowed_images=(),
    )
    with pytest.raises(AuthorizationError):
        GarakAdapter().docker_args(PIN, out_file=tmp_path / "garak-report.jsonl", scope=scope)


def test_resolve_output_finds_garak_suffix(tmp_path: Path):
    expected = tmp_path / "garak-report.jsonl"
    actual = tmp_path / GARAK_REPORT_NAME
    actual.write_text('{"entry_type":"init","garak_version":"0.0"}\n', encoding="utf-8")
    got = GarakAdapter().resolve_output(expected)
    assert got == actual


def test_available_false_without_local_cli(monkeypatch):
    monkeypatch.setattr("attestra.runner.scanners.garak.which", lambda _n: None)
    assert GarakAdapter().available() is False
