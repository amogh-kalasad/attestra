"""Unit tests for the AASI V5.1 native Garak scanner adapter (no Docker)."""
# @lat: [[aasi#Phase 2 Garak adapter]]

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest

from attestra.runner.authorization import AuthorizationError, AuthorizedScope
from attestra.runner.dns_pin import PinnedTarget
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
    assert a.image_key == ""
    assert a.allows_docker is False
    assert a.uses_docker() is False
    assert a.import_tool == "garak"
    assert a.out_name == "garak-report.jsonl"
    assert a.meta.image_ref_env == ""
    assert a.meta.capabilities == ("ai_llm_probe",)
    assert a.meta.asset_kinds == ("ai_app",)
    assert a.meta.safety_tier == "T2"
    assert a.meta.network_egress == "target"
    assert a.meta.licence == "Apache-2.0"
    assert a.meta.output_schema == "garak-jsonl"


def test_contract_problems_empty(tmp_path: Path):
    assert sdk.contract_problems(GarakAdapter(), tmp_dir=tmp_path) == []


def test_build_argv_host_paths_and_no_metacharacters(tmp_path: Path):
    out = tmp_path / "garak-report.jsonl"
    with patch("attestra.runner.scanners.garak._garak_prefix", return_value=["python", "-m", "garak"]):
        args = GarakAdapter().build_argv(PIN, out_file=out)
    assert args[:3] == ["python", "-m", "garak"]
    assert "--target_type" in args
    assert args[args.index("--target_type") + 1] == "rest"
    report_dir = out.parent.resolve().as_posix()
    assert f"{report_dir}/{GENERATOR_CONFIG_NAME}" in args
    assert f"{report_dir}/{RUN_CONFIG_NAME}" in args
    assert _has_metachar(args) == []
    gen = (tmp_path / GENERATOR_CONFIG_NAME).read_text(encoding="utf-8")
    assert "https://llm.example.com/" in gen
    assert "RestGenerator" in gen
    run = (tmp_path / RUN_CONFIG_NAME).read_text(encoding="utf-8")
    assert f"report_dir: {report_dir}" in run
    assert "report_prefix: garak-report" in run


def test_docker_args_not_supported(tmp_path: Path):
    with pytest.raises(NotImplementedError, match="native-only"):
        GarakAdapter().docker_args(PIN, out_file=tmp_path / "garak-report.jsonl")


def test_build_argv_rejects_unpinned_target(tmp_path: Path):
    with pytest.raises(ValueError, match="DNS-pinned"):
        GarakAdapter().build_argv("https://llm.example.com/", out_file=tmp_path / "o.jsonl")


def test_unavailable_reason_mentions_shared_env_not_docker(monkeypatch):
    a = GarakAdapter()
    monkeypatch.setattr("attestra.runner.scanners.garak._shared_python", lambda: None)
    monkeypatch.setattr("attestra.runner.scanners.garak.which", lambda _n: None)
    monkeypatch.setattr("attestra.runner.scanners.garak._garak_importable", lambda _py: False)
    reason = a.unavailable_reason()
    assert "install_shared_env.py" in reason
    assert "docker" not in reason.lower()
    assert "ATTESTRA_IMAGE" not in reason


def test_authorize_rejects_off_scope(tmp_path: Path):
    scope = AuthorizedScope(
        name="t",
        allowed_hosts=frozenset({"other.example.com"}),
        allowed_urls=("https://other.example.com/",),
        allowed_paths=(),
        allowed_images=(),
    )
    with patch("attestra.runner.scanners.garak._garak_prefix", return_value=["python", "-m", "garak"]):
        with pytest.raises(AuthorizationError):
            GarakAdapter().build_argv(PIN, out_file=tmp_path / "garak-report.jsonl", scope=scope)


def test_resolve_output_finds_garak_suffix(tmp_path: Path):
    expected = tmp_path / "garak-report.jsonl"
    actual = tmp_path / GARAK_REPORT_NAME
    actual.write_text('{"entry_type":"init","garak_version":"0.0"}\n', encoding="utf-8")
    got = GarakAdapter().resolve_output(expected)
    assert got == actual


def test_available_false_without_shared_or_local(monkeypatch):
    monkeypatch.setattr("attestra.runner.scanners.garak._garak_in_shared_env", lambda: False)
    monkeypatch.setattr("attestra.runner.scanners.garak._shared_python", lambda: None)
    monkeypatch.setattr("attestra.runner.scanners.garak.which", lambda _n: None)
    monkeypatch.setattr("attestra.runner.scanners.garak._garak_importable", lambda _py: False)
    assert GarakAdapter().available() is False


def test_available_true_when_shared_python_imports(monkeypatch):
    monkeypatch.setattr("attestra.runner.scanners.garak._garak_in_shared_env", lambda: True)
    assert GarakAdapter().available() is True
