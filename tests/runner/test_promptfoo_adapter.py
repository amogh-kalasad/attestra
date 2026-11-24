"""Unit tests for the AASI V5.1 native Promptfoo scanner adapter (no Docker, no image pull)."""
# @lat: [[tests#AASI Phase 2 Promptfoo adapter]]

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners import sdk
from attestra.runner.scanners.promptfoo import (
    CONFIG_NAME,
    DISABLE_ENV,
    PromptfooAdapter,
    authorized_url,
    privacy_env,
    resolve_promptfoo_argv_prefix,
    write_promptfoo_config,
)

PIN = PinnedTarget(host="llm.example.com", ip="203.0.113.10", port=443, scheme="https")


@pytest.fixture
def shared_npm_cli(tmp_path, monkeypatch):
    """Minimal shared-env layout with a non-wrapper promptfoo CLI under npm/bin."""
    from attestra import config

    root = tmp_path / "runtime"
    npm = root / "npm"
    bin_dir = npm / "bin"
    bin_dir.mkdir(parents=True)
    cli = bin_dir / "promptfoo"
    cli.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    monkeypatch.setattr(config, "SHARED_ENV_ROOT", str(root))
    return root, cli


@pytest.fixture
def shared_npm_node_entry(tmp_path, monkeypatch):
    """Shared-env layout using node + package entrypoint (Windows-safe, no .cmd)."""
    import sys

    from attestra import config

    root = tmp_path / "runtime"
    entry = root / "npm" / "node_modules" / "promptfoo" / "dist" / "src" / "entrypoint.js"
    entry.parent.mkdir(parents=True)
    entry.write_text("// promptfoo entry\n", encoding="utf-8")
    node_name = "node.exe" if sys.platform == "win32" else "node"
    node = root / "tools" / "node" / "bin" / node_name
    node.parent.mkdir(parents=True)
    node.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(config, "SHARED_ENV_ROOT", str(root))
    return root, node, entry


# @lat: [[tests#AASI Phase 2 Promptfoo adapter#Meta and contract]]
def test_promptfoo_meta_ok():
    adapter = PromptfooAdapter()
    assert adapter.name == "promptfoo"
    assert adapter.import_tool == "promptfoo"
    assert adapter.image_key == ""
    assert adapter.allows_docker is False
    assert adapter.out_name == "promptfoo-results.json"
    meta = adapter.meta
    assert isinstance(meta, sdk.AdapterMeta)
    assert meta.problems() == []
    assert meta.asset_kinds == ("ai_app",)
    assert meta.safety_tier == "T2"
    assert meta.network_egress == "target"
    assert meta.licence == "MIT"
    assert meta.image_ref_env == ""
    assert meta.output_schema == "promptfoo-results-json"


def test_promptfoo_passes_sdk_contract(tmp_path):
    assert sdk.contract_problems(PromptfooAdapter(), tmp_dir=tmp_path) == []


def test_promptfoo_rejects_unpinned_target(tmp_path, shared_npm_cli):
    adapter = PromptfooAdapter()
    with pytest.raises(ValueError, match="DNS-pinned"):
        adapter.build_argv("https://llm.example.com/", out_file=tmp_path / "o.json")


def test_privacy_env_keys():
    env = privacy_env()
    assert env == {key: val for key, val in DISABLE_ENV}
    for key in (
        "PROMPTFOO_DISABLE_REMOTE_GENERATION",
        "PROMPTFOO_DISABLE_TELEMETRY",
        "PROMPTFOO_DISABLE_SHARING",
        "PROMPTFOO_DISABLE_UPDATE",
    ):
        assert key in env


def test_promptfoo_never_uses_docker(monkeypatch):
    import attestra.runner.scanners.base as base

    monkeypatch.setattr(base, "docker_available", lambda: True)
    adapter = PromptfooAdapter()
    assert adapter.allows_docker is False
    assert adapter.uses_docker() is False
    assert adapter.image_key == ""
    assert adapter.configured_image() == ""


# @lat: [[tests#AASI Phase 2 Promptfoo adapter#Native shared-env argv]]
def test_promptfoo_build_argv_shared_cli(tmp_path, shared_npm_cli):
    _root, cli = shared_npm_cli
    adapter = PromptfooAdapter()
    assert adapter.available() is True
    out = tmp_path / "promptfoo-results.json"
    argv = adapter.build_argv(PIN, out_file=out)
    assert argv[0] == str(cli)
    assert argv[1:3] == ["eval", "-c"]
    assert "-o" in argv and str(out) in argv
    cfg_path = Path(argv[argv.index("-c") + 1])
    assert cfg_path.name == CONFIG_NAME and cfg_path.is_file()
    doc = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert doc["providers"][0]["config"]["url"] == authorized_url(PIN)
    assert doc["sharing"] is False
    for key, val in DISABLE_ENV:
        assert doc["env"][key] == val


def test_promptfoo_build_argv_node_entry(tmp_path, shared_npm_node_entry):
    _root, node, entry = shared_npm_node_entry
    adapter = PromptfooAdapter()
    assert adapter.available() is True
    prefix = resolve_promptfoo_argv_prefix()
    assert prefix == [str(node), str(entry)]
    out = tmp_path / "promptfoo-results.json"
    argv = adapter.build_argv(PIN, out_file=out)
    assert argv[:2] == [str(node), str(entry)]
    assert argv[2] == "eval"
    assert (tmp_path / CONFIG_NAME).is_file()


def test_promptfoo_unavailable_without_shared_install(tmp_path, monkeypatch):
    from attestra import config

    monkeypatch.setattr(config, "SHARED_ENV_ROOT", str(tmp_path / "empty-runtime"))
    adapter = PromptfooAdapter()
    assert adapter.available() is False
    assert resolve_promptfoo_argv_prefix() is None
    reason = adapter.unavailable_reason()
    assert "ATTESTRA_SHARED_ENV_ROOT" in reason or "shared" in reason.lower()
    assert "Docker Desktop" not in reason
    assert "ATTESTRA_IMAGE_PROMPTFOO" not in reason
    assert "docker" not in reason.lower() or "Docker is not used" in reason


def test_promptfoo_no_system_path_fallback(tmp_path, monkeypatch):
    """Even if promptfoo is on PATH, available() requires the shared npm install."""
    from attestra import config

    monkeypatch.setattr(config, "SHARED_ENV_ROOT", str(tmp_path / "no-npm"))
    monkeypatch.setenv("PATH", str(tmp_path / "fake-bin"))
    fake = tmp_path / "fake-bin"
    fake.mkdir()
    (fake / "promptfoo").write_text("#!/bin/sh\n", encoding="utf-8")
    adapter = PromptfooAdapter()
    assert adapter.available() is False


def test_write_promptfoo_config_optional_local_judge(tmp_path):
    cfg = write_promptfoo_config(tmp_path, PIN, judge="ollama:chat:llama3.2")
    doc = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    assert doc["defaultTest"]["options"]["provider"] == "ollama:chat:llama3.2"


def test_validate_report_rejects_garbage():
    msg = PromptfooAdapter().validate_report(b"\x00not promptfoo{{{")
    assert msg and "promptfoo" in msg.lower()


def test_scan_injects_privacy_env(tmp_path, shared_npm_cli, monkeypatch):
    """``_scan`` passes DISABLE_ENV into the subprocess env without mutating globals mid-flight."""
    import attestra.runner.scanners.base as base_mod
    from attestra.runner.scanners.base import ProcessResult, ScannerResult

    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs.get("env") or {}
        out = Path(argv[argv.index("-o") + 1])
        out.write_text("{}", encoding="utf-8")
        return ProcessResult(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(base_mod, "run_process", fake_run)
    monkeypatch.setattr(
        PromptfooAdapter,
        "validate_report",
        lambda self, raw: None,
    )
    adapter = PromptfooAdapter()
    result = adapter.scan(PIN, out_dir=tmp_path)
    assert isinstance(result, ScannerResult)
    assert result.error in ("", None) or result.raw_path is not None
    assert captured["env"]
    for key, val in DISABLE_ENV:
        assert captured["env"].get(key) == val
