"""Unit tests for the AASI Phase 2 Promptfoo scanner adapter (no image pull)."""
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
    disable_env_flags,
    write_promptfoo_config,
)

PIN = PinnedTarget(host="llm.example.com", ip="203.0.113.10", port=443, scheme="https")
FAKE_DIGEST = "sha256:" + "ab" * 32
FAKE_IMAGE = f"ghcr.io/promptfoo/promptfoo@{FAKE_DIGEST}"


@pytest.fixture
def pinned_image(monkeypatch):
    import attestra.config as cfg

    monkeypatch.setitem(cfg.SCANNER_IMAGES, "promptfoo", FAKE_IMAGE)
    return FAKE_IMAGE


# @lat: [[tests#AASI Phase 2 Promptfoo adapter#Meta and contract]]
def test_promptfoo_meta_ok():
    adapter = PromptfooAdapter()
    assert adapter.name == "promptfoo"
    assert adapter.import_tool == "promptfoo"
    assert adapter.image_key == "promptfoo"
    assert adapter.out_name == "promptfoo-results.json"
    meta = adapter.meta
    assert isinstance(meta, sdk.AdapterMeta)
    assert meta.problems() == []
    assert meta.asset_kinds == ("ai_app",)
    assert meta.safety_tier == "T2"
    assert meta.network_egress == "target"
    assert meta.licence == "MIT"
    assert meta.image_ref_env == "ATTESTRA_IMAGE_PROMPTFOO"
    assert meta.output_schema == "promptfoo-results-json"


def test_promptfoo_passes_sdk_contract(tmp_path):
    assert sdk.contract_problems(PromptfooAdapter(), tmp_dir=tmp_path) == []


def test_promptfoo_rejects_unpinned_target(tmp_path):
    adapter = PromptfooAdapter()
    with pytest.raises(ValueError, match="DNS-pinned"):
        adapter.build_argv("https://llm.example.com/", out_file=tmp_path / "o.json")
    with pytest.raises(ValueError, match="DNS-pinned"):
        adapter.build_docker_argv("https://llm.example.com/", out_file=tmp_path / "o.json")


def test_disable_env_flags_pairs():
    flags = disable_env_flags()
    assert flags.count("-e") == len(DISABLE_ENV)
    for key, val in DISABLE_ENV:
        assert f"{key}={val}" in flags
        assert flags[flags.index(f"{key}={val}") - 1] == "-e"


# @lat: [[tests#AASI Phase 2 Promptfoo adapter#Docker argv disables remote features]]
def test_promptfoo_docker_argv_env_disables(tmp_path, pinned_image):
    adapter = PromptfooAdapter()
    out = tmp_path / "promptfoo-results.json"
    argv = adapter.build_docker_argv(PIN, out_file=out, name="attestra-promptfoo-test")
    assert argv[:3] == ["docker", "run", "--rm"]
    assert FAKE_IMAGE in argv
    for key, val in DISABLE_ENV:
        pair = f"{key}={val}"
        assert pair in argv
        assert argv[argv.index(pair) - 1] == "-e"
    assert "--add-host" in argv
    assert "llm.example.com:203.0.113.10" in argv
    assert "--entrypoint" in argv and "promptfoo" in argv
    assert "eval" in argv
    assert "-c" in argv and f"/out/{CONFIG_NAME}" in argv
    assert "-o" in argv and "/out/promptfoo-results.json" in argv
    assert (tmp_path / CONFIG_NAME).is_file()


def test_promptfoo_image_ref_requires_digest(monkeypatch):
    import attestra.config as cfg

    monkeypatch.setitem(cfg.SCANNER_IMAGES, "promptfoo", "ghcr.io/promptfoo/promptfoo:latest")
    with pytest.raises(ValueError, match="@sha256:"):
        PromptfooAdapter().image_ref()


def test_promptfoo_local_argv_writes_config(tmp_path):
    adapter = PromptfooAdapter()
    out = tmp_path / "promptfoo-results.json"
    argv = adapter.build_argv(PIN, out_file=out)
    assert argv[:2] == ["promptfoo", "eval"]
    assert "-c" in argv and "-o" in argv
    cfg_path = Path(argv[argv.index("-c") + 1])
    assert cfg_path.name == CONFIG_NAME and cfg_path.is_file()
    doc = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert doc["providers"][0]["config"]["url"] == authorized_url(PIN)
    assert doc["sharing"] is False
    for key, val in DISABLE_ENV:
        assert doc["env"][key] == val


def test_write_promptfoo_config_optional_local_judge(tmp_path):
    cfg = write_promptfoo_config(tmp_path, PIN, judge="ollama:chat:llama3.2")
    doc = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    assert doc["defaultTest"]["options"]["provider"] == "ollama:chat:llama3.2"


def test_validate_report_rejects_garbage():
    msg = PromptfooAdapter().validate_report(b"\x00not promptfoo{{{")
    assert msg and "promptfoo" in msg.lower()
