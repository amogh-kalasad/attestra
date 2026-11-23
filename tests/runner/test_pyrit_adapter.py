"""Unit tests for the AASI Phase 5 PyRIT isolated worker adapter (no image pull)."""
# @lat: [[tests#AASI Phase 5 PyRIT adapter]]

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners import sdk
from attestra.runner.scanners.base import CONTAINER_OUT, ScannerResult
from attestra.runner.scanners.pyrit import (
    CONFIG_NAME,
    DISABLE_EXTERNAL_ENV,
    SCENARIOS,
    WORKER_MODULE,
    PyRITAdapter,
    authorized_url,
    disable_external_env_flags,
    resolve_scenario,
    write_pyrit_run_config,
)

_METACHAR = re.compile(r"[;|&`$]|\$\(|\n|\r")
PIN = PinnedTarget(host="llm.example.com", ip="203.0.113.10", port=443, scheme="https")
FAKE_DIGEST = "sha256:" + "cd" * 32
FAKE_IMAGE = f"docker.io/attestra/pyrit-worker@{FAKE_DIGEST}"
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "ai" / "pyrit" / "attack_results.json"


def _clean(argv: list[str]) -> list[str]:
    assert [a for a in argv if _METACHAR.search(a)] == []
    return argv


@pytest.fixture
def pinned_image(monkeypatch):
    import attestra.config as cfg

    monkeypatch.setitem(cfg.SCANNER_IMAGES, "pyrit", FAKE_IMAGE)
    return FAKE_IMAGE


@pytest.fixture
def adapter() -> PyRITAdapter:
    return PyRITAdapter()


# @lat: [[tests#AASI Phase 5 PyRIT adapter#Meta and contract]]
def test_pyrit_meta_ok(adapter: PyRITAdapter):
    assert adapter.name == "pyrit"
    assert adapter.import_tool == "pyrit"
    assert adapter.image_key == "pyrit"
    assert adapter.out_name == "pyrit-results.json"
    meta = adapter.meta
    assert isinstance(meta, sdk.AdapterMeta)
    assert meta.problems() == []
    assert meta.asset_kinds == ("ai_app",)
    assert meta.safety_tier == "T2"
    assert meta.network_egress == "target"
    assert meta.licence == "MIT"
    assert meta.image_ref_env == "ATTESTRA_IMAGE_PYRIT"
    assert meta.output_schema == "pyrit-json"


def test_pyrit_passes_sdk_contract(adapter: PyRITAdapter, tmp_path: Path):
    assert sdk.contract_problems(adapter, tmp_dir=tmp_path) == []


def test_pyrit_rejects_unpinned_target(adapter: PyRITAdapter, tmp_path: Path):
    with pytest.raises(ValueError, match="DNS-pinned"):
        adapter.build_argv("https://llm.example.com/", out_file=tmp_path / "o.json")
    with pytest.raises(ValueError, match="DNS-pinned"):
        adapter.build_docker_argv("https://llm.example.com/", out_file=tmp_path / "o.json")


# @lat: [[tests#AASI Phase 5 PyRIT adapter#Scenario allowlist]]
def test_resolve_scenario_allowlist_and_aliases():
    assert resolve_scenario("baseline") == "crescendo"
    assert resolve_scenario("crescendo") == "crescendo"
    assert resolve_scenario("baseline", {"scenario": "pair"}) == "pair"
    assert resolve_scenario("many_shot_jailbreak") == "many_shot"
    assert resolve_scenario("toa") == "tree_of_attacks"
    assert resolve_scenario("red_team") == "red_teaming"
    for name in SCENARIOS:
        assert resolve_scenario(name) == name
    with pytest.raises(ValueError, match="scenario"):
        resolve_scenario("evil_custom")


def test_rejects_unrestricted_command_opts(adapter: PyRITAdapter, tmp_path: Path):
    out = tmp_path / adapter.out_name
    with pytest.raises(ValueError, match="unrestricted"):
        adapter.build_argv(PIN, out_file=out, command="rm -rf /")
    with pytest.raises(ValueError, match="unrestricted"):
        adapter.build_argv(PIN, out_file=out, argv=["--anything"])


# @lat: [[tests#AASI Phase 5 PyRIT adapter#Docker argv and judge lockdown]]
def test_pyrit_docker_argv_disables_external_judge(tmp_path: Path, pinned_image, adapter: PyRITAdapter):
    out = tmp_path / adapter.out_name
    argv = _clean(adapter.build_docker_argv(PIN, out_file=out, name="attestra-pyrit-test", profile="pair"))
    assert argv[:3] == ["docker", "run", "--rm"]
    assert FAKE_IMAGE in argv
    assert "--entrypoint" in argv and "python" in argv
    assert "-m" in argv and WORKER_MODULE in argv
    assert "--scenario" in argv and argv[argv.index("--scenario") + 1] == "pair"
    assert f"{CONTAINER_OUT}/{CONFIG_NAME}" in argv
    assert f"{CONTAINER_OUT}/pyrit-results.json" in argv
    assert "--add-host" in argv
    assert "llm.example.com:203.0.113.10" in argv
    for key, val in DISABLE_EXTERNAL_ENV:
        pair = f"{key}={val}"
        assert pair in argv
        assert argv[argv.index(pair) - 1] == "-e"
    cfg = json.loads((tmp_path / CONFIG_NAME).read_text(encoding="utf-8"))
    assert cfg["scenario"] == "pair"
    assert cfg["judge"]["mode"] == "none"
    assert cfg["judge"]["external_authorized"] is False
    assert cfg["adversarial_model"]["egress"] == "disabled"
    assert cfg["output"]["include_transcripts"] is True
    assert cfg["target"]["url"] == authorized_url(PIN)
    assert cfg["target"]["prompt_target"] == "http_target"


def test_external_judge_opt_in_skips_disable_env(tmp_path: Path, pinned_image, adapter: PyRITAdapter):
    out = tmp_path / adapter.out_name
    argv = adapter.build_docker_argv(
        PIN,
        out_file=out,
        scenario="crescendo",
        tenant_authorize_external_judge=True,
        judge="ollama:local",
    )
    for key, val in DISABLE_EXTERNAL_ENV:
        assert f"{key}={val}" not in argv
    cfg = json.loads((tmp_path / CONFIG_NAME).read_text(encoding="utf-8"))
    assert cfg["judge"]["mode"] == "external"
    assert cfg["judge"]["external_authorized"] is True
    assert cfg["judge"]["provider"] == "ollama:local"
    assert cfg["adversarial_model"]["egress"] == "external"


def test_disable_env_flags_pairs():
    flags = disable_external_env_flags()
    assert flags.count("-e") == len(DISABLE_EXTERNAL_ENV)
    for key, val in DISABLE_EXTERNAL_ENV:
        assert f"{key}={val}" in flags


def test_pyrit_image_ref_requires_digest(monkeypatch, adapter: PyRITAdapter):
    import attestra.config as cfg

    monkeypatch.setitem(cfg.SCANNER_IMAGES, "pyrit", "docker.io/attestra/pyrit-worker:latest")
    with pytest.raises(ValueError, match="@sha256:"):
        adapter.image_ref()


def test_local_argv_writes_config(adapter: PyRITAdapter, tmp_path: Path):
    out = tmp_path / adapter.out_name
    argv = _clean(adapter.build_argv(PIN, out_file=out, scenario="many_shot", endpoint_path="/v1/chat"))
    assert argv[0] == "python"
    assert WORKER_MODULE in argv
    assert argv[argv.index("--scenario") + 1] == "many_shot"
    cfg = json.loads((tmp_path / CONFIG_NAME).read_text(encoding="utf-8"))
    assert cfg["target"]["url"] == "https://llm.example.com/v1/chat"
    assert cfg["scenario"] == "many_shot"


def test_write_config_rejects_unsafe_path(tmp_path: Path):
    with pytest.raises(ValueError, match="unsafe"):
        write_pyrit_run_config(tmp_path, PIN, scenario="crescendo", path="/chat;rm")


def test_validate_report_fixture_and_garbage(adapter: PyRITAdapter):
    assert adapter.validate_report(FIXTURE.read_bytes()) is None
    assert adapter.validate_report(b"{not-json") is not None


# @lat: [[tests#AASI Phase 5 PyRIT adapter#Usage and transcripts]]
def test_scan_attaches_usage_from_report(adapter: PyRITAdapter, tmp_path: Path, monkeypatch):
    report = {
        "tool": "pyrit",
        "tool_version": "1.2.1",
        "usage": {"tokens_in": 100, "tokens_out": 40, "cost_usd": 0.02},
        "attack_results": [
            {
                "attack_result_id": "ar-1",
                "conversation_id": "c-1",
                "scenario_id": "crescendo-1",
                "outcome": "success",
                "success": True,
                "transcript": [
                    {"role": "user", "content": "hello"},
                    {"role": "assistant", "content": "secret"},
                ],
                "score": {"value": True, "score_type": "true_false"},
            }
        ],
    }
    out_file = tmp_path / adapter.out_name
    out_file.write_text(json.dumps(report), encoding="utf-8")

    def fake_scan(self, pin, *, out_dir, cancel=None, profile="baseline", **opts):
        sr = ScannerResult(
            tool=self.name,
            tool_version="pyrit (docker)",
            import_tool=self.import_tool,
            raw_path=out_file,
            extra={"returncode": 0},
        )
        return self.stamp_result(sr)

    monkeypatch.setattr(
        "attestra.runner.scanners.base.ScannerAdapter.scan",
        fake_scan,
    )
    sr = adapter.scan(PIN, out_dir=tmp_path, profile="crescendo")
    assert sr.extra.get("usage") == report["usage"]
    assert sr.extra.get("tokens_in") == 100
    assert sr.extra.get("cost_usd") == 0.02
    # Transcript remains in report JSON for the importer / evidence path.
    doc = json.loads(out_file.read_text(encoding="utf-8"))
    assert doc["attack_results"][0]["transcript"]


def test_registry_lists_pyrit():
    from attestra.runner.scanners.registry import get_adapter, list_adapters

    assert "pyrit" in list_adapters()
    assert get_adapter("pyrit").name == "pyrit"


def test_health_without_real_image(adapter: PyRITAdapter, monkeypatch):
    import attestra.runner.scanners.base as base
    import attestra.runner.scanners.pyrit as mod

    monkeypatch.setattr(base, "which", lambda _name: None)
    monkeypatch.setattr(mod, "which", lambda _name: None)
    monkeypatch.setattr(adapter, "configured_image", lambda: "")
    assert adapter.available() is False
    h = adapter.health()
    assert h["name"] == "pyrit"
    assert h["ready"] is False
    assert h["safety_tier"] == "T2"
    assert h["meta_problems"] == []
