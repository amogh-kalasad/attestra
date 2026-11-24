"""Unit tests for the AASI V5.1 native PyRIT adapter (no Docker / no image pull)."""
# @lat: [[tests#AASI Phase 5 PyRIT adapter]]

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners import sdk
from attestra.runner.scanners.base import ScannerResult
from attestra.runner.scanners.pyrit import (
    CONFIG_NAME,
    DISABLE_EXTERNAL_ENV,
    NATIVE_MODULE,
    SCENARIOS,
    PyRITAdapter,
    authorized_url,
    resolve_scenario,
    write_pyrit_run_config,
)

_METACHAR = re.compile(r"[;|&`$]|\$\(|\n|\r")
PIN = PinnedTarget(host="llm.example.com", ip="203.0.113.10", port=443, scheme="https")
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "ai" / "pyrit" / "attack_results.json"


def _clean(argv: list[str]) -> list[str]:
    assert [a for a in argv if _METACHAR.search(a)] == []
    return argv


@pytest.fixture
def adapter() -> PyRITAdapter:
    return PyRITAdapter()


# @lat: [[tests#AASI Phase 5 PyRIT adapter#Meta and contract]]
def test_pyrit_meta_ok(adapter: PyRITAdapter):
    assert adapter.name == "pyrit"
    assert adapter.import_tool == "pyrit"
    assert adapter.image_key == ""
    assert adapter.allows_docker is False
    assert adapter.out_name == "pyrit-results.json"
    meta = adapter.meta
    assert isinstance(meta, sdk.AdapterMeta)
    assert meta.problems() == []
    assert meta.asset_kinds == ("ai_app",)
    assert meta.safety_tier == "T2"
    assert meta.network_egress == "target"
    assert meta.licence == "MIT"
    assert meta.image_ref_env == ""
    assert meta.output_schema == "pyrit-json"


def test_pyrit_passes_sdk_contract(adapter: PyRITAdapter, tmp_path: Path):
    assert sdk.contract_problems(adapter, tmp_dir=tmp_path) == []


def test_pyrit_rejects_unpinned_target(adapter: PyRITAdapter, tmp_path: Path):
    with pytest.raises(ValueError, match="DNS-pinned"):
        adapter.build_argv("https://llm.example.com/", out_file=tmp_path / "o.json")


def test_allows_docker_false_and_uses_docker(adapter: PyRITAdapter):
    assert adapter.allows_docker is False
    assert adapter.uses_docker() is False
    with pytest.raises(NotImplementedError, match="native-only"):
        adapter.build_docker_argv(PIN, out_file=Path("o.json"))


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


def test_native_argv_writes_config(adapter: PyRITAdapter, tmp_path: Path):
    out = tmp_path / adapter.out_name
    argv = _clean(adapter.build_argv(PIN, out_file=out, scenario="many_shot", endpoint_path="/v1/chat"))
    assert Path(argv[0]).name.lower().startswith("python")
    assert "-m" in argv and NATIVE_MODULE in argv
    assert argv[argv.index("--scenario") + 1] == "many_shot"
    cfg = json.loads((tmp_path / CONFIG_NAME).read_text(encoding="utf-8"))
    assert cfg["target"]["url"] == "https://llm.example.com/v1/chat"
    assert cfg["scenario"] == "many_shot"
    assert cfg["scenario_engine"] == "pyrit-backed"
    assert cfg["judge"]["mode"] == "none"
    assert cfg["judge"]["external_authorized"] is False
    assert cfg["adversarial_model"]["egress"] == "disabled"
    assert cfg["target"]["prompt_target"] == "http_target"


def test_external_judge_opt_in_config(adapter: PyRITAdapter, tmp_path: Path):
    out = tmp_path / adapter.out_name
    adapter.build_argv(
        PIN,
        out_file=out,
        scenario="crescendo",
        tenant_authorize_external_judge=True,
        judge="ollama:local",
    )
    cfg = json.loads((tmp_path / CONFIG_NAME).read_text(encoding="utf-8"))
    assert cfg["judge"]["mode"] == "external"
    assert cfg["judge"]["external_authorized"] is True
    assert cfg["judge"]["provider"] == "ollama:local"
    assert cfg["adversarial_model"]["egress"] == "external"


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
        "pyrit_version": "1.2.1",
        "scenario_engine": "pyrit-backed",
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
            tool_version="pyrit 1.2.1",
            import_tool=self.import_tool,
            raw_path=out_file,
            extra={"returncode": 0},
        )
        return self.stamp_result(sr)

    monkeypatch.setattr(
        "attestra.runner.scanners.base.ScannerAdapter.scan",
        fake_scan,
    )
    # Bypass _scan_with_env by authorizing external so super().scan is used.
    sr = adapter.scan(PIN, out_dir=tmp_path, profile="crescendo", tenant_authorize_external_judge=True)
    assert sr.extra.get("usage") == report["usage"]
    assert sr.extra.get("tokens_in") == 100
    assert sr.extra.get("cost_usd") == 0.02
    doc = json.loads(out_file.read_text(encoding="utf-8"))
    assert doc["attack_results"][0]["transcript"]


def test_available_false_when_pyrit_missing(adapter: PyRITAdapter, monkeypatch):
    import attestra.aasi.pyrit_native as native
    import attestra.runner.scanners.pyrit as mod

    monkeypatch.setattr(native, "available", lambda: False)
    monkeypatch.setattr(native, "pyrit_version", lambda: None)
    monkeypatch.setattr(mod, "_pyrit_in_shared_env", lambda: False)
    monkeypatch.setattr(mod, "_pyrit_importable", lambda _py: False)
    assert adapter.available() is False
    h = adapter.health()
    assert h["name"] == "pyrit"
    assert h["ready"] is False
    assert "pyrit" in adapter.unavailable_reason().lower()
    assert "shared" in adapter.unavailable_reason().lower()


def test_available_true_when_pyrit_present(adapter: PyRITAdapter, monkeypatch):
    import attestra.aasi.pyrit_native as native
    import attestra.runner.scanners.pyrit as mod

    monkeypatch.setattr(mod, "_pyrit_in_shared_env", lambda: True)
    monkeypatch.setattr(mod, "_pyrit_importable", lambda _py: True)
    monkeypatch.setattr(native, "available", lambda: True)
    monkeypatch.setattr(native, "pyrit_version", lambda: "1.2.1")

    class _Proc:
        returncode = 0
        stdout = "1.2.1\n"
        stderr = ""

    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: _Proc())
    assert adapter.available() is True
    assert "1.2.1" in adapter.version()


def test_registry_lists_pyrit():
    from attestra.runner.scanners.registry import get_adapter, list_adapters

    assert "pyrit" in list_adapters()
    assert get_adapter("pyrit").name == "pyrit"


def test_disable_env_constants():
    assert ("PYRIT_DISABLE_EXTERNAL_JUDGE", "1") in DISABLE_EXTERNAL_ENV
    assert ("PYRIT_DISABLE_ADVERSARIAL_EGRESS", "1") in DISABLE_EXTERNAL_ENV
    assert authorized_url(PIN) == "https://llm.example.com/"
