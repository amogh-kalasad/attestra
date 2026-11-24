"""AASI V5.1 SafeLabs adapter — native argv, meta, and validate_report (no Docker)."""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners import sdk
from attestra.runner.scanners.safelabs import SafeLabsAdapter

_METACHAR = re.compile(r"[;|&`$]|\$\(|\n|\r")
PIN = PinnedTarget(host="agent.example.com", ip="203.0.113.10", port=8443, scheme="https")
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "ai" / "safelabs" / "report.json"


def _clean(argv: list[str]) -> list[str]:
    assert [a for a in argv if _METACHAR.search(a)] == []
    return argv


@pytest.fixture
def adapter() -> SafeLabsAdapter:
    return SafeLabsAdapter()


# @lat: [[tests#AASI Phase 2 SafeLabs adapter#Contract and metadata]]
def test_safelabs_passes_adapter_contract(adapter: SafeLabsAdapter, tmp_path: Path):
    assert sdk.contract_problems(adapter, tmp_dir=tmp_path) == []
    m = adapter.meta
    assert adapter.name == "safelabs"
    assert adapter.import_tool == "safelabs"
    assert adapter.image_key == ""
    assert adapter.allows_docker is False
    assert adapter.uses_docker() is False
    assert adapter.out_name == "safelabs-report.json"
    assert adapter.report_on_stdout is True
    assert m.asset_kinds == ("ai_app",)
    assert m.safety_tier == "T2"
    assert m.network_egress == "target"
    assert m.licence == "Apache-2.0"
    assert m.image_ref_env == ""
    assert m.output_schema == "safelabs-json"
    assert m.problems() == []


# @lat: [[tests#AASI Phase 2 SafeLabs adapter#Argv and docker_args]]
def test_safelabs_build_argv_native(adapter: SafeLabsAdapter, tmp_path: Path):
    out = tmp_path / adapter.out_name
    with patch("attestra.runner.scanners.safelabs._safelabs_prefix", return_value=["python", "-m", "safelabs"]):
        argv = _clean(adapter.build_argv(PIN, out_file=out, profile="baseline"))
    assert argv[:3] == ["python", "-m", "safelabs"]
    assert argv[3] == "run"
    assert argv[argv.index("--target") + 1] == "https://agent.example.com:8443/"
    assert argv[argv.index("--category") + 1] == "ASI01"
    assert argv[argv.index("--output") + 1] == "json"

    with patch("attestra.runner.scanners.safelabs._safelabs_prefix", return_value=["python", "-m", "safelabs"]):
        argv_full = _clean(adapter.build_argv(PIN, out_file=out, profile="full"))
    assert argv_full[argv_full.index("--category") + 1] == "all"

    with patch("attestra.runner.scanners.safelabs._safelabs_prefix", return_value=["python", "-m", "safelabs"]):
        argv2 = _clean(
            adapter.build_argv(PIN, out_file=out, profile="baseline", endpoint_path="/chat", category="ASI06")
        )
    assert argv2[argv2.index("--target") + 1] == "https://agent.example.com:8443/chat"
    assert argv2[argv2.index("--category") + 1] == "ASI06"

    with pytest.raises(ValueError, match="DNS-pinned"):
        adapter.build_argv("https://agent.example.com/chat", out_file=out)
    with pytest.raises(NotImplementedError, match="native-only"):
        adapter.docker_args(PIN, out_file=out)
    with pytest.raises(ValueError, match="category"):
        adapter.build_argv(PIN, out_file=out, category="ASI99")
    with pytest.raises(ValueError, match="endpoint_path"):
        adapter.build_argv(PIN, out_file=out, endpoint_path="/chat;rm")


# @lat: [[tests#AASI Phase 2 SafeLabs adapter#Report validation]]
def test_safelabs_validate_report_fixture_and_garbage(adapter: SafeLabsAdapter):
    assert adapter.validate_report(FIXTURE.read_bytes()) is None
    assert adapter.validate_report(b"{not-json") is not None


# @lat: [[tests#AASI Phase 2 SafeLabs adapter#No real image required]]
def test_safelabs_health_without_shared_env(adapter: SafeLabsAdapter, monkeypatch):
    monkeypatch.setattr("attestra.runner.scanners.safelabs._safelabs_in_shared_env", lambda: False)
    monkeypatch.setattr("attestra.runner.scanners.safelabs._shared_python", lambda: None)
    monkeypatch.setattr("attestra.runner.scanners.safelabs.which", lambda _n: None)
    monkeypatch.setattr("attestra.runner.scanners.safelabs._safelabs_importable", lambda _py: False)
    assert adapter.available() is False
    reason = adapter.unavailable_reason()
    assert "install_shared_env.py" in reason
    assert "docker" not in reason.lower()
    h = adapter.health()
    assert h["name"] == "safelabs"
    assert h["ready"] is False
    assert h["safety_tier"] == "T2"
    assert h["meta_problems"] == []


def test_safelabs_available_when_shared_python_imports(adapter: SafeLabsAdapter, monkeypatch):
    monkeypatch.setattr("attestra.runner.scanners.safelabs._safelabs_in_shared_env", lambda: True)
    assert adapter.available() is True
