"""Unit tests for AASI V5.1 native PyRIT runner (mocked package import)."""
# @lat: [[tests#AASI Phase 5 PyRIT adapter]]

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from attestra.aasi import pyrit_native as native


def test_available_false_when_missing(monkeypatch):
    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "pyrit" or name.startswith("pyrit."):
            raise ImportError("no pyrit")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    # available() does `import pyrit` inside the function — patch the helper.
    monkeypatch.setattr(native, "available", lambda: False)
    assert native.available() is False
    assert "pip install" in native.install_hint().lower()


def test_available_true_when_present(monkeypatch):
    monkeypatch.setattr(native, "available", lambda: True)
    monkeypatch.setattr(native, "pyrit_version", lambda: "1.2.1")
    assert native.available() is True
    assert native.pyrit_version() == "1.2.1"


def test_resolve_scenario_allowlist():
    assert native.resolve_scenario("crescendo") == "crescendo"
    assert native.resolve_scenario("TAP") == "tree_of_attacks"
    assert native.resolve_scenario("many_shot_jailbreak") == "many_shot"
    with pytest.raises(ValueError, match="scenario"):
        native.resolve_scenario("not_a_real_scenario")


def test_run_scenario_missing_pyrit_writes_error_report(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(native, "available", lambda: False)
    cfg = tmp_path / "pyrit-run.json"
    out = tmp_path / "pyrit-results.json"
    cfg.write_text(
        json.dumps({"target": {"url": "https://llm.example.com/v1/chat"}, "judge": {"external_authorized": False}}),
        encoding="utf-8",
    )
    rc = native.run_scenario(cfg, out, "crescendo")
    assert rc == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["tool"] == "pyrit"
    assert doc["scenario_engine"] == "pyrit-backed"
    assert "pip install" in (doc.get("error") or doc.get("note") or "").lower()


def test_run_scenario_rejects_unknown(tmp_path: Path):
    cfg = tmp_path / "pyrit-run.json"
    out = tmp_path / "pyrit-results.json"
    cfg.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="scenario"):
        native.run_scenario(cfg, out, "evil_custom")


def test_cli_main_run(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(native, "available", lambda: False)
    cfg = tmp_path / "pyrit-run.json"
    out = tmp_path / "pyrit-results.json"
    cfg.write_text(
        json.dumps({"target": {"url": "http://127.0.0.1:9/v1/chat"}, "judge": {"mode": "none", "external_authorized": False}}),
        encoding="utf-8",
    )
    rc = native.main(["run", "--config", str(cfg), "--output", str(out), "--scenario", "pair"])
    assert rc == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["scenario"] == "pair"


def test_http_request_template_shapes():
    raw, use_tls = native._http_request_template("https://llm.example.com/v1/chat/completions")
    assert use_tls is True
    assert "Host: llm.example.com" in raw
    assert "{PROMPT}" in raw
    assert "POST /v1/chat/completions" in raw
    raw2, use_tls2 = native._http_request_template("http://127.0.0.1:8080/chat")
    assert use_tls2 is False
    assert "Host: 127.0.0.1:8080" in raw2


def test_run_async_mocked_pyrit(tmp_path: Path, monkeypatch):
    """When pyrit is 'present', runner builds report via PromptSendingAttack mock."""

    class FakeOutcome:
        name = "UNDETERMINED"

    class FakeResult:
        conversation_id = "conv-1"
        last_response = types.SimpleNamespace(converted_value="I cannot help with that.")
        outcome = FakeOutcome()
        success = False

    class FakeAttack:
        def __init__(self, *a, **k):
            pass

        async def execute_async(self, **kwargs):
            return FakeResult()

    fake_pyrit = types.ModuleType("pyrit")
    fake_pyrit.__version__ = "9.9.9"

    monkeypatch.setattr(native, "available", lambda: True)
    monkeypatch.setattr(native, "pyrit_version", lambda: "9.9.9")
    monkeypatch.setitem(__import__("sys").modules, "pyrit", fake_pyrit)

    async def fake_init():
        return None

    monkeypatch.setattr(native, "_init_pyrit_memory", fake_init)
    monkeypatch.setattr(native, "_build_http_target", lambda url: object())

    async def fake_send(target, prompts, *, scenario):
        return [
            native._serialize_attack_result(
                scenario=scenario,
                objective=prompts[0],
                conversation_id="conv-1",
                transcript=[
                    {"role": "user", "content": prompts[0]},
                    {"role": "assistant", "content": "I cannot help with that."},
                ],
                outcome="undetermined",
                success=False,
                attack_type="PromptSendingAttack",
            )
        ]

    monkeypatch.setattr(native, "_send_via_prompt_sending_attack", fake_send)

    cfg = {
        "target": {"url": "https://llm.example.com/v1/chat"},
        "judge": {"mode": "none", "external_authorized": False},
    }
    out = tmp_path / "pyrit-results.json"
    cfg_path = tmp_path / "pyrit-run.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    rc = native.run_scenario(cfg_path, out, "crescendo")
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["scenario_engine"] == "pyrit-backed"
    assert doc["tool_version"] == "9.9.9"
    assert doc["preferred_attack_class"] == "CrescendoAttack"
    assert doc["attack_results"][0]["attack_type"] == "PromptSendingAttack"
    assert doc["attack_results"][0]["scenario_engine"] == "pyrit-backed"
    assert doc["external_judge_authorized"] is False


def test_egress_lockdown_sets_env(monkeypatch):
    monkeypatch.delenv("PYRIT_DISABLE_EXTERNAL_JUDGE", raising=False)
    monkeypatch.delenv("PYRIT_DISABLE_ADVERSARIAL_EGRESS", raising=False)
    ok = native._apply_egress_lockdown({"judge": {"external_authorized": False}})
    assert ok is False
    import os

    assert os.environ.get("PYRIT_DISABLE_EXTERNAL_JUDGE") == "1"
    assert os.environ.get("PYRIT_DISABLE_ADVERSARIAL_EGRESS") == "1"


def test_egress_authorized_skips_disable(monkeypatch):
    monkeypatch.delenv("PYRIT_DISABLE_EXTERNAL_JUDGE", raising=False)
    ok = native._apply_egress_lockdown({"judge": {"external_authorized": True}})
    assert ok is True
    import os

    assert os.environ.get("PYRIT_DISABLE_EXTERNAL_JUDGE") is None
