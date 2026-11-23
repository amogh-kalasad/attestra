"""Smoke-test the container PyRIT worker CLI without Docker."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

WORKER_ROOT = Path(__file__).resolve().parents[2] / "docker" / "aasi" / "pyrit_worker"


@pytest.fixture()
def worker_main(monkeypatch):
    monkeypatch.syspath_prepend(str(WORKER_ROOT))
    from attestra_pyrit_worker.__main__ import main  # type: ignore

    return main


def test_pyrit_worker_writes_results(tmp_path, worker_main, monkeypatch):
    # @lat: [[aasi#Phase 5 PyRIT adapter]]
    cfg = {
        "tool": "pyrit",
        "target": {"url": "http://127.0.0.1:9/v1/chat/completions"},
        "judge": {"mode": "none", "external_authorized": False},
    }
    config_path = tmp_path / "pyrit-run.json"
    out_path = tmp_path / "pyrit-results.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")

    # Force connection failure → report still written with outcome error.
    rc = worker_main(
        [
            "run",
            "--config",
            str(config_path),
            "--output",
            str(out_path),
            "--scenario",
            "crescendo",
        ]
    )
    assert rc == 1
    doc = json.loads(out_path.read_text(encoding="utf-8"))
    assert doc["tool"] == "pyrit"
    assert doc["scenario"] == "crescendo"
    assert isinstance(doc.get("attack_results"), list) and doc["attack_results"]
    assert doc["attack_results"][0]["outcome"] == "error"
