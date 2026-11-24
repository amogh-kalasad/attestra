"""Dependency checks, health_report, manifests, and process wrapper (mocked; no Docker)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from attestra.runner.scanners.base import ProcessResult
from attestra.scanner_runtime.dependency_check import (
    check_all,
    check_node,
    check_promptfoo,
    check_python_package,
)
from attestra.scanner_runtime.environment import resolve_shared_env
from attestra.scanner_runtime.health import health_report
from attestra.scanner_runtime.manifest import (
    ManifestError,
    list_manifests,
    read_manifest,
    write_manifest,
)
from attestra.scanner_runtime.process import run_with_shared_env


@pytest.fixture
def shared_root(tmp_path: Path):
    root = tmp_path / ".attestra-runtime"
    env = resolve_shared_env(root=root, create=True)
    env.venv_bin.mkdir(parents=True, exist_ok=True)
    env.python.write_text("", encoding="utf-8")
    (env.tools_node).mkdir(parents=True, exist_ok=True)
    node_name = "node.exe" if env.node.name.endswith(".exe") else "node"
    (env.tools_node / node_name).write_text("", encoding="utf-8")
    cli = env.promptfoo
    cli.parent.mkdir(parents=True, exist_ok=True)
    cli.write_text("", encoding="utf-8")
    return env


def test_check_python_package_uses_shared_interpreter(shared_root, monkeypatch):
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        out = MagicMock()
        out.returncode = 0
        out.stdout = json.dumps({"version": "0.17.1"})
        out.stderr = ""
        return out

    monkeypatch.setattr(
        "attestra.scanner_runtime.dependency_check.subprocess.run",
        fake_run,
    )
    status = check_python_package("garak", env=shared_root)
    assert status.ok is True
    assert status.installed == "0.17.1"
    assert status.expected == "0.17.1"
    assert calls and str(shared_root.python) == calls[0][0]
    assert "-c" in calls[0]
    assert "garak" in calls[0]


def test_check_python_package_version_mismatch(shared_root, monkeypatch):
    def fake_run(argv, **kwargs):
        out = MagicMock()
        out.returncode = 0
        out.stdout = json.dumps({"version": "0.16.0"})
        out.stderr = ""
        return out

    monkeypatch.setattr(
        "attestra.scanner_runtime.dependency_check.subprocess.run",
        fake_run,
    )
    status = check_python_package("garak", env=shared_root)
    assert status.ok is False
    assert status.installed == "0.16.0"


def test_check_node_and_promptfoo(shared_root, monkeypatch):
    def fake_run(argv, **kwargs):
        out = MagicMock()
        out.returncode = 0
        out.stderr = ""
        if "node" in Path(argv[0]).name.lower():
            out.stdout = "v20.11.1\n"
        else:
            out.stdout = "0.118.5\n"
        return out

    monkeypatch.setattr(
        "attestra.scanner_runtime.dependency_check.subprocess.run",
        fake_run,
    )
    node = check_node(env=shared_root)
    assert node.ok and node.installed == "20.11.1"
    pf = check_promptfoo(env=shared_root)
    assert pf.ok and pf.installed == "0.118.5"


def test_check_all_keys(shared_root, monkeypatch):
    def fake_run(argv, **kwargs):
        out = MagicMock()
        out.returncode = 0
        out.stderr = ""
        name = Path(argv[0]).name.lower()
        if "node" in name:
            out.stdout = "v20.0.0\n"
        elif "promptfoo" in name:
            out.stdout = "0.118.0\n"
        else:
            # shared python -c metadata
            pkg = argv[-1]
            pins = {
                "garak": "0.17.1",
                "safelabs-eval": "0.12.0",
                "pyrit": "1.2.1",
            }
            out.stdout = json.dumps({"version": pins.get(pkg)})
        return out

    monkeypatch.setattr(
        "attestra.scanner_runtime.dependency_check.subprocess.run",
        fake_run,
    )
    results = check_all(env=shared_root)
    assert set(results) >= {"garak", "safelabs-eval", "pyrit", "node", "promptfoo"}
    assert all(r.ok for r in results.values())


def test_health_report_no_docker(shared_root, monkeypatch):
    def fake_run(argv, **kwargs):
        out = MagicMock()
        out.returncode = 0
        out.stderr = ""
        name = Path(argv[0]).name.lower()
        if "node" in name:
            out.stdout = "v20.5.0\n"
        elif "promptfoo" in name:
            out.stdout = "0.118.9\n"
        else:
            pkg = argv[-1]
            pins = {"garak": "0.17.1", "safelabs-eval": "0.12.0", "pyrit": "1.2.1"}
            out.stdout = json.dumps({"version": pins.get(pkg)})
        return out

    monkeypatch.setattr(
        "attestra.scanner_runtime.dependency_check.subprocess.run",
        fake_run,
    )
    report = health_report(env=shared_root)
    assert report["docker"] is False
    assert report["ready"] is True
    assert set(report["scanners"]) == {"garak", "safelabs", "pyrit", "promptfoo"}
    assert all(s["docker"] is False for s in report["scanners"].values())
    assert report["scanners"]["safelabs"]["package"] == "safelabs-eval"
    assert report["scanners"]["promptfoo"]["runtime"] == "shared-npm"


def test_health_report_flags_extra_venv(shared_root):
    (shared_root.root / "venv-pyrit").mkdir()
    report = health_report(env=shared_root)
    assert report["extra_venvs"]["ok"] is False
    assert report["ready"] is False
    assert report["docker"] is False


def test_manifest_roundtrip(shared_root):
    path = write_manifest(
        "install",
        {"garak": "0.17.1", "promptfoo": "0.118.5"},
        env=shared_root,
    )
    assert path.parent == shared_root.manifests
    data = read_manifest("install", env=shared_root)
    assert data["garak"] == "0.17.1"
    assert "written_at" in data
    assert list_manifests(env=shared_root) == ["install"]
    with pytest.raises(ManifestError, match="unsafe"):
        write_manifest("../evil", {}, env=shared_root)
    with pytest.raises(ManifestError, match="not found"):
        read_manifest("missing", env=shared_root)


def test_run_with_shared_env_delegates(shared_root, monkeypatch):
    captured: dict = {}

    def fake_run_process(argv, *, timeout=None, cancel=None, cwd=None, env=None):
        captured["argv"] = argv
        captured["env"] = env
        return ProcessResult(returncode=0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr(
        "attestra.scanner_runtime.process.run_process",
        fake_run_process,
    )
    result = run_with_shared_env(["garak", "--help"], env=shared_root)
    assert result.returncode == 0
    assert captured["argv"] == ["garak", "--help"]
    assert captured["env"]["VIRTUAL_ENV"] == str(shared_root.venv)
    assert captured["env"]["ATTESTRA_SHARED_ENV_ROOT"] == str(shared_root.root)
    assert captured["env"]["ATTESTRA_SCANNER_JOB"] == "1"
    assert "ATTESTRA_AI_SCANNER_DOCKER" not in captured["env"]
    assert "AWS_SECRET_ACCESS_KEY" not in captured["env"]
