"""AASI V5.1 shared environment resolution and layout (no Docker)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from attestra.scanner_runtime.environment import (
    ENV_ROOT_VAR,
    ExtraVenvError,
    SharedEnvError,
    reject_extra_venvs,
    require_promptfoo,
    require_python,
    resolve_shared_env,
    shared_python,
)
from attestra.scanner_runtime.versions import SUPPORTED, version_matches


def _touch_python(env_root: Path) -> Path:
    env = resolve_shared_env(root=env_root, create=True)
    env.venv_bin.mkdir(parents=True, exist_ok=True)
    py = env.python
    py.write_text("", encoding="utf-8")
    return py


def _touch_promptfoo(env_root: Path) -> Path:
    env = resolve_shared_env(root=env_root, create=True)
    cli = env.promptfoo
    cli.parent.mkdir(parents=True, exist_ok=True)
    cli.write_text("", encoding="utf-8")
    return cli


def test_supported_pins():
    assert SUPPORTED["garak"] == "0.17.1"
    assert SUPPORTED["safelabs-eval"] == "0.12.0"
    assert SUPPORTED["pyrit"] == "1.2.1"
    assert SUPPORTED["promptfoo"] == "~0.118.x"
    assert SUPPORTED["node"] == "20.x"
    assert version_matches("0.17.1", "0.17.1")
    assert version_matches("0.118.7", "~0.118.x")
    assert version_matches("v20.11.1", "20.x")
    assert not version_matches("0.119.0", "~0.118.x")
    assert not version_matches("18.20.0", "20.x")


def test_resolve_uses_env_var_and_layout(tmp_path: Path, monkeypatch):
    root = tmp_path / "runtime"
    monkeypatch.setenv(ENV_ROOT_VAR, str(root))
    env = resolve_shared_env(create=True)
    assert env.root == root.resolve()
    for rel in ("venv", "tools/node", "npm", "manifests", "logs", "cache", "tmp"):
        assert (env.root / rel).is_dir()
    if sys.platform == "win32":
        assert env.python.name == "python.exe"
        assert env.python.parent.name == "Scripts"
    else:
        assert env.python.name == "python"
        assert env.python.parent.name == "bin"


def test_resolve_explicit_root_overrides_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv(ENV_ROOT_VAR, str(tmp_path / "from-env"))
    other = tmp_path / "explicit"
    env = resolve_shared_env(root=other, create=True)
    assert env.root == other.resolve()


def test_require_python_and_promptfoo(tmp_path: Path):
    empty = resolve_shared_env(root=tmp_path / "empty", create=True)
    assert shared_python(empty) is None
    with pytest.raises(SharedEnvError, match="shared venv Python"):
        require_python(empty)
    py = _touch_python(tmp_path / "ok")
    ok = resolve_shared_env(root=tmp_path / "ok")
    assert require_python(ok) == py
    assert shared_python(ok) == str(py)

    with pytest.raises(SharedEnvError, match="promptfoo"):
        require_promptfoo(ok)
    cli = _touch_promptfoo(tmp_path / "ok")
    assert require_promptfoo(ok) == cli


def test_reject_extra_and_per_scanner_venvs(tmp_path: Path):
    root = tmp_path / "runtime"
    env = resolve_shared_env(root=root, create=True)
    # Allowed shared venv alone is fine.
    reject_extra_venvs(shared=env, search_roots=[root])

    bad = root / "venv-garak"
    bad.mkdir()
    with pytest.raises(ExtraVenvError, match="venv-garak"):
        reject_extra_venvs(shared=env, search_roots=[root])

    bad.rmdir()
    extra = root / "tools" / ".venv"
    extra.mkdir(parents=True)
    with pytest.raises(ExtraVenvError, match="\\.venv"):
        reject_extra_venvs(shared=env, search_roots=[root])


def test_process_env_sanitizes_path(tmp_path: Path, monkeypatch):
    root = tmp_path / "runtime"
    env = resolve_shared_env(root=root, create=True)
    env.venv_bin.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("PATH", str(tmp_path / "other-bin"))
    monkeypatch.setenv("ATTESTRA_AI_SCANNER_DOCKER", "1")
    merged = env.process_env()
    assert merged["VIRTUAL_ENV"] == str(env.venv)
    assert merged["ATTESTRA_SHARED_ENV_ROOT"] == str(env.root)
    assert "ATTESTRA_AI_SCANNER_DOCKER" not in merged
    assert str(env.venv_bin) in merged["PATH"].split(os.pathsep)
