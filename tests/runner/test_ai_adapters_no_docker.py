"""AASI V5.1: adapters with allows_docker=False never use Docker even when an image is set."""
# @lat: [[tests#AASI V5.1 no Docker for AI adapters]]

from __future__ import annotations

from pathlib import Path

import pytest

from attestra.runner.scanners.base import ScannerAdapter


class _FakeNativeAdapter(ScannerAdapter):
    name = "fake_ai"
    import_tool = "garak"
    image_key = "garak"
    allows_docker = False

    def available(self) -> bool:
        return False

    def version(self) -> str:
        return "fake-ai 0"

    def build_argv(self, target, *, out_file: Path, profile: str = "baseline") -> list[str]:
        return ["fake-ai", "--out", str(out_file)]


@pytest.fixture
def fake_digest_image(monkeypatch):
    """A non-placeholder digest so image_configured() would otherwise be true."""
    digest = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    image = f"attestra/fake-ai@sha256:{digest}"
    monkeypatch.setitem(__import__("attestra.config", fromlist=["SCANNER_IMAGES"]).SCANNER_IMAGES, "garak", image)
    return image


# @lat: [[tests#AASI V5.1 no Docker for AI adapters#Fake native adapter ignores image env]]
def test_allows_docker_false_never_uses_docker_even_with_image(fake_digest_image, monkeypatch):
    import attestra.runner.scanners.base as base

    monkeypatch.setattr(base, "docker_available", lambda: True)
    adapter = _FakeNativeAdapter()
    assert adapter.image_configured() is True
    assert adapter.allows_docker is False
    assert adapter.uses_docker() is False


# @lat: [[tests#AASI V5.1 no Docker for AI adapters#Unavailable reason points at shared env]]
def test_allows_docker_false_unavailable_reason_points_at_shared_env(fake_digest_image, monkeypatch):
    import attestra.runner.scanners.base as base
    from attestra import config

    monkeypatch.setattr(base, "docker_available", lambda: True)
    monkeypatch.setattr(config, "SHARED_ENV_ROOT", "")
    adapter = _FakeNativeAdapter()
    reason = adapter.unavailable_reason()
    assert "ATTESTRA_SHARED_ENV_ROOT" in reason
    assert "not used" in reason.lower()
    assert "ATTESTRA_IMAGE_" not in reason
    assert "Docker Desktop" not in reason
    assert str(config.shared_env_root()) in reason


def test_allows_docker_true_still_uses_docker_when_image_set(fake_digest_image, monkeypatch):
    import attestra.runner.scanners.base as base

    class _DockerOk(_FakeNativeAdapter):
        allows_docker = True

    monkeypatch.setattr(base, "docker_available", lambda: True)
    assert _DockerOk().uses_docker() is True


# @lat: [[tests#AASI V5.1 no Docker for AI adapters#Shared env root default]]
def test_shared_env_root_defaults_to_attestra_runtime(monkeypatch, tmp_path):
    from attestra import config

    monkeypatch.setattr(config, "SHARED_ENV_ROOT", "")
    monkeypatch.chdir(tmp_path)
    root = config.shared_env_root()
    assert root == (tmp_path / ".attestra-runtime").resolve()
