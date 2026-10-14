"""Tests for scanner adapter argv construction — no shell metacharacters."""
from __future__ import annotations

import re

import pytest

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.nuclei import NucleiAdapter
from attestra.runner.scanners.semgrep import SemgrepAdapter
from attestra.runner.scanners.trivy import TrivyAdapter
from attestra.runner.scanners.zap import ZapAdapter

_METACHAR = re.compile(r"[;|&`$]|\$\(|\n|\r")

DUMMY_PIN = PinnedTarget(host="shop.example.com", ip="93.184.216.34", port=443, scheme="https")
DUMMY_PATH = "services/payments"
DUMMY_IMAGE = "registry.example.com/shop/api:latest"


def _has_metachar(argv: list[str]) -> list[str]:
    return [a for a in argv if _METACHAR.search(a)]


# ---------------------------------------------------------------- trivy argv


def test_trivy_fs_argv_no_metacharacters(tmp_path):
    adapter = TrivyAdapter()
    argv = adapter.build_argv(DUMMY_PATH, out_file=tmp_path / "out.json")
    assert _has_metachar(argv) == []


def test_trivy_image_argv_no_metacharacters(tmp_path):
    adapter = TrivyAdapter()
    argv = adapter.build_argv(DUMMY_IMAGE, out_file=tmp_path / "out.json")
    assert _has_metachar(argv) == []


# ---------------------------------------------------------------- semgrep argv


def test_semgrep_argv_no_metacharacters(tmp_path):
    adapter = SemgrepAdapter()
    argv = adapter.build_argv(DUMMY_PATH, out_file=tmp_path / "out.sarif")
    assert _has_metachar(argv) == []


# ---------------------------------------------------------------- nuclei argv


def test_nuclei_argv_no_metacharacters(tmp_path):
    adapter = NucleiAdapter()
    argv = adapter.build_argv(DUMMY_PIN, out_file=tmp_path / "out.jsonl")
    assert _has_metachar(argv) == []


# ---------------------------------------------------------------- zap argv


def test_zap_argv_no_metacharacters(tmp_path):
    adapter = ZapAdapter()
    argv = adapter.build_argv(DUMMY_PIN, out_file=tmp_path / "out.json")
    assert _has_metachar(argv) == []


# ---------------------------------------------------------------- floating tag raises via require_digest_image


def test_require_digest_image_rejects_floating_tag():
    from attestra.runner.scanners.base import require_digest_image
    with pytest.raises(ValueError, match="@sha256:"):
        require_digest_image("zaproxy:latest")


def test_require_digest_image_allows_digest():
    from attestra.runner.scanners.base import require_digest_image
    img = "ghcr.io/zaproxy/zaproxy@sha256:" + "a" * 64
    result = require_digest_image(img)
    assert result == img


# ---------------------------------------------------------------- ZapAdapter.image_ref with floating tag raises


def test_zap_image_ref_floating_tag_raises(monkeypatch):
    import attestra.config as cfg
    monkeypatch.setitem(cfg.SCANNER_IMAGES, "zap", "zaproxy/zaproxy:latest")
    adapter = ZapAdapter()
    with pytest.raises(ValueError, match="@sha256:"):
        adapter.image_ref()


def test_nuclei_image_ref_floating_tag_raises(monkeypatch):
    import attestra.config as cfg
    monkeypatch.setitem(cfg.SCANNER_IMAGES, "nuclei", "projectdiscovery/nuclei:latest")
    adapter = NucleiAdapter()
    with pytest.raises(ValueError, match="@sha256:"):
        adapter.image_ref()
