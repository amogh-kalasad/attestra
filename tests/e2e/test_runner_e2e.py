"""End-to-end integration tests for the runner — skipped unless tools present."""
from __future__ import annotations

import shutil

import pytest


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# ---------------------------------------------------------------- trivy e2e


@pytest.mark.integration
@pytest.mark.skipif(not _tool_available("trivy"), reason="trivy not installed")
def test_trivy_scans_path(tmp_path, engagement):
    """Minimal e2e: trivy fs scan on a temp directory produces output."""
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset
    from attestra.runner.scanners.trivy import TrivyAdapter

    # Create a dummy file to scan
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.18\n")

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "repo")
        ).first()
        assert asset

    adapter = TrivyAdapter()
    out_dir = tmp_path / "out"
    result = adapter.scan(str(tmp_path), out_dir=out_dir)
    assert result.raw_path is not None or result.extra.get("returncode") is not None


# ---------------------------------------------------------------- nuclei e2e


@pytest.mark.integration
@pytest.mark.skipif(not _tool_available("nuclei"), reason="nuclei not installed")
def test_nuclei_scans_localhost(tmp_path, engagement):
    """Minimal nuclei scan stub — just checks adapter builds valid argv."""
    from attestra.runner.dns_pin import PinnedTarget
    from attestra.runner.scanners.nuclei import NucleiAdapter

    pin = PinnedTarget(host="127.0.0.1", ip="127.0.0.1", port=8080, scheme="http")
    adapter = NucleiAdapter()
    argv = adapter.build_argv(pin, out_file=tmp_path / "out.jsonl")
    assert "nuclei" in argv[0]
    assert "-u" in argv
