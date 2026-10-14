"""Semgrep adapter — SARIF output imported via sarif importer."""

from __future__ import annotations

from pathlib import Path

from attestra import config
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, require_digest_image, which


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"
    import_tool = "sarif"

    def available(self) -> bool:
        return which("semgrep") is not None

    def version(self) -> str:
        return "semgrep"

    def image_ref(self) -> str:
        return require_digest_image(config.SCANNER_IMAGES["semgrep"])

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if isinstance(target, PinnedTarget):
            raise ValueError("semgrep expects a filesystem path")
        return [
            "semgrep",
            "scan",
            "--config",
            "auto",
            "--sarif",
            "--output",
            str(out_file),
            str(target),
        ]
