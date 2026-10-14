"""Gitleaks adapter: secrets in a repository path, redacted JSON imported via gitleaks importer."""

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, which


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"
    import_tool = "gitleaks"

    def available(self) -> bool:
        return which("gitleaks") is not None

    def version(self) -> str:
        return "gitleaks"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if isinstance(target, PinnedTarget):
            raise ValueError("gitleaks expects a filesystem path")
        return [
            "gitleaks",
            "detect",
            "--source",
            str(target),
            "--report-format",
            "json",
            "--report-path",
            str(out_file),
            "--redact",  # never write secret values to the report
            "--no-banner",
            "--exit-code",
            "0",
        ]
