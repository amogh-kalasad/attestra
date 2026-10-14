"""Checkov adapter: IaC misconfiguration checks, JSON on stdout imported via checkov importer."""

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, which


class CheckovAdapter(ScannerAdapter):
    name = "checkov"
    import_tool = "checkov"

    def available(self) -> bool:
        return which("checkov") is not None

    def version(self) -> str:
        return "checkov"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if isinstance(target, PinnedTarget):
            raise ValueError("checkov expects a filesystem path")
        # JSON goes to stdout; ScannerAdapter.scan saves stdout when no file is written.
        return ["checkov", "--directory", str(target), "--output", "json", "--compact", "--quiet", "--soft-fail"]
