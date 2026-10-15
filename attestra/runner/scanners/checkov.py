"""Checkov adapter: IaC misconfiguration checks, JSON on stdout imported via checkov importer."""

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, CONTAINER_SRC, ScannerAdapter, which
from attestra.runner.scanners.trivy import _src_dir

FLAGS = ["--output", "json", "--compact", "--quiet", "--soft-fail"]


class CheckovAdapter(ScannerAdapter):
    name = "checkov"
    import_tool = "checkov"
    image_key = "checkov"
    report_on_stdout = True  # JSON goes to stdout; scan() saves it as the report
    empty_report_ok = True  # nothing to check in the folder

    def available(self) -> bool:
        return which("checkov") is not None

    def version(self) -> str:
        return "checkov"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if isinstance(target, PinnedTarget):
            raise ValueError("checkov expects a filesystem path")
        return ["checkov", "--directory", str(target), *FLAGS]

    def docker_mounts(self, target, *, out_file: Path):
        if isinstance(target, PinnedTarget):
            raise ValueError("checkov expects a filesystem path")
        return [(out_file.parent, CONTAINER_OUT, "rw"), (_src_dir(str(target)), CONTAINER_SRC, "ro")]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **_):
        return ["--directory", CONTAINER_SRC, *FLAGS, "--skip-download"]
