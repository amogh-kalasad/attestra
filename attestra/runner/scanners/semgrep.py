"""Semgrep adapter: SARIF output imported via sarif importer."""

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, CONTAINER_SRC, ScannerAdapter, which
from attestra.runner.scanners.trivy import _src_dir

# Registry rule pack; unlike "auto" it works with metrics turned off.
RULES = "p/default"


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"
    import_tool = "sarif"
    image_key = "semgrep"
    out_name = "semgrep-out.sarif"

    def available(self) -> bool:
        return which("semgrep") is not None

    def version(self) -> str:
        return "semgrep"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if isinstance(target, PinnedTarget):
            raise ValueError("semgrep expects a filesystem path")
        return ["semgrep", "scan", "--config", RULES, "--metrics", "off", "--sarif", "--output", str(out_file), str(target)]

    def docker_mounts(self, target, *, out_file: Path):
        if isinstance(target, PinnedTarget):
            raise ValueError("semgrep expects a filesystem path")
        return [(out_file.parent, CONTAINER_OUT, "rw"), (_src_dir(str(target)), CONTAINER_SRC, "ro")]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **_):
        return [
            "semgrep", "scan", "--config", RULES, "--metrics", "off", "--sarif",
            "--output", f"{CONTAINER_OUT}/{out_file.name}", CONTAINER_SRC,
        ]
