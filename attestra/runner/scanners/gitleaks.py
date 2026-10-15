"""Gitleaks adapter: secrets in a repository path, redacted JSON imported via gitleaks importer."""

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, CONTAINER_SRC, ScannerAdapter, which
from attestra.runner.scanners.trivy import _src_dir


def _flags(source: str, report: str) -> list[str]:
    return [
        "detect",
        "--source",
        source,
        "--report-format",
        "json",
        "--report-path",
        report,
        "--redact",  # never write secret values to the report
        "--no-banner",
        "--exit-code",
        "0",
    ]


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"
    import_tool = "gitleaks"
    image_key = "gitleaks"

    def available(self) -> bool:
        return which("gitleaks") is not None

    def version(self) -> str:
        return "gitleaks"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if isinstance(target, PinnedTarget):
            raise ValueError("gitleaks expects a filesystem path")
        return ["gitleaks", *_flags(str(target), str(out_file))]

    def docker_mounts(self, target, *, out_file: Path):
        if isinstance(target, PinnedTarget):
            raise ValueError("gitleaks expects a filesystem path")
        return [(out_file.parent, CONTAINER_OUT, "rw"), (_src_dir(str(target)), CONTAINER_SRC, "ro")]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **_):
        # --no-git: scan the files as they are (the mounted folder need not be a git checkout).
        return [*_flags(CONTAINER_SRC, f"{CONTAINER_OUT}/{out_file.name}"), "--no-git"]
