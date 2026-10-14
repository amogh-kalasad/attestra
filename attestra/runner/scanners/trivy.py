"""Trivy adapter — filesystem/image scans; output imported via trivy importer."""

from __future__ import annotations

from pathlib import Path

from attestra import config
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, require_digest_image, which


class TrivyAdapter(ScannerAdapter):
    name = "trivy"
    import_tool = "trivy"

    def available(self) -> bool:
        return which("trivy") is not None

    def version(self) -> str:
        return "trivy"

    def image_ref(self) -> str:
        return require_digest_image(config.SCANNER_IMAGES["trivy"])

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        # Path / image string targets for fs and image modes
        if isinstance(target, PinnedTarget):
            raise ValueError("trivy fs/image adapters expect a path or image string, not a URL pin")
        target_s = str(target)
        mode = "image" if "/" in target_s and not Path(target_s).exists() and ":" in target_s.split("/")[-1] else "fs"
        # Prefer local binary; argv never uses shell.
        return [
            "trivy",
            mode,
            "--format",
            "json",
            "--output",
            str(out_file),
            "--quiet",
            target_s,
        ]
