"""Prowler adapter: cloud/Kubernetes posture checks, JSON-OCSF output imported via prowler importer."""

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, which

PROVIDERS = ("aws", "azure", "gcp", "kubernetes")


class ProwlerAdapter(ScannerAdapter):
    name = "prowler"
    import_tool = "prowler"

    def available(self) -> bool:
        return which("prowler") is not None

    def version(self) -> str:
        return "prowler"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if isinstance(target, PinnedTarget):
            raise ValueError("prowler expects a cloud provider name, not a URL pin")
        provider = str(target).strip().lower()
        if provider not in PROVIDERS:
            raise ValueError(f"prowler provider must be one of {PROVIDERS}")
        return [
            "prowler",
            provider,
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            str(out_file.parent),
            "--output-filename",
            out_file.stem,
            "--no-banner",
        ]

    def resolve_output(self, out_file: Path) -> Path:
        # Prowler appends its own extension (e.g. <stem>.ocsf.json).
        if out_file.exists():
            return out_file
        matches = sorted(out_file.parent.glob(f"{out_file.stem}*.json"))
        return matches[0] if matches else out_file
