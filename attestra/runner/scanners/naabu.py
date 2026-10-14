"""naabu adapter: port discovery on the pinned address only, JSON Lines imported via naabu importer."""

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, which

PROFILES = {"baseline": ["-top-ports", "100"], "full": ["-top-ports", "1000"]}


class NaabuAdapter(ScannerAdapter):
    name = "naabu"
    import_tool = "naabu"

    def available(self) -> bool:
        return which("naabu") is not None

    def version(self) -> str:
        return "naabu"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("naabu needs a DNS-pinned target")
        if profile not in PROFILES:
            raise ValueError(f"naabu profile must be one of {sorted(PROFILES)}")
        return [
            "naabu",
            "-host",
            target.ip,  # scan only the pinned, authorized address
            *PROFILES[profile],
            "-rate",
            "100",
            "-json",
            "-silent",
            "-o",
            str(out_file),
        ]
