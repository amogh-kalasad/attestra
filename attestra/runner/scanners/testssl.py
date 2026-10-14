"""testssl.sh adapter: TLS configuration against a pinned host, JSON imported via testssl importer."""

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, which


class TlsTestsslAdapter(ScannerAdapter):
    name = "testssl"
    import_tool = "testssl"

    def available(self) -> bool:
        return which("testssl.sh") is not None

    def version(self) -> str:
        return "testssl.sh"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("testssl needs a DNS-pinned target")
        return [
            "testssl.sh",
            "--quiet",
            "--warnings",
            "off",
            "--color",
            "0",
            "--ip",
            target.ip,  # connect only to the pinned, authorized address
            "--jsonfile",
            str(out_file),
            f"{target.host}:{target.port}",
        ]
