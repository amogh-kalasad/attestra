"""testssl.sh adapter: TLS configuration against a pinned host, JSON imported via testssl importer."""

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, ScannerAdapter, which


def _flags(target: PinnedTarget, out_path: str) -> list[str]:
    return [
        "--quiet",
        "--warnings",
        "off",
        "--color",
        "0",
        "--ip",
        target.ip,  # connect only to the pinned, authorized address
        "--jsonfile",
        out_path,
        f"{target.host}:{target.port}",
    ]


class TlsTestsslAdapter(ScannerAdapter):
    name = "testssl"
    import_tool = "testssl"
    image_key = "testssl"

    def available(self) -> bool:
        return which("testssl.sh") is not None

    def version(self) -> str:
        return "testssl.sh"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("testssl needs a DNS-pinned target")
        return ["testssl.sh", *_flags(target, str(out_file))]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **_):
        if not isinstance(target, PinnedTarget):
            raise ValueError("testssl needs a DNS-pinned target")
        return _flags(target, f"{CONTAINER_OUT}/{out_file.name}")
