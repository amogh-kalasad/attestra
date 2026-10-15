"""naabu adapter: port discovery on the pinned address only, JSON Lines imported via naabu importer."""

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, ScannerAdapter, which

PROFILES = {"baseline": ["-top-ports", "100"], "full": ["-top-ports", "1000"]}
# The Queue scan form offers baseline / active; active maps to the wider port list.
PROFILE_ALIASES = {"active": "full"}


def _flags(target: PinnedTarget, profile: str, out_path: str) -> list[str]:
    profile = PROFILE_ALIASES.get(profile, profile)
    if profile not in PROFILES:
        raise ValueError(f"naabu profile must be one of {sorted(PROFILES)}")
    return [
        "-host",
        target.ip,  # scan only the pinned, authorized address
        *PROFILES[profile],
        "-rate",
        "100",
        "-json",
        "-silent",
        "-o",
        out_path,
    ]


class NaabuAdapter(ScannerAdapter):
    name = "naabu"
    import_tool = "naabu"
    image_key = "naabu"
    out_name = "naabu-out.jsonl"
    empty_report_ok = True  # no open ports found

    def available(self) -> bool:
        return which("naabu") is not None

    def version(self) -> str:
        return "naabu"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("naabu needs a DNS-pinned target")
        return ["naabu", *_flags(target, profile, str(out_file))]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **_):
        if not isinstance(target, PinnedTarget):
            raise ValueError("naabu needs a DNS-pinned target")
        # Connect scan: works through Docker Desktop's network without raw sockets.
        return [*_flags(target, profile, f"{CONTAINER_OUT}/{out_file.name}"), "-scan-type", "c"]
