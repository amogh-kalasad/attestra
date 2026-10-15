"""Nuclei adapter: JSONL output imported via the nuclei importer.

Runs the digest-pinned nuclei image when configured (templates cached under the scanner cache
folder), else a local ``nuclei`` binary. Baseline excludes intrusive / DoS / fuzz / brute-force
templates and never uses out-of-band (interactsh) callbacks.
"""

from __future__ import annotations

from pathlib import Path

from attestra import config
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, ScannerAdapter, which
from attestra.runner.scanners.nuclei_policy import excluded_tags, templates_allowed

RATE_LIMIT = "50"


def _url(target: PinnedTarget | str) -> str:
    if isinstance(target, PinnedTarget):
        return f"{target.scheme}://{target.host_header}/"
    return str(target)


def nuclei_flags(target, *, out_path: str, profile: str, intrusive_allowed: bool) -> list[str]:
    tags = templates_allowed(profile=profile, intrusive_allowed=intrusive_allowed)
    return [
        "-u",
        _url(target),
        "-jsonl",
        "-o",
        out_path,
        "-tags",
        tags[0],
        "-etags",
        excluded_tags(profile=profile),
        "-ni",  # no interactsh: never send data to out-of-band servers
        "-rl",
        RATE_LIMIT,
        "-silent",
        "-nc",
    ]


class NucleiAdapter(ScannerAdapter):
    name = "nuclei"
    import_tool = "nuclei"
    image_key = "nuclei"
    out_name = "nuclei-out.jsonl"
    empty_report_ok = True  # nuclei writes nothing when no template matched
    # The first run downloads the template library; a full baseline sends about 13,000 requests.
    default_timeout_s = 1800

    def available(self) -> bool:
        return which("nuclei") is not None

    def version(self) -> str:
        return "nuclei"

    def build_argv(
        self,
        target: PinnedTarget | str,
        *,
        out_file: Path,
        profile: str = "baseline",
        intrusive_allowed: bool = False,
    ) -> list[str]:
        return ["nuclei", *nuclei_flags(target, out_path=str(out_file), profile=profile, intrusive_allowed=intrusive_allowed)]

    def docker_mounts(self, target, *, out_file: Path):
        cache = config.SCANNER_CACHE_DIR / "nuclei"
        (cache / "templates").mkdir(parents=True, exist_ok=True)
        (cache / "config").mkdir(parents=True, exist_ok=True)
        return [
            (out_file.parent, CONTAINER_OUT, "rw"),
            (cache / "templates", "/root/nuclei-templates", "rw"),
            (cache / "config", "/root/.config/nuclei", "rw"),
        ]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", intrusive_allowed: bool = False, **_):
        return nuclei_flags(
            target, out_path=f"{CONTAINER_OUT}/{out_file.name}", profile=profile, intrusive_allowed=intrusive_allowed
        )

    def scan(self, pin, *, out_dir, cancel=None, profile="baseline", intrusive_allowed=False):  # type: ignore[override]
        return super().scan(pin, out_dir=out_dir, cancel=cancel, profile=profile, intrusive_allowed=intrusive_allowed)
