"""httpx (ProjectDiscovery) probe adapter: status/title/tech/CDN for hosts (A-04).

This one *does* send HTTP requests to the hosts, so it is tier T1 (read-only GET, no
redirect following, no path brute force) and must only be queued for hosts that are
approved, in-scope assets (the dispatch gate enforces that for every scan). Requests are
bounded: max 500 hosts, 5 req/s, 10 s timeout, no retries.

The binary is looked up as ``ATTESTRA_HTTPX_BIN`` or ``httpx-toolkit`` — never plain
``httpx``, which on most Python installs is the unrelated httpx client CLI. Image:
``ATTESTRA_IMAGE_HTTPX`` (digest-pinned).
"""
# @lat: [[attack-surface-and-platform#Discovery adapters]]

from __future__ import annotations

import os
from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, ScannerAdapter, which
from attestra.runner.scanners.dnsx import hosts_from_target, write_host_list
from attestra.runner.scanners.sdk import AdapterMeta, ResourceProfile

RATE_LIMIT = 5
DEFAULT_BIN = "httpx-toolkit"


def binary() -> str:
    return (os.environ.get("ATTESTRA_HTTPX_BIN") or DEFAULT_BIN).strip()


def _flags(list_path: str, out_path: str) -> list[str]:
    return [
        "-l", list_path,
        "-json",
        "-silent",
        "-o", out_path,
        "-status-code", "-title", "-tech-detect", "-web-server", "-cdn",
        "-rl", str(RATE_LIMIT),
        "-t", "5",
        "-timeout", "10",
        "-retries", "0",
        "-no-fallback-scheme",
        "-disable-update-check",
    ]


class HttpxProbeAdapter(ScannerAdapter):
    name = "httpx_probe"
    import_tool = "httpx_probe"
    image_key = "httpx"
    out_name = "httpx-out.jsonl"
    empty_report_ok = True
    default_timeout_s = 900
    adapter_version = "1.0"
    meta = AdapterMeta(
        capabilities=("http_probe", "tech_fingerprint", "cdn_detect"),
        asset_kinds=("web_app", "api", "host"),
        safety_tier="T1",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=0.5, mem_mb=256, timeout_s=900),
        licence="MIT",
        image_ref_env="ATTESTRA_IMAGE_HTTPX",
        output_schema="httpx-jsonl",
    )

    def available(self) -> bool:
        b = binary()
        return bool(b) and b != "httpx" and which(b) is not None

    def version(self) -> str:
        return "httpx (projectdiscovery)"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        lst = write_host_list(out_file, self.name, hosts_from_target(target))
        return [binary(), *_flags(str(lst), str(out_file))]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **_):
        lst = write_host_list(out_file, self.name, hosts_from_target(target))
        return _flags(f"{CONTAINER_OUT}/{lst.name}", f"{CONTAINER_OUT}/{out_file.name}")

    def validate_report(self, raw: bytes) -> str | None:
        from attestra.importers import httpx_probe as imp

        try:
            imp.parse(raw)
        except Exception as exc:  # noqa: BLE001
            return f"httpx output could not be read: {exc}"[:500]
        return None
