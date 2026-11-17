"""dnsx adapter: resolve candidate hostnames (A/AAAA/CNAME + rcode) (A-03).

DNS lookups go to resolvers, not to the hosts themselves. Input is a bounded host list
(max 500); rate-limited and retried once. Output becomes candidate resolution state only.
Image: ``ATTESTRA_IMAGE_DNSX`` (digest-pinned).
"""
# @lat: [[attack-surface-and-platform#Discovery adapters]]

from __future__ import annotations

import re
from pathlib import Path

from attestra.discovery.normalize import normalize_hostname
from attestra.runner.authorization import assert_safe_cli_arg
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, ScannerAdapter, which
from attestra.runner.scanners.sdk import AdapterMeta, ResourceProfile

RATE_LIMIT = 50  # DNS queries per second

MAX_HOSTS = 500


def hosts_from_target(target: PinnedTarget | str, *, max_hosts: int = MAX_HOSTS) -> list[str]:
    """A pinned target (its host) or a newline/comma separated host list, validated."""
    if isinstance(target, PinnedTarget):
        raw = [target.host]
    else:
        raw = [x for x in re.split(r"[\s,]+", str(target or "")) if x]
    hosts: list[str] = []
    for item in raw:
        h = normalize_hostname(item)
        if not h:
            raise ValueError(f"not a valid hostname: {item[:80]!r}")
        assert_safe_cli_arg(h)
        if h not in hosts:
            hosts.append(h)
    if not hosts:
        raise ValueError("no hosts given")
    if len(hosts) > max_hosts:
        raise ValueError(f"at most {max_hosts} hosts per run")
    return hosts


def write_host_list(out_file: Path, name: str, hosts: list[str]) -> Path:
    p = out_file.parent / f"{name}-hosts.txt"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    return p


def _flags(list_path: str, out_path: str) -> list[str]:
    return [
        "-l", list_path,
        "-a", "-aaaa", "-cname",
        "-resp",
        "-rcode", "noerror,nxdomain,servfail,refused",
        "-json",
        "-silent",
        "-o", out_path,
        "-rl", str(RATE_LIMIT),
        "-retry", "1",
        "-t", "10",
    ]


class DnsxAdapter(ScannerAdapter):
    name = "dnsx"
    import_tool = "dnsx"
    image_key = "dnsx"
    out_name = "dnsx-out.jsonl"
    empty_report_ok = True
    default_timeout_s = 600
    adapter_version = "1.0"
    meta = AdapterMeta(
        capabilities=("dns_resolution", "cname_chain"),
        asset_kinds=("domain", "web_app", "host"),
        safety_tier="T0",
        network_egress="third_party",
        resource_profile=ResourceProfile(cpu=0.5, mem_mb=256, timeout_s=600),
        licence="MIT",
        image_ref_env="ATTESTRA_IMAGE_DNSX",
        output_schema="dnsx-jsonl",
    )

    def available(self) -> bool:
        return which("dnsx") is not None

    def version(self) -> str:
        return "dnsx"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        lst = write_host_list(out_file, self.name, hosts_from_target(target))
        return ["dnsx", *_flags(str(lst), str(out_file))]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **_):
        lst = write_host_list(out_file, self.name, hosts_from_target(target))
        return _flags(f"{CONTAINER_OUT}/{lst.name}", f"{CONTAINER_OUT}/{out_file.name}")

    def validate_report(self, raw: bytes) -> str | None:
        from attestra.importers import dnsx as imp

        try:
            imp.parse(raw)
        except Exception as exc:  # noqa: BLE001
            return f"dnsx output could not be read: {exc}"[:500]
        return None
