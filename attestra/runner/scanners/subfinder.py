"""subfinder adapter: passive subdomain enumeration for an in-scope apex (A-02).

Passive only: subfinder queries public aggregators (CT logs, archives, DNS datasets) and
never contacts the target. No provider API keys are used: the run points subfinder at an
empty provider config inside the run folder, so keys in a user's home config are never
read. Output (JSON lines) becomes discovery candidates only. Rate and time are bounded.
Off unless discovery is enabled, and the image must be digest-pinned
(``ATTESTRA_IMAGE_SUBFINDER``).
"""
# @lat: [[attack-surface-and-platform#Discovery adapters]]

from __future__ import annotations

from pathlib import Path

from attestra.discovery.normalize import normalize_hostname
from attestra.runner.authorization import assert_safe_cli_arg
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, ScannerAdapter, which
from attestra.runner.scanners.sdk import AdapterMeta, ResourceProfile

MAX_TIME_MIN = 10  # subfinder -max-time (minutes)
RATE_LIMIT = 10  # requests per second across sources
EMPTY_PROVIDER_CONFIG = "subfinder-provider-config.yaml"


def apex_arg(target: PinnedTarget | str) -> str:
    if isinstance(target, PinnedTarget):
        raise ValueError("subfinder takes an apex domain, not a pinned URL")
    apex = normalize_hostname(str(target))
    if not apex:
        raise ValueError("subfinder needs a valid apex domain")
    return assert_safe_cli_arg(apex)


def _flags(apex: str, out_path: str, provider_config: str) -> list[str]:
    return [
        "-d", apex,
        "-silent",
        "-json",
        "-o", out_path,
        "-pc", provider_config,  # empty file: no API keys, ever
        "-timeout", "30",
        "-max-time", str(MAX_TIME_MIN),
        "-rl", str(RATE_LIMIT),
        "-t", "5",
    ]


class SubfinderAdapter(ScannerAdapter):
    name = "subfinder"
    import_tool = "subfinder"
    image_key = "subfinder"
    out_name = "subfinder-out.jsonl"
    empty_report_ok = True
    default_timeout_s = MAX_TIME_MIN * 60 + 120
    adapter_version = "1.0"
    meta = AdapterMeta(
        capabilities=("subdomain_enum_passive",),
        asset_kinds=("domain", "web_app", "host"),
        safety_tier="T0",
        network_egress="third_party",
        resource_profile=ResourceProfile(cpu=0.5, mem_mb=256, timeout_s=MAX_TIME_MIN * 60 + 120),
        licence="MIT",
        image_ref_env="ATTESTRA_IMAGE_SUBFINDER",
        output_schema="subfinder-jsonl",
    )

    def available(self) -> bool:
        return which("subfinder") is not None

    def version(self) -> str:
        return "subfinder"

    def _provider_config(self, out_file: Path) -> Path:
        p = out_file.parent / EMPTY_PROVIDER_CONFIG
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("# intentionally empty: Attestra never uses provider API keys\n", encoding="utf-8")
        return p

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline") -> list[str]:
        apex = apex_arg(target)
        pc = self._provider_config(out_file)
        return ["subfinder", *_flags(apex, str(out_file), str(pc))]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **_):
        apex = apex_arg(target)
        self._provider_config(out_file)
        return _flags(apex, f"{CONTAINER_OUT}/{out_file.name}", f"{CONTAINER_OUT}/{EMPTY_PROVIDER_CONFIG}")

    def validate_report(self, raw: bytes) -> str | None:
        from attestra.importers import subfinder as imp

        try:
            imp.parse(raw)
        except Exception as exc:  # noqa: BLE001
            return f"subfinder output could not be read: {exc}"[:500]
        return None
