"""SafeLabs safelabs-eval adapter: ASI heuristic eval against a pinned AI endpoint.

Runs in a digest-pinned Python container (light deps: pydantic/httpx/click). Detectors are
pattern-based; this adapter never upgrades findings — the safelabs importer maps hits to
potential. JSON is printed with ``--output json``; base ``scan`` persists stdout into the
host out dir bind-mounted at CONTAINER_OUT (/out).
"""
# @lat: [[aasi#Phase 2 SafeLabs adapter]]

from __future__ import annotations

from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, ScannerAdapter, which
from attestra.runner.scanners.sdk import AdapterMeta, ResourceProfile

_ASI_CATEGORIES = frozenset(f"ASI{i:02d}" for i in range(1, 11))
# Baseline: one category (faster). full/active: all 300 prompts.
_PROFILE_CATEGORY = {"baseline": "ASI01", "full": "all", "active": "all"}


def _category(profile: str, opts: dict) -> str:
    raw = opts.get("category")
    if raw is not None and str(raw).strip():
        c = str(raw).strip()
        if c.lower() == "all":
            return "all"
        u = c.upper()
        if u not in _ASI_CATEGORIES:
            raise ValueError("safelabs category must be 'all' or ASI01–ASI10")
        return u
    key = (profile or "baseline").lower()
    if key not in _PROFILE_CATEGORY:
        raise ValueError(f"safelabs profile must be one of {sorted(_PROFILE_CATEGORY)}")
    return _PROFILE_CATEGORY[key]


def _endpoint_path(opts: dict) -> str:
    path = str(opts.get("endpoint_path") or "/").strip() or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    # Refuse shell / path tricks in the URL we pass on argv.
    if any(ch in path for ch in ";|&`$() \n\r\t"):
        raise ValueError("safelabs endpoint_path contains unsafe characters")
    return path


def _target_url(target: PinnedTarget, *, endpoint_path: str) -> str:
    return f"{target.scheme}://{target.host_header}{endpoint_path}"


def _cli_args(target: PinnedTarget, *, profile: str, opts: dict) -> list[str]:
    url = _target_url(target, endpoint_path=_endpoint_path(opts))
    return [
        "run",
        "--target",
        url,
        "--category",
        _category(profile, opts),
        "--output",
        "json",
    ]


def container_report_path(out_file: Path | None = None) -> str:
    """Where the JSON report is expected on the container bind mount."""
    name = out_file.name if out_file is not None else SafeLabsAdapter.out_name
    return f"{CONTAINER_OUT}/{name}"


class SafeLabsAdapter(ScannerAdapter):
    """Digest-pinned safelabs-eval runner for ``ai_app`` targets."""

    name = "safelabs"
    import_tool = "safelabs"
    image_key = "safelabs"
    out_name = "safelabs-report.json"
    adapter_version = "0.1"
    # CLI ``--output json`` prints the report; scan() writes it under the /out mount.
    report_on_stdout = True
    docker_entrypoint = "safelabs"
    # Full ASI suite can take a while; override with ATTESTRA_SCANNER_TIMEOUT_SAFELABS.
    default_timeout_s = 3600
    meta = AdapterMeta(
        capabilities=("asi_heuristic_eval",),
        asset_kinds=("ai_app",),
        safety_tier="T2",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=1, mem_mb=512, timeout_s=3600),
        licence="Apache-2.0",
        image_ref_env="ATTESTRA_IMAGE_SAFELABS",
        output_schema="safelabs-json",
    )

    def available(self) -> bool:
        # Prefer the digest-pinned image; a host install is optional for local argv checks.
        return which("safelabs") is not None

    def version(self) -> str:
        return "safelabs-eval"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline", **opts) -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("safelabs needs a DNS-pinned target")
        return ["safelabs", *_cli_args(target, profile=profile, opts=opts)]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **opts) -> list[str]:
        """Invoke ``safelabs run … --output json``; report is persisted under ``CONTAINER_OUT``."""
        if not isinstance(target, PinnedTarget):
            raise ValueError("safelabs needs a DNS-pinned target")
        # Bind mount out_dir → CONTAINER_OUT; base.scan saves stdout to out_file there.
        if container_report_path(out_file) != f"{CONTAINER_OUT}/{self.out_name}":
            raise ValueError("safelabs docker report path must stay under CONTAINER_OUT")
        return _cli_args(target, profile=profile, opts=opts)
