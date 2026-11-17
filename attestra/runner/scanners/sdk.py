"""Scanner adapter SDK: metadata, defaults for the existing adapters, contract checks (L-01/L-02).

A new adapter is a :class:`~attestra.runner.scanners.base.ScannerAdapter` subclass with a
``meta = AdapterMeta(...)`` class attribute, an importer, and one registry line (INT). The
orchestration core does not change. ``scripts/new_adapter.py`` scaffolds all three plus a
contract test.

The metadata for the 11 adapters that predate the SDK lives here in :data:`DEFAULT_META`
so their modules stay untouched (``semgrep.py`` belongs to another work package).

Safety tiers follow PHASE2 §6: ``T0`` passive / offline, ``T1`` read-only network,
``T2`` active but non-destructive (needs target-environment policy), ``T3`` lab only.
"""
# @lat: [[attack-surface-and-platform#Adapter SDK]]

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SAFETY_TIERS = ("T0", "T1", "T2", "T3")
EGRESS = ("none", "target", "third_party", "cloud_api")
SDK_VERSION = "1"


@dataclass(frozen=True)
class ResourceProfile:
    cpu: float = 1.0
    mem_mb: int = 512
    timeout_s: int = 1800


@dataclass(frozen=True)
class AdapterMeta:
    capabilities: tuple[str, ...]
    asset_kinds: tuple[str, ...]
    safety_tier: str = "T1"
    auth_required: bool = False
    network_egress: str = "target"
    resource_profile: ResourceProfile = field(default_factory=ResourceProfile)
    licence: str = ""
    image_ref_env: str = ""
    output_schema: str = ""
    version: str = "1.0"

    def problems(self) -> list[str]:
        out: list[str] = []
        if not self.capabilities:
            out.append("capabilities empty")
        if not self.asset_kinds:
            out.append("asset_kinds empty")
        if self.safety_tier not in SAFETY_TIERS:
            out.append(f"safety_tier {self.safety_tier!r} not in {SAFETY_TIERS}")
        if self.network_egress not in EGRESS:
            out.append(f"network_egress {self.network_egress!r} not in {EGRESS}")
        if self.image_ref_env and not re.fullmatch(r"ATTESTRA_IMAGE_[A-Z0-9_]+", self.image_ref_env):
            out.append("image_ref_env must look like ATTESTRA_IMAGE_<TOOL>")
        if not self.licence:
            out.append("licence missing")
        if not self.output_schema:
            out.append("output_schema missing")
        rp = self.resource_profile
        if rp.timeout_s <= 0 or rp.mem_mb <= 0 or rp.cpu <= 0:
            out.append("resource_profile must be positive")
        return out

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


_WEB = ("web_app", "api", "host")

DEFAULT_META: dict[str, AdapterMeta] = {
    "trivy": AdapterMeta(
        capabilities=("sca", "container_vuln", "iac_misconfig"),
        asset_kinds=("repo", "image"),
        safety_tier="T0",
        network_egress="third_party",  # vulnerability DB download
        resource_profile=ResourceProfile(cpu=1, mem_mb=1024, timeout_s=1800),
        licence="Apache-2.0",
        image_ref_env="ATTESTRA_IMAGE_TRIVY",
        output_schema="trivy-json",
    ),
    "semgrep": AdapterMeta(
        capabilities=("sast",),
        asset_kinds=("repo",),
        safety_tier="T0",
        network_egress="none",
        resource_profile=ResourceProfile(cpu=1, mem_mb=1024, timeout_s=1800),
        licence="LGPL-2.1",
        image_ref_env="ATTESTRA_IMAGE_SEMGREP",
        output_schema="sarif-2.1.0",
    ),
    "nuclei": AdapterMeta(
        capabilities=("dast_templates", "exposure", "misconfig"),
        asset_kinds=_WEB,
        safety_tier="T2",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=1, mem_mb=1024, timeout_s=7200),
        licence="MIT",
        image_ref_env="ATTESTRA_IMAGE_NUCLEI",
        output_schema="nuclei-jsonl",
    ),
    "zap": AdapterMeta(
        capabilities=("dast", "spider", "passive_scan"),
        asset_kinds=("web_app", "api"),
        safety_tier="T2",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=2, mem_mb=2048, timeout_s=1800),
        licence="Apache-2.0",
        image_ref_env="ATTESTRA_IMAGE_ZAP",
        output_schema="zap-json",
    ),
    "prowler": AdapterMeta(
        capabilities=("cloud_posture", "k8s_posture"),
        asset_kinds=("cloud_account",),
        safety_tier="T1",
        auth_required=True,
        network_egress="cloud_api",
        resource_profile=ResourceProfile(cpu=1, mem_mb=1024, timeout_s=3600),
        licence="Apache-2.0",
        output_schema="ocsf-json",
    ),
    "kube_bench": AdapterMeta(
        capabilities=("k8s_cis",),
        asset_kinds=("cluster",),
        safety_tier="T1",
        network_egress="none",
        licence="Apache-2.0",
        output_schema="kube-bench-json",
    ),
    "testssl": AdapterMeta(
        capabilities=("tls",),
        asset_kinds=_WEB,
        safety_tier="T1",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=1, mem_mb=256, timeout_s=1800),
        licence="GPL-2.0",
        image_ref_env="ATTESTRA_IMAGE_TESTSSL",
        output_schema="testssl-json",
    ),
    "gitleaks": AdapterMeta(
        capabilities=("secrets",),
        asset_kinds=("repo",),
        safety_tier="T0",
        network_egress="none",
        licence="MIT",
        image_ref_env="ATTESTRA_IMAGE_GITLEAKS",
        output_schema="gitleaks-json",
    ),
    "checkov": AdapterMeta(
        capabilities=("iac_misconfig",),
        asset_kinds=("repo",),
        safety_tier="T0",
        network_egress="none",
        licence="Apache-2.0",
        image_ref_env="ATTESTRA_IMAGE_CHECKOV",
        output_schema="checkov-json",
    ),
    "naabu": AdapterMeta(
        capabilities=("port_discovery",),
        asset_kinds=_WEB,
        safety_tier="T1",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=1, mem_mb=256, timeout_s=1800),
        licence="MIT",
        image_ref_env="ATTESTRA_IMAGE_NAABU",
        output_schema="naabu-jsonl",
    ),
    "webcheck": AdapterMeta(
        capabilities=("headers", "tls_summary", "dns_email", "exposure"),
        asset_kinds=_WEB,
        safety_tier="T1",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=0.5, mem_mb=256, timeout_s=900),
        licence="internal",
        output_schema="webcheck-json",
    ),
}


def meta_for(adapter) -> AdapterMeta | None:
    own = getattr(adapter, "meta", None)
    if isinstance(own, AdapterMeta):
        return own
    return DEFAULT_META.get(getattr(adapter, "name", ""))


def adapter_version(adapter) -> str:
    """``<name>/<adapter_version or meta.version>+sdk<SDK_VERSION>`` (L-02)."""
    name = getattr(adapter, "name", "") or type(adapter).__name__
    own = getattr(adapter, "adapter_version", "") or ""
    meta = meta_for(adapter)
    ver = own or (meta.version if meta else "0")
    return f"{name}/{ver}+sdk{SDK_VERSION}"


def default_health(adapter) -> dict[str, Any]:
    """Readiness without touching any target: tool on PATH, image pin state, metadata."""
    meta = meta_for(adapter)
    try:
        local = bool(adapter.available())
    except Exception:  # noqa: BLE001
        local = False
    try:
        image_ok = bool(adapter.image_configured())
    except Exception:  # noqa: BLE001
        image_ok = False
    try:
        version = str(adapter.version())
    except Exception:  # noqa: BLE001
        version = ""
    problems = meta.problems() if meta else ["no adapter metadata"]
    return {
        "name": getattr(adapter, "name", ""),
        "adapter_version": adapter_version(adapter),
        "tool_version": version,
        "local_tool": local,
        "image_pinned": image_ok,
        "ready": local or image_ok,
        "safety_tier": meta.safety_tier if meta else "",
        "meta_problems": problems,
    }


def contract_problems(adapter, *, tmp_dir: Path) -> list[str]:
    """Static contract checks every registered adapter must pass (no process is started).

    * metadata is present and valid,
    * ``available()`` / ``version()`` never raise, version is a non-empty string,
    * ``validate_report`` rejects garbage bytes with a message (never raises),
    * ``timeout_s()`` is positive and ``health()`` is value-free.
    """
    out: list[str] = []
    name = getattr(adapter, "name", "") or ""
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,30}", name):
        out.append(f"bad adapter name {name!r}")
    meta = meta_for(adapter)
    if meta is None:
        out.append("no metadata (set meta = AdapterMeta(...) or add sdk.DEFAULT_META entry)")
    else:
        out += [f"meta: {p}" for p in meta.problems()]
    if not getattr(adapter, "import_tool", ""):
        out.append("import_tool missing")
    try:
        adapter.available()
    except Exception as exc:  # noqa: BLE001
        out.append(f"available() raised {type(exc).__name__}")
    try:
        v = adapter.version()
        if not isinstance(v, str) or not v:
            out.append("version() must return a non-empty string")
    except Exception as exc:  # noqa: BLE001
        out.append(f"version() raised {type(exc).__name__}")
    try:
        if int(adapter.timeout_s()) <= 0:
            out.append("timeout_s() must be positive")
    except Exception as exc:  # noqa: BLE001
        out.append(f"timeout_s() raised {type(exc).__name__}")
    try:
        msg = adapter.validate_report(b"\x00not a report{{{")
        if adapter.import_tool not in _LENIENT_IMPORTERS and not msg:
            out.append("validate_report accepted garbage")
    except Exception as exc:  # noqa: BLE001
        out.append(f"validate_report raised {type(exc).__name__}")
    try:
        h = adapter.health()
        if not isinstance(h, dict) or "ready" not in h:
            out.append("health() must return a dict with 'ready'")
    except Exception as exc:  # noqa: BLE001
        out.append(f"health() raised {type(exc).__name__}")
    return out


# Importers that intentionally tolerate unknown bytes (they return no findings instead of
# raising); the contract records them rather than failing them.
_LENIENT_IMPORTERS: frozenset[str] = frozenset()
