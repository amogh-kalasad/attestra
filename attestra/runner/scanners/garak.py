"""Garak adapter: digest-pinned LLM probe run against an authorized ai_app URL (AASI Phase 2).

Docker is the primary path (``ATTESTRA_IMAGE_GARAK``). Local ``garak`` is optional for
dev. The REST generator is pointed at the pinned target via a JSON options file written
into the report dir; the JSONL report lands under the mounted ``/out`` (or host out_dir).
Argv is a fixed template — never ``shell=True``, never agent-supplied commands.
"""
# @lat: [[aasi#Phase 2 Garak adapter]]

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attestra.runner.authorization import AuthorizedScope, authorize_target
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import CONTAINER_OUT, ScannerAdapter, which
from attestra.runner.scanners.sdk import AdapterMeta, ResourceProfile

GENERATOR_CONFIG_NAME = "garak-generator.json"
RUN_CONFIG_NAME = "garak-run.yaml"
# Garak appends ".report.jsonl" to reporting.report_prefix.
REPORT_PREFIX = "garak-report"
GARAK_REPORT_NAME = f"{REPORT_PREFIX}.report.jsonl"


def target_url(target: PinnedTarget, *, endpoint_url: str | None = None) -> str:
    """Authorized URL for RestGenerator (optional full endpoint overrides the pin root)."""
    if endpoint_url:
        return str(endpoint_url).strip()
    return f"{target.scheme}://{target.host_header}/"


def _write_generator_config(out_dir: Path, uri: str) -> Path:
    """Write RestGenerator options; uri is the only per-run value."""
    doc = {
        "rest": {
            "RestGenerator": {
                "name": "attestra-ai-target",
                "uri": uri,
                "method": "post",
                "req_template_json_object": {"messages": [{"role": "user", "content": "$INPUT"}]},
                "response_json": True,
                "response_json_field": "$.choices[0].message.content",
            }
        }
    }
    path = out_dir / GENERATOR_CONFIG_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return path


def _write_run_config(out_dir: Path, report_dir: str) -> Path:
    """Point garak reporting at the mounted out dir (absolute path inside the container)."""
    # YAML without a dependency: fixed keys only.
    text = (
        "reporting:\n"
        f"  report_dir: {report_dir}\n"
        f"  report_prefix: {REPORT_PREFIX}\n"
        "run:\n"
        "  generations: 1\n"
    )
    path = out_dir / RUN_CONFIG_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _garak_flags(*, generator_path: str, config_path: str) -> list[str]:
    """Fixed CLI template for a REST target; no shell, no free-form agent argv."""
    return [
        "--target_type",
        "rest",
        "-G",
        generator_path,
        "--config",
        config_path,
        "--generations",
        "1",
    ]


class GarakAdapter(ScannerAdapter):
    name = "garak"
    import_tool = "garak"
    image_key = "garak"
    out_name = "garak-report.jsonl"
    empty_report_ok = False
    default_timeout_s = 3600
    adapter_version = "1.0"
    # Override image ENTRYPOINT so pip-style images work as ``python -m garak``.
    docker_entrypoint = "python"
    meta = AdapterMeta(
        capabilities=("ai_llm_probe",),
        asset_kinds=("ai_app",),
        safety_tier="T2",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=1.0, mem_mb=2048, timeout_s=3600),
        licence="Apache-2.0",
        image_ref_env="ATTESTRA_IMAGE_GARAK",
        output_schema="garak-jsonl",
    )

    def available(self) -> bool:
        # Docker is primary; local CLI is only for optional host-side runs.
        return which("garak") is not None

    def version(self) -> str:
        return "garak"

    def resolve_output(self, out_file: Path) -> Path:
        if out_file.exists():
            return out_file
        candidate = out_file.parent / GARAK_REPORT_NAME
        if candidate.exists():
            return candidate
        matches = sorted(out_file.parent.glob("*.report.jsonl"))
        return matches[0] if matches else out_file

    def _prepare(
        self,
        target: PinnedTarget | str,
        *,
        out_file: Path,
        scope: AuthorizedScope | None = None,
        endpoint_url: str | None = None,
        report_dir: str,
    ) -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("garak needs a DNS-pinned ai_app target")
        url = target_url(target, endpoint_url=endpoint_url)
        if scope is not None:
            authorize_target(scope, url, "url")
        out_dir = out_file.parent
        _write_generator_config(out_dir, url)
        _write_run_config(out_dir, report_dir)
        return _garak_flags(
            generator_path=f"{report_dir}/{GENERATOR_CONFIG_NAME}",
            config_path=f"{report_dir}/{RUN_CONFIG_NAME}",
        )

    def build_argv(
        self,
        target: PinnedTarget | str,
        *,
        out_file: Path,
        profile: str = "baseline",
        scope: AuthorizedScope | None = None,
        endpoint_url: str | None = None,
        **_,
    ) -> list[str]:
        report_dir = out_file.parent.resolve().as_posix()
        flags = self._prepare(
            target, out_file=out_file, scope=scope, endpoint_url=endpoint_url, report_dir=report_dir
        )
        return ["garak", *flags]

    def docker_args(
        self,
        target,
        *,
        out_file: Path,
        profile: str = "baseline",
        scope: AuthorizedScope | None = None,
        endpoint_url: str | None = None,
        **_,
    ) -> list[str]:
        flags = self._prepare(
            target,
            out_file=out_file,
            scope=scope,
            endpoint_url=endpoint_url,
            report_dir=CONTAINER_OUT,
        )
        return ["-m", "garak", *flags]

    def scan(  # type: ignore[override]
        self,
        pin: PinnedTarget | str,
        *,
        out_dir: Path,
        cancel=None,
        profile: str = "baseline",
        scope: AuthorizedScope | None = None,
        endpoint_url: str | None = None,
        **opts: Any,
    ):
        if scope is not None and isinstance(pin, PinnedTarget):
            authorize_target(scope, target_url(pin, endpoint_url=endpoint_url), "url")
        if scope is not None:
            opts["scope"] = scope
        if endpoint_url is not None:
            opts["endpoint_url"] = endpoint_url
        return super().scan(pin, out_dir=out_dir, cancel=cancel, profile=profile, **opts)
