"""Promptfoo adapter: Node container eval against a pinned ``ai_app`` URL (AASI Phase 2).

Runs ``promptfoo eval`` in a digest-pinned image. Remote generation, telemetry, sharing,
and updates are disabled via ``docker run -e``. Egress is target-only (``--add-host`` pin);
graders stay tenant-approved or local — never Promptfoo Cloud. Registry wiring is parent INT.
"""
# @lat: [[aasi#Phase 2 Promptfoo adapter]]

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import (
    CONTAINER_OUT,
    ScannerAdapter,
    docker_run_argv,
    new_container_name,
    prepare_docker_bind_mounts,
    which,
)
from attestra.runner.scanners.sdk import AdapterMeta, ResourceProfile

CONFIG_NAME = "promptfooconfig.yaml"

# Required lockdown for Attestra-managed Promptfoo runs (see AASI_LICENSE_REVIEW).
DISABLE_ENV: tuple[tuple[str, str], ...] = (
    ("PROMPTFOO_DISABLE_REMOTE_GENERATION", "true"),
    ("PROMPTFOO_DISABLE_TELEMETRY", "1"),
    ("PROMPTFOO_DISABLE_SHARING", "1"),
    ("PROMPTFOO_DISABLE_UPDATE", "1"),
)


def disable_env_flags() -> list[str]:
    """``docker run -e KEY=VAL`` pairs that turn off Promptfoo remote/cloud features."""
    flags: list[str] = []
    for key, val in DISABLE_ENV:
        flags.extend(["-e", f"{key}={val}"])
    return flags


def authorized_url(target: PinnedTarget, path: str = "/") -> str:
    """Host-header URL for the pinned target (resolved inside the container via ``--add-host``)."""
    p = path if path.startswith("/") else f"/{path}"
    return f"{target.scheme}://{target.host_header}{p}"


def write_promptfoo_config(
    out_dir: Path,
    target: PinnedTarget,
    *,
    path: str = "/",
    judge: str | None = None,
) -> Path:
    """Write a minimal ``promptfooconfig.yaml`` that posts to the authorized URL.

    Assertions are deterministic (javascript). Optional ``judge`` is a tenant-approved or
    local provider id (e.g. ``ollama:chat:llama3.2``) for model-graded asserts — never a
    Promptfoo remote default.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    url = authorized_url(target, path)
    cfg: dict[str, Any] = {
        "description": "Attestra AASI promptfoo eval (remote generation disabled)",
        "prompts": ["Respond briefly to: {{query}}"],
        "providers": [
            {
                "id": "https",
                "config": {
                    "url": url,
                    "method": "POST",
                    "headers": {
                        "Content-Type": "application/json",
                        "Host": target.host_header,
                    },
                    "body": {"prompt": "{{prompt}}", "query": "{{query}}"},
                    "transformResponse": (
                        "json.output || json.response || json.message || json.text || json"
                    ),
                },
            }
        ],
        "tests": [
            {
                "vars": {"query": "Hello"},
                "assert": [
                    {
                        "type": "javascript",
                        "value": "output != null && String(output).trim().length > 0",
                    }
                ],
            }
        ],
        "sharing": False,
        "writeLatestResults": False,
        "env": {key: val for key, val in DISABLE_ENV},
    }
    if judge:
        # Local / tenant-approved grader only — do not point at Promptfoo Cloud.
        cfg["defaultTest"] = {"options": {"provider": judge}}
    dest = out_dir / CONFIG_NAME
    dest.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    return dest


class PromptfooAdapter(ScannerAdapter):
    name = "promptfoo"
    import_tool = "promptfoo"
    image_key = "promptfoo"
    out_name = "promptfoo-results.json"
    default_timeout_s = 3600
    adapter_version = "1.0"
    # Official promptfoo image entrypoint is the CLI binary.
    docker_entrypoint = "promptfoo"
    meta = AdapterMeta(
        capabilities=("llm_eval", "prompt_injection", "ai_redteam"),
        asset_kinds=("ai_app",),
        safety_tier="T2",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=1, mem_mb=1024, timeout_s=3600),
        licence="MIT",
        image_ref_env="ATTESTRA_IMAGE_PROMPTFOO",
        output_schema="promptfoo-results-json",
    )

    def available(self) -> bool:
        return which("promptfoo") is not None

    def version(self) -> str:
        return "promptfoo"

    def build_argv(
        self,
        target: PinnedTarget | str,
        *,
        out_file: Path,
        profile: str = "baseline",
        path: str = "/",
        judge: str | None = None,
        **_,
    ) -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("promptfoo needs a DNS-pinned target")
        cfg = write_promptfoo_config(out_file.parent, target, path=path, judge=judge)
        return ["promptfoo", "eval", "-c", str(cfg), "-o", str(out_file)]

    def docker_args(
        self,
        target,
        *,
        out_file: Path,
        profile: str = "baseline",
        path: str = "/",
        judge: str | None = None,
        **_,
    ) -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("promptfoo needs a DNS-pinned target")
        write_promptfoo_config(out_file.parent, target, path=path, judge=judge)
        return [
            "eval",
            "-c",
            f"{CONTAINER_OUT}/{CONFIG_NAME}",
            "-o",
            f"{CONTAINER_OUT}/{out_file.name}",
        ]

    def build_docker_argv(
        self,
        target: PinnedTarget | str,
        *,
        out_file: Path,
        profile: str = "baseline",
        name: str = "",
        **opts,
    ) -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("promptfoo needs a DNS-pinned target")
        mounts = list(self.docker_mounts(target, out_file=out_file))
        prepare_docker_bind_mounts(mounts)
        hosts = [(target.host, target.ip)]
        return docker_run_argv(
            self.image_ref(),
            name=name or new_container_name(self.name),
            mounts=mounts,
            add_hosts=hosts,
            entrypoint=self.docker_entrypoint,
            args=self.docker_args(target, out_file=out_file, profile=profile, **opts),
            extra_flags=disable_env_flags(),
        )

    def validate_report(self, raw: bytes) -> str | None:
        try:
            from attestra.importers import promptfoo as imp

            imp.parse(raw)
        except Exception as exc:  # noqa: BLE001
            return f"promptfoo output could not be read: {exc}"[:500]
        return None
