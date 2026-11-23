"""PyRIT isolated multi-turn worker adapter (AASI Phase 5).

Runs selected PyRIT attacks (crescendo, PAIR, tree-of-attacks, red teaming,
many-shot) against a DNS-pinned ``ai_app`` URL inside a digest-pinned container.
Argv is a fixed allowlist — never ``shell=True``, never agent-supplied commands.
Third-party judge / adversarial-model egress stays off unless the tenant explicitly
sets ``tenant_authorize_external_judge=True``. Transcripts and usage land in the
report JSON consumed by [[attestra/importers/pyrit.py#parse]].
"""
# @lat: [[aasi#Phase 5 PyRIT adapter]]

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import (
    CONTAINER_OUT,
    ScannerAdapter,
    ScannerResult,
    docker_run_argv,
    new_container_name,
    prepare_docker_bind_mounts,
    which,
)
from attestra.runner.scanners.sdk import AdapterMeta, ResourceProfile

CONFIG_NAME = "pyrit-run.json"
# Image contract: worker module that reads the run config and writes pyrit-results.json.
WORKER_MODULE = "attestra_pyrit_worker"

# Allowlisted scenarios only (blueprint Phase 5). No free-form PyRIT CLI.
SCENARIOS: frozenset[str] = frozenset(
    {"crescendo", "pair", "tree_of_attacks", "red_teaming", "many_shot"}
)
_SCENARIO_ALIASES: dict[str, str] = {
    "many_shot_jailbreak": "many_shot",
    "toa": "tree_of_attacks",
    "tap": "tree_of_attacks",
    "redteam": "red_teaming",
    "red_team": "red_teaming",
}
# When profile is a scan profile name (not a scenario), use this default.
_DEFAULT_SCENARIO = "crescendo"
_PROFILE_DEFAULTS: dict[str, str] = {
    "baseline": "crescendo",
    "full": "crescendo",
    "active": "crescendo",
}

# Env lockdown when third-party judge / adversarial egress is not authorized.
DISABLE_EXTERNAL_ENV: tuple[tuple[str, str], ...] = (
    ("PYRIT_DISABLE_EXTERNAL_JUDGE", "1"),
    ("PYRIT_DISABLE_ADVERSARIAL_EGRESS", "1"),
)


def disable_external_env_flags() -> list[str]:
    """``docker run -e`` pairs that refuse third-party judge/adversarial egress."""
    flags: list[str] = []
    for key, val in DISABLE_EXTERNAL_ENV:
        flags.extend(["-e", f"{key}={val}"])
    return flags


def resolve_scenario(profile: str = "baseline", opts: dict[str, Any] | None = None) -> str:
    """Map profile/opts to an allowlisted scenario id (fixed argv only)."""
    opts = opts or {}
    raw = opts.get("scenario")
    if raw is None or str(raw).strip() == "":
        raw = profile
    key = str(raw).strip().lower().replace("-", "_")
    key = _SCENARIO_ALIASES.get(key, key)
    if key in SCENARIOS:
        return key
    if key in _PROFILE_DEFAULTS:
        return _PROFILE_DEFAULTS[key]
    raise ValueError(
        f"pyrit scenario must be one of {sorted(SCENARIOS)} "
        f"(or profile baseline/full/active); got {raw!r}"
    )


def authorized_url(target: PinnedTarget, path: str = "/") -> str:
    """Host-header URL for the pinned target (resolved inside the container via ``--add-host``)."""
    p = path if path.startswith("/") else f"/{path}"
    if any(ch in p for ch in ";|&`$()\n\r\t "):
        raise ValueError("pyrit endpoint_path contains unsafe characters")
    return f"{target.scheme}://{target.host_header}{p}"


def external_judge_authorized(opts: dict[str, Any]) -> bool:
    """True only when the tenant explicitly opts into third-party judge egress."""
    return opts.get("tenant_authorize_external_judge") is True


def write_pyrit_run_config(
    out_dir: Path,
    target: PinnedTarget,
    *,
    scenario: str,
    path: str = "/",
    opts: dict[str, Any] | None = None,
) -> Path:
    """Write ``pyrit-run.json`` for the isolated worker (HTTP target + scenario).

    Transcripts must appear under each attack result (``transcript`` / ``conversation``)
    so the importer and evidence gallery can cite conversation turns. Usage/cost belong
    at the top level when the worker records them.
    """
    opts = dict(opts or {})
    out_dir.mkdir(parents=True, exist_ok=True)
    url = authorized_url(target, path)
    allow_external = external_judge_authorized(opts)
    doc: dict[str, Any] = {
        "tool": "pyrit",
        "schema": "pyrit-run-v1",
        "scenario": scenario,
        "target": {
            "url": url,
            "host": target.host,
            "scheme": target.scheme,
            "prompt_target": "http_target",
        },
        "judge": {
            # Default local/none — never open third-party scorers without explicit auth.
            "mode": "external" if allow_external else "none",
            "external_authorized": allow_external,
        },
        "adversarial_model": {
            "egress": "external" if allow_external else "disabled",
            "external_authorized": allow_external,
        },
        "output": {
            "include_transcripts": True,
            "include_usage": True,
        },
        "env": {key: val for key, val in DISABLE_EXTERNAL_ENV} if not allow_external else {},
    }
    if allow_external:
        judge = opts.get("judge")
        if judge not in (None, ""):
            doc["judge"]["provider"] = str(judge).strip()
        adv = opts.get("adversarial_model")
        if adv not in (None, ""):
            doc["adversarial_model"]["provider"] = str(adv).strip()
    dest = out_dir / CONFIG_NAME
    dest.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return dest


def _cli_tail(*, config_path: str, output_path: str, scenario: str) -> list[str]:
    """Fixed worker argv after the interpreter/module — no free-form agent commands."""
    return [
        "-m",
        WORKER_MODULE,
        "run",
        "--config",
        config_path,
        "--output",
        output_path,
        "--scenario",
        scenario,
    ]


def _attach_usage(sr: ScannerResult, raw_path: Path | None) -> None:
    """Copy usage/cost from the report into ``ScannerResult.extra`` when present."""
    if raw_path is None or not raw_path.is_file():
        return
    try:
        doc = json.loads(raw_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return
    if not isinstance(doc, dict):
        return
    if not isinstance(sr.extra, dict):
        sr.extra = {}
    for key in ("usage", "cost", "cost_usd", "tokens_in", "tokens_out", "token_usage"):
        if key in doc and doc[key] is not None:
            sr.extra[key] = doc[key]
    usage = doc.get("usage")
    if isinstance(usage, dict):
        for key in ("cost", "cost_usd", "tokens_in", "tokens_out", "calls"):
            if key in usage and key not in sr.extra:
                sr.extra[key] = usage[key]


class PyRITAdapter(ScannerAdapter):
    """Digest-pinned PyRIT multi-turn worker for ``ai_app`` targets."""

    name = "pyrit"
    import_tool = "pyrit"
    image_key = "pyrit"
    out_name = "pyrit-results.json"
    default_timeout_s = 3600
    adapter_version = "1.0"
    # Isolated worker image entrypoint is a Python interpreter + worker module.
    docker_entrypoint = "python"
    meta = AdapterMeta(
        capabilities=("ai_multi_turn", "ai_redteam", "crescendo", "pair"),
        asset_kinds=("ai_app",),
        safety_tier="T2",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=1.0, mem_mb=2048, timeout_s=3600),
        licence="MIT",
        image_ref_env="ATTESTRA_IMAGE_PYRIT",
        output_schema="pyrit-json",
    )

    def available(self) -> bool:
        # Docker is primary; local worker module is optional for argv checks.
        return which("python") is not None

    def version(self) -> str:
        return "pyrit"

    def _prepare(
        self,
        target: PinnedTarget | str,
        *,
        out_file: Path,
        profile: str = "baseline",
        path: str = "/",
        endpoint_path: str | None = None,
        **opts: Any,
    ) -> tuple[str, list[str]]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("pyrit needs a DNS-pinned target")
        # Refuse free-form command injection from agents / callers.
        for banned in ("command", "argv", "shell", "extra_args", "pyrit_args"):
            if banned in opts and opts[banned] not in (None, "", (), []):
                raise ValueError(f"pyrit does not accept unrestricted {banned!r}")
        scenario = resolve_scenario(profile, opts)
        ep = endpoint_path if endpoint_path is not None else path
        write_pyrit_run_config(
            out_file.parent,
            target,
            scenario=scenario,
            path=str(ep or "/"),
            opts=opts,
        )
        return scenario, opts

    def build_argv(
        self,
        target: PinnedTarget | str,
        *,
        out_file: Path,
        profile: str = "baseline",
        path: str = "/",
        endpoint_path: str | None = None,
        **opts: Any,
    ) -> list[str]:
        scenario, _ = self._prepare(
            target,
            out_file=out_file,
            profile=profile,
            path=path,
            endpoint_path=endpoint_path,
            **opts,
        )
        cfg = (out_file.parent / CONFIG_NAME).resolve().as_posix()
        return [
            "python",
            *_cli_tail(config_path=cfg, output_path=str(out_file), scenario=scenario),
        ]

    def docker_args(
        self,
        target,
        *,
        out_file: Path,
        profile: str = "baseline",
        path: str = "/",
        endpoint_path: str | None = None,
        **opts: Any,
    ) -> list[str]:
        scenario, _ = self._prepare(
            target,
            out_file=out_file,
            profile=profile,
            path=path,
            endpoint_path=endpoint_path,
            **opts,
        )
        return _cli_tail(
            config_path=f"{CONTAINER_OUT}/{CONFIG_NAME}",
            output_path=f"{CONTAINER_OUT}/{out_file.name}",
            scenario=scenario,
        )

    def build_docker_argv(
        self,
        target: PinnedTarget | str,
        *,
        out_file: Path,
        profile: str = "baseline",
        name: str = "",
        **opts: Any,
    ) -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("pyrit needs a DNS-pinned target")
        mounts = list(self.docker_mounts(target, out_file=out_file))
        prepare_docker_bind_mounts(mounts)
        hosts = [(target.host, target.ip)]
        extra = [] if external_judge_authorized(opts) else disable_external_env_flags()
        return docker_run_argv(
            self.image_ref(),
            name=name or new_container_name(self.name),
            mounts=mounts,
            add_hosts=hosts,
            entrypoint=self.docker_entrypoint,
            args=self.docker_args(target, out_file=out_file, profile=profile, **opts),
            extra_flags=extra,
        )

    def scan(  # type: ignore[override]
        self,
        pin: PinnedTarget | str,
        *,
        out_dir: Path,
        cancel=None,
        profile: str = "baseline",
        **opts: Any,
    ) -> ScannerResult:
        sr = super().scan(pin, out_dir=out_dir, cancel=cancel, profile=profile, **opts)
        _attach_usage(sr, sr.raw_path)
        return sr

    def validate_report(self, raw: bytes) -> str | None:
        try:
            from attestra.importers import pyrit as imp

            imp.parse(raw)
        except Exception as exc:  # noqa: BLE001
            return f"pyrit output could not be read: {exc}"[:500]
        return None
