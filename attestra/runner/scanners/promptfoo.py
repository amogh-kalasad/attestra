"""Promptfoo adapter: native Node eval against a pinned ``ai_app`` URL (AASI V5.1).

Runs ``promptfoo eval`` from the shared env npm prefix (``ATTESTRA_SHARED_ENV_ROOT/npm``).
Remote generation, telemetry, sharing, and updates stay disabled via process env and the
written config. Graders stay tenant-approved or local — never Promptfoo Cloud. No Docker.
"""
# @lat: [[aasi#Phase 2 Promptfoo adapter]]

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from attestra import config
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter
from attestra.runner.scanners.sdk import AdapterMeta, ResourceProfile
from attestra.scanner_runtime.egress import scanner_process_env
from attestra.scanner_runtime.environment import resolve_shared_env

CONFIG_NAME = "promptfooconfig.yaml"

# Required lockdown for Attestra-managed Promptfoo runs (see AASI_LICENSE_REVIEW).
DISABLE_ENV: tuple[tuple[str, str], ...] = (
    ("PROMPTFOO_DISABLE_REMOTE_GENERATION", "true"),
    ("PROMPTFOO_DISABLE_TELEMETRY", "1"),
    ("PROMPTFOO_DISABLE_SHARING", "1"),
    ("PROMPTFOO_DISABLE_UPDATE", "1"),
)

# Windows npm wrappers need a shell; skip them and use ``node`` + JS entry instead.
_WIN_WRAPPER_SUFFIXES = (".cmd", ".bat", ".ps1")


def privacy_env() -> dict[str, str]:
    """Process env that turns off Promptfoo remote/cloud features."""
    return {key: val for key, val in DISABLE_ENV}


def authorized_url(target: PinnedTarget, path: str = "/") -> str:
    """Host-header URL for the pinned target."""
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


def _shared_env():
    """Shared runtime rooted at ``config.shared_env_root()`` (honours test monkeypatches)."""
    return resolve_shared_env(root=config.shared_env_root())


def _is_shell_wrapper(path: Path) -> bool:
    return path.suffix.lower() in _WIN_WRAPPER_SUFFIXES


def _promptfoo_js_entry(npm: Path) -> Path | None:
    """Published package CLI entry (``bin.promptfoo`` → ``dist/src/entrypoint.js``)."""
    entry = npm / "node_modules" / "promptfoo" / "dist" / "src" / "entrypoint.js"
    return entry if entry.is_file() else None


def resolve_promptfoo_argv_prefix() -> list[str] | None:
    """Fixed argv prefix for shared-env Promptfoo, or ``None`` when not installed.

    Prefers a real CLI under ``npm/bin`` or ``npm/node_modules/.bin`` (not Windows shell
    wrappers). Otherwise ``[node, entrypoint.js]`` using the shared Node runtime.
    Never falls back to a system-global Promptfoo on PATH.
    """
    shared = _shared_env()
    npm = shared.npm
    for rel in ("bin/promptfoo", "node_modules/.bin/promptfoo", "promptfoo"):
        cli = npm / rel
        if cli.is_file() and not _is_shell_wrapper(cli):
            return [str(cli)]

    entry = _promptfoo_js_entry(npm)
    node = shared.node
    if entry is not None and node.is_file():
        return [str(node), str(entry)]
    return None


class PromptfooAdapter(ScannerAdapter):
    name = "promptfoo"
    import_tool = "promptfoo"
    image_key = ""
    allows_docker = False
    out_name = "promptfoo-results.json"
    default_timeout_s = 3600
    adapter_version = "2.0"
    meta = AdapterMeta(
        capabilities=("llm_eval", "prompt_injection", "ai_redteam"),
        asset_kinds=("ai_app",),
        safety_tier="T2",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=1, mem_mb=1024, timeout_s=3600),
        licence="MIT",
        image_ref_env="",
        output_schema="promptfoo-results-json",
    )

    def available(self) -> bool:
        return resolve_promptfoo_argv_prefix() is not None

    def version(self) -> str:
        # Recorded tool_version only — never invent a pin when the probe fails.
        try:
            from attestra.scanner_runtime import check_promptfoo

            status = check_promptfoo()
            if status.installed:
                return f"promptfoo {status.installed}"
        except Exception:  # noqa: BLE001
            pass
        return "promptfoo"

    def unavailable_reason(self) -> str:
        root = config.shared_env_root()
        return (
            f"promptfoo cannot run: install the promptfoo npm package under {root / 'npm'} "
            f"(set ATTESTRA_SHARED_ENV_ROOT); Docker is not used for this adapter"
        )

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
        prefix = resolve_promptfoo_argv_prefix()
        if not prefix:
            raise RuntimeError(self.unavailable_reason())
        cfg = write_promptfoo_config(out_file.parent, target, path=path, judge=judge)
        return [*prefix, "eval", "-c", str(cfg), "-o", str(out_file)]

    def _scan(
        self,
        pin: PinnedTarget | str,
        *,
        out_dir: Path,
        cancel=None,
        profile: str = "baseline",
        **opts,
    ):
        """Native run: shared-env PATH + sanitized/privacy env (no Docker, no global env mutate)."""
        import attestra.runner.scanners.base as base_mod

        orig = base_mod.run_process
        shared = _shared_env()

        def run_with_privacy(argv, **kwargs):
            base_env = shared.process_env()
            env = scanner_process_env(base=base_env, extra=privacy_env())
            kwargs["env"] = env
            return orig(argv, **kwargs)

        base_mod.run_process = run_with_privacy  # type: ignore[assignment]
        try:
            return super()._scan(pin, out_dir=out_dir, cancel=cancel, profile=profile, **opts)
        finally:
            base_mod.run_process = orig

    def validate_report(self, raw: bytes) -> str | None:
        try:
            from attestra.importers import promptfoo as imp

            imp.parse(raw)
        except Exception as exc:  # noqa: BLE001
            return f"promptfoo output could not be read: {exc}"[:500]
        return None
