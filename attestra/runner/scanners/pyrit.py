"""PyRIT native multi-turn adapter (AASI V5.1).

Runs selected PyRIT attacks (crescendo, PAIR, tree-of-attacks, red teaming,
many-shot) against a DNS-pinned ``ai_app`` URL via the shared-env ``pyrit``
package. Execution is ``python -m attestra.aasi.pyrit_native`` (process
isolation). Docker is disabled (``allows_docker=False``, empty ``image_key``).

Argv is a fixed allowlist — never ``shell=True``, never agent-supplied commands.
Third-party judge / adversarial-model egress stays off unless the tenant
explicitly sets ``tenant_authorize_external_judge=True``. Transcripts and usage
land in the report JSON consumed by [[attestra/importers/pyrit.py#parse]].

The older Docker HTTP-marker worker is deprecated; see
``docs/ai_security/AASI_V51_PYRIT_NATIVE.md``.
"""
# @lat: [[aasi#Phase 5 PyRIT adapter]]

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, ScannerResult
from attestra.runner.scanners.sdk import AdapterMeta, ResourceProfile

CONFIG_NAME = "pyrit-run.json"
# Native module (shared venv) — not the deprecated docker attestra_pyrit_worker.
NATIVE_MODULE = "attestra.aasi.pyrit_native"
_INSTALL_HINT = (
    "Install pyrit into the shared scanner env "
    "(pip install 'pyrit>=0.9.0' or python scripts/aasi/install_shared_env.py); "
    "Docker is not used for this adapter."
)


def _shared_python() -> str | None:
    """Resolve shared-env Python; prefer ``attestra.scanner_runtime`` when present."""
    try:
        from attestra.scanner_runtime import resolve_shared_env

        py = resolve_shared_env().python
        if py.is_file():
            return str(py)
    except Exception:
        pass
    root = (os.environ.get("ATTESTRA_SHARED_ENV_ROOT") or "").strip()
    if not root:
        for base in (Path.cwd(), Path(__file__).resolve().parents[3]):
            marker = base / ".attestra-runtime"
            if marker.is_dir():
                root = str(marker)
                break
            if marker.is_file():
                text = marker.read_text(encoding="utf-8").strip()
                if text:
                    root = text.splitlines()[0].strip()
                    break
    if not root:
        try:
            from attestra import config

            root = str(config.shared_env_root())
        except Exception:
            return None
    root_path = Path(root)
    for candidate in (
        root_path / "venv" / "Scripts" / "python.exe",
        root_path / "venv" / "bin" / "python",
        root_path / "Scripts" / "python.exe",
        root_path / "bin" / "python",
        root_path / "python.exe",
        root_path / "python",
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def _pyrit_importable(python: str) -> bool:
    try:
        proc = subprocess.run(
            [python, "-c", "import pyrit"],
            capture_output=True,
            timeout=20,
            check=False,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _pyrit_in_shared_env() -> bool:
    """True when shared-env metadata / import shows pyrit is installed."""
    try:
        from attestra.scanner_runtime import check_python_package

        status = check_python_package("pyrit", expected="")
        if status.installed:
            return True
    except Exception:
        pass
    py = _shared_python()
    return bool(py and _pyrit_importable(py))


def _native_python() -> str:
    """Interpreter for ``-m attestra.aasi.pyrit_native`` (shared env preferred)."""
    py = _shared_python()
    if py and (_pyrit_in_shared_env() or _pyrit_importable(py)):
        return py
    if _pyrit_importable(sys.executable):
        return sys.executable
    if py:
        return py
    return sys.executable

# Allowlisted scenarios only (blueprint / V5.1). No free-form PyRIT CLI.
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

# Kept for tests that still import the old name; native path uses NATIVE_MODULE.
WORKER_MODULE = NATIVE_MODULE


def disable_external_env_flags() -> list[str]:
    """``-e KEY=VAL`` pairs for subprocess env lockdown (legacy docker helper)."""
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
    """Host-header URL for the pinned target."""
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
    """Write ``pyrit-run.json`` for the native runner (HTTP target + scenario)."""
    opts = dict(opts or {})
    out_dir.mkdir(parents=True, exist_ok=True)
    url = authorized_url(target, path)
    allow_external = external_judge_authorized(opts)
    doc: dict[str, Any] = {
        "tool": "pyrit",
        "schema": "pyrit-run-v1",
        "scenario": scenario,
        "scenario_engine": "pyrit-backed",
        "target": {
            "url": url,
            "host": target.host,
            "scheme": target.scheme,
            "prompt_target": "http_target",
        },
        "judge": {
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
    """Fixed native argv after the interpreter — no free-form agent commands."""
    return [
        "-m",
        NATIVE_MODULE,
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
    for key in ("usage", "cost", "cost_usd", "tokens_in", "tokens_out", "token_usage", "pyrit_version"):
        if key in doc and doc[key] is not None:
            sr.extra[key] = doc[key]
    usage = doc.get("usage")
    if isinstance(usage, dict):
        for key in ("cost", "cost_usd", "tokens_in", "tokens_out", "calls"):
            if key in usage and key not in sr.extra:
                sr.extra[key] = usage[key]


class PyRITAdapter(ScannerAdapter):
    """Native shared-env PyRIT runner for ``ai_app`` targets (no Docker)."""

    name = "pyrit"
    import_tool = "pyrit"
    image_key = ""
    allows_docker = False
    out_name = "pyrit-results.json"
    default_timeout_s = 3600
    adapter_version = "2.0"
    meta = AdapterMeta(
        capabilities=("ai_multi_turn", "ai_redteam", "crescendo", "pair"),
        asset_kinds=("ai_app",),
        safety_tier="T2",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=1.0, mem_mb=2048, timeout_s=3600),
        licence="MIT",
        image_ref_env="",
        output_schema="pyrit-json",
    )

    def available(self) -> bool:
        if _pyrit_in_shared_env():
            return True
        if _pyrit_importable(sys.executable):
            return True
        try:
            from attestra.aasi import pyrit_native

            return bool(pyrit_native.available())
        except Exception:  # noqa: BLE001
            return False

    def version(self) -> str:
        py = _native_python()
        try:
            proc = subprocess.run(
                [py, "-c", "import pyrit; print(getattr(pyrit,'__version__','unknown'))"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return f"pyrit {proc.stdout.strip()}"
        except Exception:  # noqa: BLE001
            pass
        try:
            from attestra.aasi import pyrit_native

            ver = pyrit_native.pyrit_version()
            if ver:
                return f"pyrit {ver}"
        except Exception:  # noqa: BLE001
            pass
        return "pyrit"

    def uses_docker(self) -> bool:
        return False

    def unavailable_reason(self) -> str:
        try:
            from attestra import config

            root = config.shared_env_root()
        except Exception:  # noqa: BLE001
            root = ".attestra-runtime"
        return f"pyrit cannot run: pyrit is not available in the shared scanner env at {root}. {_INSTALL_HINT}"

    def _prepare(
        self,
        target: PinnedTarget | str,
        *,
        out_file: Path,
        profile: str = "baseline",
        path: str = "/",
        endpoint_path: str | None = None,
        **opts: Any,
    ) -> tuple[str, dict[str, Any]]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("pyrit needs a DNS-pinned target")
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
            _native_python(),
            *_cli_tail(config_path=cfg, output_path=str(out_file.resolve()), scenario=scenario),
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
        raise NotImplementedError("pyrit V5.1 is native-only (allows_docker=False)")

    def build_docker_argv(
        self,
        target: PinnedTarget | str,
        *,
        out_file: Path,
        profile: str = "baseline",
        name: str = "",
        **opts: Any,
    ) -> list[str]:
        raise NotImplementedError("pyrit V5.1 is native-only (allows_docker=False)")

    def scan(  # type: ignore[override]
        self,
        pin: PinnedTarget | str,
        *,
        out_dir: Path,
        cancel=None,
        profile: str = "baseline",
        **opts: Any,
    ) -> ScannerResult:
        # Ensure judge lockdown env is present for the child process when not opted in.
        env = None
        if not external_judge_authorized(opts):
            import os

            env = os.environ.copy()
            for key, val in DISABLE_EXTERNAL_ENV:
                env.setdefault(key, val)
            # Inject into opts only for our local scan wrapper — base.scan has no env=
            # parameter, so we override _scan via a thin local path when needed.
        if env is None:
            sr = super().scan(pin, out_dir=out_dir, cancel=cancel, profile=profile, **opts)
        else:
            sr = self._scan_with_env(pin, out_dir=out_dir, cancel=cancel, profile=profile, env=env, **opts)
        _attach_usage(sr, sr.raw_path)
        return sr

    def _scan_with_env(
        self,
        pin: PinnedTarget | str,
        *,
        out_dir: Path,
        cancel=None,
        profile: str = "baseline",
        env: dict[str, str],
        **opts: Any,
    ) -> ScannerResult:
        """Same as base._scan but passes env into run_process for judge lockdown."""
        from attestra.runner.scanners.base import run_process

        redact = tuple(opts.pop("redact_values", ()) or ())
        from attestra import config as cfg

        cfg.ensure_dirs()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / (self.out_name or f"{self.name}-out.json")
        if out_file.exists():
            out_file.unlink()
        if not self.available():
            return ScannerResult(tool=self.name, tool_version=self.version(), error=self.unavailable_reason())
        argv = self.build_argv(pin, out_file=out_file, profile=profile, **opts)
        version = self.version()
        timeout = self.timeout_s()
        result = run_process(argv, cancel=cancel, timeout=timeout, env=env)
        self._write_tool_log(out_dir, result, redact)
        if result.cancelled or result.timed_out:
            return ScannerResult(
                tool=self.name,
                tool_version=version,
                error="" if result.cancelled else f"{self.name} timed out after {timeout}s",
                extra={
                    "cancelled": result.cancelled,
                    "timed_out": result.timed_out,
                    "stderr": (result.stderr or b"")[-2000:].decode("utf-8", errors="replace"),
                },
            )
        out_file = self.resolve_output(out_file)
        if not out_file.exists() and self.report_on_stdout and result.stdout.strip():
            out_file.write_bytes(result.stdout)
        extra = {
            "returncode": result.returncode,
            "argv": argv,
            "stderr": (result.stderr or b"")[-2000:].decode("utf-8", errors="replace"),
        }
        sr = ScannerResult(tool=self.name, tool_version=version, import_tool=self.import_tool, extra=extra)
        if not out_file.exists():
            sr.error = f"{self.name} wrote no report (exit code {result.returncode})"[:1500]
            return sr
        problem = self.validate_report(out_file.read_bytes())
        if problem:
            sr.error = f"{problem} (exit code {result.returncode})"[:1500]
            return sr
        sr.raw_path = out_file
        return self.stamp_result(sr)

    def validate_report(self, raw: bytes) -> str | None:
        try:
            from attestra.importers import pyrit as imp

            imp.parse(raw)
        except Exception as exc:  # noqa: BLE001
            return f"pyrit output could not be read: {exc}"[:500]
        return None
