"""Garak adapter: native shared-env LLM probe against an authorized ai_app URL (AASI V5.1).

Runs via the Attestra shared scanner Python (``python -m garak``), never Docker.
The REST generator is pointed at the pinned target via a JSON options file written into
the report dir; the JSONL report lands under the host out_dir. Argv is a fixed template —
never ``shell=True``, never agent-supplied commands.

Shared-env openai policy: the venv pins openai 3.x for PyRIT, so Garak is installed
with ``--no-deps``. This adapter uses ``--target_type rest`` only. Garak's native
OpenAI generator is unsupported here; Anthropic and LiteLLM packages are present for
Garak generators that need them.
"""
# @lat: [[aasi#Phase 2 Garak adapter]]

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from attestra.runner.authorization import AuthorizedScope, authorize_target
from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, which
from attestra.runner.scanners.sdk import AdapterMeta, ResourceProfile

GENERATOR_CONFIG_NAME = "garak-generator.json"
RUN_CONFIG_NAME = "garak-run.yaml"
# Garak appends ".report.jsonl" to reporting.report_prefix.
REPORT_PREFIX = "garak-report"
GARAK_REPORT_NAME = f"{REPORT_PREFIX}.report.jsonl"

_INSTALL_HINT = (
    "Run python scripts/aasi/install_shared_env.py to provision the shared scanner env, then retry."
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
            # Marker may be a directory (default layout) or a one-line path file.
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


def _garak_in_shared_env() -> bool:
    """True when shared-env metadata / import shows garak is installed."""
    try:
        from attestra.scanner_runtime import check_python_package

        status = check_python_package("garak", expected="")
        if status.installed:
            return True
    except Exception:
        pass
    py = _shared_python()
    return bool(py and _garak_importable(py))


def _garak_importable(python: str) -> bool:
    try:
        proc = subprocess.run(
            [python, "-c", "import garak"],
            capture_output=True,
            timeout=20,
            check=False,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _garak_prefix() -> list[str]:
    """Fixed launcher: shared ``python -m garak``, else PATH / sys.executable."""
    py = _shared_python()
    if py and (_garak_in_shared_env() or _garak_importable(py)):
        return [py, "-m", "garak"]
    local = which("garak")
    if local:
        return [local]
    if _garak_importable(sys.executable):
        return [sys.executable, "-m", "garak"]
    if py:
        return [py, "-m", "garak"]
    return [sys.executable, "-m", "garak"]


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
    """Point garak reporting at the host out dir (absolute path)."""
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
    image_key = ""
    allows_docker = False
    out_name = "garak-report.jsonl"
    empty_report_ok = False
    default_timeout_s = 3600
    adapter_version = "5.1"
    meta = AdapterMeta(
        capabilities=("ai_llm_probe",),
        asset_kinds=("ai_app",),
        safety_tier="T2",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=1.0, mem_mb=2048, timeout_s=3600),
        licence="Apache-2.0",
        image_ref_env="",
        output_schema="garak-jsonl",
    )

    def uses_docker(self) -> bool:
        return False

    def available(self) -> bool:
        if _garak_in_shared_env():
            return True
        if which("garak") is not None:
            return True
        return _garak_importable(sys.executable)

    def unavailable_reason(self) -> str:
        return f"{self.name} cannot run: garak is not available in the shared scanner env. {_INSTALL_HINT}"

    def version(self) -> str:
        # Recorded tool_version only — never invent a pin when the probe fails.
        try:
            from attestra.scanner_runtime import check_python_package

            status = check_python_package("garak", expected="")
            if status.installed:
                return f"garak {status.installed}"
        except Exception:  # noqa: BLE001
            pass
        py = _shared_python()
        if py:
            try:
                proc = subprocess.run(
                    [py, "-c", "import garak; print(getattr(garak,'__version__','') or '')"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
                ver = (proc.stdout or "").strip()
                if proc.returncode == 0 and ver:
                    return f"garak {ver}"
            except Exception:  # noqa: BLE001
                pass
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
        return [*_garak_prefix(), *flags]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **opts) -> list[str]:
        raise NotImplementedError("garak is native-only (AASI V5.1); Docker is not supported")

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
