"""SafeLabs safelabs-eval adapter: ASI heuristic eval against a pinned AI endpoint (AASI V5.1).

Runs via the Attestra shared scanner Python (``python -m safelabs`` or the venv ``safelabs``
console script), never Docker. Detectors are pattern-based; this adapter never upgrades
findings — the safelabs importer maps hits to potential. JSON is printed with
``--output json``; base ``scan`` persists stdout into the host out dir.
"""
# @lat: [[aasi#Phase 2 SafeLabs adapter]]

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from attestra.runner.dns_pin import PinnedTarget
from attestra.runner.scanners.base import ScannerAdapter, which
from attestra.runner.scanners.sdk import AdapterMeta, ResourceProfile

_ASI_CATEGORIES = frozenset(f"ASI{i:02d}" for i in range(1, 11))
# Baseline: one category (faster). full/active: all 300 prompts.
_PROFILE_CATEGORY = {"baseline": "ASI01", "full": "all", "active": "all"}
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


def _safelabs_in_shared_env() -> bool:
    """True when shared-env metadata shows safelabs-eval (or a Scripts CLI) is present."""
    try:
        from attestra.scanner_runtime import check_python_package

        status = check_python_package("safelabs-eval", expected="")
        if status.installed:
            return True
    except Exception:
        pass
    py = _shared_python()
    if not py:
        return False
    if _safelabs_script_near(py) is not None:
        return True
    return _safelabs_importable(py)


def _safelabs_importable(python: str) -> bool:
    try:
        proc = subprocess.run(
            [python, "-c", "import safelabs"],
            capture_output=True,
            timeout=20,
            check=False,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _safelabs_script_near(python: str) -> str | None:
    """Return ``safelabs`` console script next to shared-env Python, if present."""
    scripts = Path(python).parent
    for name in ("safelabs.exe", "safelabs"):
        candidate = scripts / name
        if candidate.is_file():
            return str(candidate)
    return None


def _safelabs_prefix() -> list[str]:
    """Fixed launcher: shared ``python -m safelabs``, else Scripts ``safelabs``, else PATH."""
    py = _shared_python()
    if py:
        script = _safelabs_script_near(py)
        if script:
            return [script]
        if _safelabs_in_shared_env() or _safelabs_importable(py):
            return [py, "-m", "safelabs"]
    local = which("safelabs")
    if local:
        return [local]
    if _safelabs_importable(sys.executable):
        return [sys.executable, "-m", "safelabs"]
    if py:
        return [py, "-m", "safelabs"]
    return [sys.executable, "-m", "safelabs"]


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


class SafeLabsAdapter(ScannerAdapter):
    """Native shared-env safelabs-eval runner for ``ai_app`` targets."""

    name = "safelabs"
    import_tool = "safelabs"
    image_key = ""
    allows_docker = False
    out_name = "safelabs-report.json"
    adapter_version = "5.1"
    # CLI ``--output json`` prints the report; scan() writes it under out_dir.
    report_on_stdout = True
    # Full ASI suite can take a while; override with ATTESTRA_SCANNER_TIMEOUT_SAFELABS.
    default_timeout_s = 3600
    meta = AdapterMeta(
        capabilities=("asi_heuristic_eval",),
        asset_kinds=("ai_app",),
        safety_tier="T2",
        network_egress="target",
        resource_profile=ResourceProfile(cpu=1, mem_mb=512, timeout_s=3600),
        licence="Apache-2.0",
        image_ref_env="",
        output_schema="safelabs-json",
    )

    def uses_docker(self) -> bool:
        return False

    def available(self) -> bool:
        if _safelabs_in_shared_env():
            return True
        if which("safelabs") is not None:
            return True
        return _safelabs_importable(sys.executable)

    def unavailable_reason(self) -> str:
        return (
            f"{self.name} cannot run: safelabs is not available in the shared scanner env. "
            f"{_INSTALL_HINT}"
        )

    def version(self) -> str:
        return "safelabs-eval"

    def build_argv(self, target: PinnedTarget | str, *, out_file: Path, profile: str = "baseline", **opts) -> list[str]:
        if not isinstance(target, PinnedTarget):
            raise ValueError("safelabs needs a DNS-pinned target")
        return [*_safelabs_prefix(), *_cli_args(target, profile=profile, opts=opts)]

    def docker_args(self, target, *, out_file: Path, profile: str = "baseline", **opts) -> list[str]:
        raise NotImplementedError("safelabs is native-only (AASI V5.1); Docker is not supported")
