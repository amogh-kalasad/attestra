"""Aggregated readiness for the four AASI AI scanners on the shared runtime.

Never falls back to Docker. Reports whether each scanner's shared-env dependency
is present and version-pinned.
"""

from __future__ import annotations

from attestra.scanner_runtime.dependency_check import (
    PackageStatus,
    check_node,
    check_promptfoo,
    check_python_package,
)
from attestra.scanner_runtime.environment import (
    ExtraVenvError,
    SharedEnvironment,
    reject_extra_venvs,
    resolve_shared_env,
)
from attestra.scanner_runtime.versions import SCANNER_TO_PACKAGE, SUPPORTED

# @lat: [[aasi#AASI (Attestra Agentic Security Intelligence)#V5.1 shared scanner runtime]]


def _scanner_status(
    scanner: str,
    *,
    env: SharedEnvironment,
    node_status: PackageStatus,
) -> dict:
    """Build one scanner health entry from package / CLI checks."""
    package = SCANNER_TO_PACKAGE[scanner]
    if scanner == "promptfoo":
        pkg = check_promptfoo(env=env)
        ready = pkg.ok and node_status.ok
        return {
            "name": scanner,
            "ready": ready,
            "package": package,
            "expected": pkg.expected,
            "installed": pkg.installed,
            "node_ok": node_status.ok,
            "node_version": node_status.installed,
            "detail": pkg.detail or ("" if node_status.ok else node_status.detail),
            "runtime": "shared-npm",
            "docker": False,
        }

    pkg = check_python_package(package, env=env)
    return {
        "name": scanner,
        "ready": pkg.ok,
        "package": package,
        "expected": pkg.expected,
        "installed": pkg.installed,
        "detail": pkg.detail,
        "runtime": "shared-venv",
        "docker": False,
    }


def health_report(*, env: SharedEnvironment | None = None, check_extra_venvs: bool = True) -> dict:
    """Return a value-free health report for garak, safelabs, pyrit, and promptfoo.

    ``docker`` is always false — V5.1 does not use Docker for AI scanners.
    """
    shared = env or resolve_shared_env()
    extra_venvs: dict = {"ok": True, "error": ""}
    if check_extra_venvs:
        try:
            reject_extra_venvs(shared=shared, search_roots=[shared.root])
        except ExtraVenvError as exc:
            extra_venvs = {"ok": False, "error": str(exc)}

    node_status = check_node(env=shared)
    scanners = {
        name: _scanner_status(name, env=shared, node_status=node_status)
        for name in ("garak", "safelabs", "pyrit", "promptfoo")
    }
    ready_all = extra_venvs["ok"] and all(s["ready"] for s in scanners.values())
    return {
        "schema": "aasi.scanner_runtime.health.v1",
        "root": str(shared.root),
        "python": str(shared.python),
        "ready": ready_all,
        "docker": False,
        "supported": dict(SUPPORTED),
        "extra_venvs": extra_venvs,
        "node": node_status.as_dict(),
        "scanners": scanners,
    }
