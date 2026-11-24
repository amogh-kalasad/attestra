"""AASI V5.1 shared scanner runtime — one venv + npm root for AI scanners.

Layout under ``ATTESTRA_SHARED_ENV_ROOT`` (default ``<repo>/.attestra-runtime``):
``venv``, ``tools/node``, ``npm``, ``manifests``, ``logs``, ``cache``, ``tmp``.
Promptfoo is Node/npm; Python scanners share the single venv. No Docker.
"""

from attestra.scanner_runtime.dependency_check import (
    PackageStatus,
    check_all,
    check_node,
    check_promptfoo,
    check_python_package,
)
from attestra.scanner_runtime.egress import assert_target_egress_allowed, scanner_process_env
from attestra.scanner_runtime.environment import (
    ENV_ROOT_VAR,
    ExtraVenvError,
    SharedEnvError,
    SharedEnvironment,
    reject_extra_venvs,
    require_promptfoo,
    require_python,
    resolve_shared_env,
    shared_promptfoo,
    shared_python,
)
from attestra.scanner_runtime.health import health_report
from attestra.scanner_runtime.manifest import (
    ManifestError,
    list_manifests,
    read_manifest,
    write_manifest,
)
from attestra.scanner_runtime.process import run_with_shared_env
from attestra.scanner_runtime.versions import SUPPORTED, version_matches

__all__ = [
    "ENV_ROOT_VAR",
    "SUPPORTED",
    "ExtraVenvError",
    "ManifestError",
    "PackageStatus",
    "SharedEnvError",
    "SharedEnvironment",
    "assert_target_egress_allowed",
    "check_all",
    "check_node",
    "check_promptfoo",
    "check_python_package",
    "health_report",
    "list_manifests",
    "read_manifest",
    "reject_extra_venvs",
    "require_promptfoo",
    "require_python",
    "resolve_shared_env",
    "run_with_shared_env",
    "scanner_process_env",
    "shared_promptfoo",
    "shared_python",
    "version_matches",
    "write_manifest",
]
