"""Thin process wrapper that runs argv under the shared scanner environment.

Sanitizes PATH via :meth:`SharedEnvironment.process_env`, strips host secrets via
:func:`scanner_process_env`, and delegates to
``attestra.runner.scanners.base.run_process``. Does not use Docker.
"""

from __future__ import annotations

import threading
from pathlib import Path

from attestra.runner.scanners.base import ProcessResult, run_process
from attestra.scanner_runtime.egress import scanner_process_env
from attestra.scanner_runtime.environment import SharedEnvironment, resolve_shared_env


def run_with_shared_env(
    argv: list[str],
    *,
    env: SharedEnvironment | None = None,
    timeout: float | None = None,
    cancel: threading.Event | None = None,
    cwd: str | Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> ProcessResult:
    """Run ``argv`` with the shared runtime PATH; never shells out via Docker."""
    shared = env or resolve_shared_env()
    path_env = shared.process_env()
    merged = scanner_process_env(base=path_env, extra=extra_env)
    return run_process(argv, timeout=timeout, cancel=cancel, cwd=cwd, env=merged)
