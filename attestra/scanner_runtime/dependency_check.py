"""Check shared-runtime package versions against V5.1 pins.

Python packages are queried via the shared venv interpreter and
``importlib.metadata`` (not the host process). Node and Promptfoo are checked
as CLI binaries under the shared root.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from attestra.scanner_runtime.environment import (
    SharedEnvironment,
    require_promptfoo,
    require_python,
    resolve_shared_env,
)
from attestra.scanner_runtime.versions import (
    NODE_PIN,
    PROMPTFOO_PIN,
    PYTHON_PACKAGE_PINS,
    version_matches,
)

# Run under the shared interpreter; package name is sys.argv[1].
_META_SCRIPT = (
    "import importlib.metadata as m, json, sys\n"
    "n = sys.argv[1]\n"
    "try:\n"
    "    v = m.version(n)\n"
    "except m.PackageNotFoundError:\n"
    "    v = None\n"
    "print(json.dumps({'version': v}))\n"
)


@dataclass(frozen=True)
class PackageStatus:
    """Result of one dependency pin check."""

    name: str
    expected: str
    installed: str | None
    ok: bool
    detail: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _run_shared_python(python: Path, *args: str, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(python), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def check_python_package(
    name: str,
    *,
    env: SharedEnvironment | None = None,
    expected: str | None = None,
) -> PackageStatus:
    """Check one PyPI package via ``importlib.metadata`` in the shared venv."""
    shared = env or resolve_shared_env()
    pin = expected if expected is not None else PYTHON_PACKAGE_PINS.get(name, "")
    try:
        python = require_python(shared)
    except Exception as exc:  # noqa: BLE001 - surface as status, not crash
        return PackageStatus(name=name, expected=pin, installed=None, ok=False, detail=str(exc))

    try:
        proc = _run_shared_python(python, "-c", _META_SCRIPT, name)
    except OSError as exc:
        return PackageStatus(
            name=name,
            expected=pin,
            installed=None,
            ok=False,
            detail=f"shared python not executable: {exc}"[:500],
        )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "shared python metadata query failed").strip()[:500]
        return PackageStatus(name=name, expected=pin, installed=None, ok=False, detail=detail)

    try:
        payload = json.loads(proc.stdout.strip() or "{}")
        installed = payload.get("version")
    except json.JSONDecodeError:
        return PackageStatus(
            name=name,
            expected=pin,
            installed=None,
            ok=False,
            detail=f"unreadable metadata output: {proc.stdout[:200]!r}",
        )

    ok = version_matches(installed, pin) if pin else bool(installed)
    detail = "" if ok else f"expected {pin!r}, got {installed!r}"
    return PackageStatus(name=name, expected=pin, installed=installed, ok=ok, detail=detail)


def check_node(*, env: SharedEnvironment | None = None) -> PackageStatus:
    """Check Node major version under ``tools/node`` against the 20.x pin."""
    shared = env or resolve_shared_env()
    node = shared.node
    if not node.is_file():
        return PackageStatus(
            name="node",
            expected=NODE_PIN,
            installed=None,
            ok=False,
            detail=f"node binary not found at {node}",
        )
    try:
        proc = subprocess.run(
            [str(node), "--version"],
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
    except OSError as exc:
        return PackageStatus(
            name="node",
            expected=NODE_PIN,
            installed=None,
            ok=False,
            detail=f"node binary not executable: {exc}"[:500],
        )
    installed = (proc.stdout or proc.stderr or "").strip() or None
    if proc.returncode != 0 or not installed:
        return PackageStatus(
            name="node",
            expected=NODE_PIN,
            installed=installed,
            ok=False,
            detail=(proc.stderr or "node --version failed").strip()[:500],
        )
    ok = version_matches(installed, NODE_PIN)
    return PackageStatus(
        name="node",
        expected=NODE_PIN,
        installed=installed.lstrip("vV"),
        ok=ok,
        detail="" if ok else f"expected {NODE_PIN!r}, got {installed!r}",
    )


def check_promptfoo(*, env: SharedEnvironment | None = None) -> PackageStatus:
    """Check Promptfoo CLI version (npm) against ~0.118.x."""
    shared = env or resolve_shared_env()
    try:
        cli = require_promptfoo(shared)
    except Exception as exc:  # noqa: BLE001
        return PackageStatus(
            name="promptfoo",
            expected=PROMPTFOO_PIN,
            installed=None,
            ok=False,
            detail=str(exc),
        )
    try:
        proc = subprocess.run(
            [str(cli), "--version"],
            capture_output=True,
            text=True,
            timeout=60.0,
            check=False,
            env=shared.process_env(),
        )
    except OSError as exc:
        return PackageStatus(
            name="promptfoo",
            expected=PROMPTFOO_PIN,
            installed=None,
            ok=False,
            detail=f"promptfoo not executable: {exc}"[:500],
        )
    raw = (proc.stdout or proc.stderr or "").strip()
    installed = _parse_promptfoo_version(raw)
    if proc.returncode != 0 and not installed:
        return PackageStatus(
            name="promptfoo",
            expected=PROMPTFOO_PIN,
            installed=None,
            ok=False,
            detail=(proc.stderr or raw or "promptfoo --version failed")[:500],
        )
    ok = version_matches(installed, PROMPTFOO_PIN)
    return PackageStatus(
        name="promptfoo",
        expected=PROMPTFOO_PIN,
        installed=installed,
        ok=ok,
        detail="" if ok else f"expected {PROMPTFOO_PIN!r}, got {installed!r}",
    )


def _parse_promptfoo_version(raw: str) -> str | None:
    if not raw:
        return None
    # Common forms: "0.118.12", "promptfoo/0.118.12", first token with digits.
    for token in raw.replace(",", " ").split():
        cleaned = token.strip().lstrip("vV")
        if cleaned and cleaned[0].isdigit() and "." in cleaned:
            return cleaned.split("/")[-1]
    return raw.splitlines()[0].strip().lstrip("vV") or None


def check_all(*, env: SharedEnvironment | None = None) -> dict[str, PackageStatus]:
    """Check all V5.1 pins (Python packages + node + promptfoo)."""
    shared = env or resolve_shared_env()
    results: dict[str, PackageStatus] = {}
    for name in PYTHON_PACKAGE_PINS:
        results[name] = check_python_package(name, env=shared)
    results["node"] = check_node(env=shared)
    results["promptfoo"] = check_promptfoo(env=shared)
    return results
