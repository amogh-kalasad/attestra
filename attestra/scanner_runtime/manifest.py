"""Read/write JSON manifests under the shared runtime ``manifests/`` directory.

Manifests record installed tool versions and layout metadata for operators and
health checks. Filenames are constrained to safe basename stems.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attestra.scanner_runtime.environment import SharedEnvironment, resolve_shared_env

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ManifestError(ValueError):
    """Manifest name or contents are invalid."""


def _manifest_path(name: str, shared: SharedEnvironment) -> Path:
    stem = name[:-5] if name.endswith(".json") else name
    if not _SAFE_NAME.match(stem):
        raise ManifestError(f"unsafe manifest name: {name!r}")
    return shared.manifests / f"{stem}.json"


def write_manifest(
    name: str,
    data: dict[str, Any],
    *,
    env: SharedEnvironment | None = None,
    stamp: bool = True,
) -> Path:
    """Write ``data`` as JSON under ``manifests/<name>.json``; return the path."""
    shared = env or resolve_shared_env()
    shared.manifests.mkdir(parents=True, exist_ok=True)
    path = _manifest_path(name, shared)
    payload = dict(data)
    if stamp:
        payload.setdefault("written_at", datetime.now(timezone.utc).isoformat())
        payload.setdefault("shared_env_root", str(shared.root))
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def read_manifest(name: str, *, env: SharedEnvironment | None = None) -> dict[str, Any]:
    """Read and parse ``manifests/<name>.json``."""
    shared = env or resolve_shared_env()
    path = _manifest_path(name, shared)
    if not path.is_file():
        raise ManifestError(f"manifest not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestError(f"manifest root must be an object: {path}")
    return raw


def list_manifests(*, env: SharedEnvironment | None = None) -> list[str]:
    """Return sorted manifest stems (without ``.json``) under ``manifests/``."""
    shared = env or resolve_shared_env()
    if not shared.manifests.is_dir():
        return []
    return sorted(p.stem for p in shared.manifests.glob("*.json") if p.is_file())
