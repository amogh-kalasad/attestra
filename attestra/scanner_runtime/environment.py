"""Single shared scanner environment for AASI V5.1.

Exactly one Python venv lives under ``ATTESTRA_SHARED_ENV_ROOT`` (default
``<repo>/.attestra-runtime``). Promptfoo is Node/npm under the same root —
never a second venv and never Docker for AI scanners.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from attestra.env_loader import REPO_ROOT

# @lat: [[aasi#AASI (Attestra Agentic Security Intelligence)#V5.1 shared scanner runtime]]

ENV_ROOT_VAR = "ATTESTRA_SHARED_ENV_ROOT"
DEFAULT_ENV_DIRNAME = ".attestra-runtime"

# Layout under the shared root (relative paths).
LAYOUT_REL: tuple[str, ...] = (
    "venv",
    "tools/node",
    "npm",
    "manifests",
    "logs",
    "cache",
    "tmp",
)

# Names that look like forbidden per-scanner venvs (directory basenames).
_PER_SCANNER_VENV_NAMES = frozenset(
    {
        "venv-garak",
        "venv-safelabs",
        "venv-pyrit",
        "venv-promptfoo",
        ".venv-garak",
        ".venv-safelabs",
        ".venv-pyrit",
        ".venv-promptfoo",
        "garak-venv",
        "safelabs-venv",
        "pyrit-venv",
        "promptfoo-venv",
        ".garak-venv",
        ".safelabs-venv",
        ".pyrit-venv",
        ".promptfoo-venv",
    }
)


class SharedEnvError(RuntimeError):
    """Shared scanner environment is missing or misconfigured."""


class ExtraVenvError(SharedEnvError):
    """A per-scanner or extra venv was found; V5.1 allows only one shared venv."""


@dataclass(frozen=True)
class SharedEnvironment:
    """Resolved paths for the single shared AI-scanner runtime root."""

    root: Path

    @property
    def venv(self) -> Path:
        return self.root / "venv"

    @property
    def tools_node(self) -> Path:
        return self.root / "tools" / "node"

    @property
    def npm(self) -> Path:
        return self.root / "npm"

    @property
    def manifests(self) -> Path:
        return self.root / "manifests"

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    @property
    def cache(self) -> Path:
        return self.root / "cache"

    @property
    def tmp(self) -> Path:
        return self.root / "tmp"

    @property
    def python(self) -> Path:
        """Interpreter inside the shared venv (Windows ``Scripts``, else ``bin``)."""
        if sys.platform == "win32":
            return self.venv / "Scripts" / "python.exe"
        return self.venv / "bin" / "python"

    @property
    def venv_bin(self) -> Path:
        """Directory that holds venv executables (on PATH)."""
        if sys.platform == "win32":
            return self.venv / "Scripts"
        return self.venv / "bin"

    @property
    def node(self) -> Path:
        """Node binary under ``tools/node`` (Windows-aware)."""
        if sys.platform == "win32":
            direct = self.tools_node / "node.exe"
            if direct.exists():
                return direct
            nested = self.tools_node / "bin" / "node.exe"
            if nested.exists():
                return nested
            return direct
        direct = self.tools_node / "node"
        if direct.exists():
            return direct
        nested = self.tools_node / "bin" / "node"
        if nested.exists():
            return nested
        return direct

    @property
    def promptfoo(self) -> Path:
        """Promptfoo CLI under the shared npm prefix (``.cmd`` on Windows)."""
        if sys.platform == "win32":
            candidates = (
                self.npm / "promptfoo.cmd",
                self.npm / "node_modules" / ".bin" / "promptfoo.cmd",
                self.npm / "promptfoo.exe",
                self.npm / "node_modules" / ".bin" / "promptfoo.exe",
            )
        else:
            candidates = (
                self.npm / "bin" / "promptfoo",
                self.npm / "promptfoo",
                self.npm / "node_modules" / ".bin" / "promptfoo",
            )
        for path in candidates:
            if path.exists():
                return path
        return candidates[0]

    def ensure_layout(self) -> None:
        """Create the standard directories under ``root`` (idempotent)."""
        for rel in LAYOUT_REL:
            (self.root / rel).mkdir(parents=True, exist_ok=True)

    def process_env(self, base: dict[str, str] | None = None) -> dict[str, str]:
        """Return an env mapping with shared bin dirs prepended and PATH sanitized.

        Does not inject Docker socket or compose overrides. Existing ``VIRTUAL_ENV``
        pointing at a non-shared venv is cleared so child processes use this root.
        """
        env = dict(base if base is not None else os.environ)
        prepend: list[str] = []
        for directory in (self.venv_bin, self.tools_node, self.tools_node / "bin", self.npm, self.npm / "bin"):
            if directory.is_dir():
                prepend.append(str(directory))
        # Drop empty and dedupe while preserving order.
        seen: set[str] = set()
        ordered: list[str] = []
        for part in prepend:
            key = part.lower() if sys.platform == "win32" else part
            if key not in seen:
                seen.add(key)
                ordered.append(part)
        old_path = env.get("PATH", "")
        path_parts = [p for p in old_path.split(os.pathsep) if p]
        # Prefer shared bins; keep the rest so system tools remain reachable.
        for part in path_parts:
            key = part.lower() if sys.platform == "win32" else part
            if key not in seen:
                seen.add(key)
                ordered.append(part)
        env["PATH"] = os.pathsep.join(ordered)
        env["ATTESTRA_SHARED_ENV_ROOT"] = str(self.root)
        env["npm_config_prefix"] = str(self.npm)
        # Point VIRTUAL_ENV at the shared venv only.
        env["VIRTUAL_ENV"] = str(self.venv)
        # Never fall back to Docker for AI scanners via this env.
        env.pop("ATTESTRA_AI_SCANNER_DOCKER", None)
        return env


def default_shared_env_root() -> Path:
    """``ATTESTRA_SHARED_ENV_ROOT`` or ``<repo>/.attestra-runtime``."""
    raw = os.environ.get(ENV_ROOT_VAR, "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return (REPO_ROOT / DEFAULT_ENV_DIRNAME).resolve()


def resolve_shared_env(
    *,
    root: Path | str | None = None,
    create: bool = False,
) -> SharedEnvironment:
    """Resolve the shared environment; optionally create the layout directories.

    Does not create the venv or install packages — only path resolution / layout.
    """
    resolved = Path(root).expanduser().resolve() if root is not None else default_shared_env_root()
    env = SharedEnvironment(root=resolved)
    if create:
        env.ensure_layout()
    return env


def require_python(env: SharedEnvironment | None = None) -> Path:
    """Return the shared venv Python path, or raise if missing."""
    shared = env or resolve_shared_env()
    python = shared.python
    if not python.is_file():
        raise SharedEnvError(
            f"shared venv Python not found at {python}; "
            f"create the single venv under {shared.root / 'venv'} "
            f"(ATTESTRA_SHARED_ENV_ROOT={shared.root})"
        )
    return python


def shared_python(env: SharedEnvironment | None = None) -> str | None:
    """Return the shared venv Python path as a string, or ``None`` if missing.

    Soft resolver used by native adapters (``garak`` / ``safelabs`` / ``pyrit``).
    """
    shared = env or resolve_shared_env()
    python = shared.python
    return str(python) if python.is_file() else None


def require_promptfoo(env: SharedEnvironment | None = None) -> Path:
    """Return the shared npm Promptfoo CLI path, or raise if missing.

    Promptfoo must be installed via Node/npm under the shared root — never pip.
    """
    shared = env or resolve_shared_env()
    cli = shared.promptfoo
    if not cli.is_file():
        raise SharedEnvError(
            f"promptfoo CLI not found under {shared.npm}; "
            "install promptfoo with npm into the shared root "
            f"(expected ~0.118.x). Path tried: {cli}"
        )
    return cli


def shared_promptfoo(env: SharedEnvironment | None = None) -> str | None:
    """Return the shared Promptfoo CLI path as a string, or ``None`` if missing."""
    shared = env or resolve_shared_env()
    cli = shared.promptfoo
    return str(cli) if cli.is_file() else None


def reject_extra_venvs(
    *,
    search_roots: list[Path] | None = None,
    shared: SharedEnvironment | None = None,
) -> None:
    """Raise :class:`ExtraVenvError` if per-scanner or extra venvs are present.

    Allowed: exactly ``<shared.root>/venv``. Forbidden: named per-scanner venvs
    and any additional ``venv`` / ``.venv`` directories under the shared root or
    provided search roots.
    """
    shared = shared or resolve_shared_env()
    allowed = shared.venv.resolve()
    roots = list(search_roots) if search_roots is not None else [shared.root]
    # Always inspect the shared root for extras.
    if shared.root not in roots and shared.root.resolve() not in {r.resolve() for r in roots}:
        roots.append(shared.root)

    offenders: list[Path] = []
    for base in roots:
        base = Path(base)
        if not base.is_dir():
            continue
        for dirpath, dirnames, _filenames in os.walk(base):
            current = Path(dirpath)
            # Do not descend into the allowed venv tree.
            try:
                current.resolve().relative_to(allowed)
                in_allowed = True
            except ValueError:
                in_allowed = current.resolve() == allowed
            if in_allowed and current.resolve() != allowed:
                dirnames.clear()
                continue

            for name in list(dirnames):
                child = current / name
                try:
                    child_res = child.resolve()
                except OSError:
                    continue
                basename = name.lower()
                if basename in _PER_SCANNER_VENV_NAMES:
                    offenders.append(child_res)
                    continue
                if basename in {"venv", ".venv"} and child_res != allowed:
                    offenders.append(child_res)

    if offenders:
        unique = sorted({str(p) for p in offenders})
        raise ExtraVenvError(
            "AASI V5.1 allows exactly one shared venv at "
            f"{allowed}; found forbidden venv(s): {', '.join(unique)}"
        )
