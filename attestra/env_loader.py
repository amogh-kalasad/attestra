"""Load a local ``.env`` file into ``os.environ`` at CLI startup.

No third-party dependency. Rules:

* Real environment variables always win: a key already set in the process
  environment is never overwritten by the file.
* File lookup order: ``ATTESTRA_ENV_FILE`` (explicit path) -> ``./.env`` in the
  current directory -> ``.env`` in the repository root (next to ``attestra/``).
* Set ``ATTESTRA_DOTENV=0`` (or ``off``/``false``/``no``) to disable loading.
* Supported syntax: blank lines, ``# comments``, optional ``export `` prefix,
  ``KEY=value``, single/double quoted values, inline `` # comment`` after an
  unquoted value, and values that contain ``=`` or ``@sha256:``.

This only fills in environment variables. Every safety rule stays in
``attestra.config`` (for example, BYPASS_* flags only take effect when
``APP_ENV`` is local/test/development, and ``validate_runtime_config`` still
rejects bypass flags in staging/production).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}

REPO_ROOT = Path(__file__).resolve().parent.parent


def _unquote_double(body: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body) and body[i + 1] in _ESCAPES:
            out.append(_ESCAPES[body[i + 1]])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _parse_value(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    quote = raw[0]
    if quote in ("'", '"'):
        end = raw.find(quote, 1)
        while quote == '"' and end != -1 and raw[end - 1] == "\\":
            end = raw.find(quote, end + 1)
        if end != -1:
            body = raw[1:end]
            return _unquote_double(body) if quote == '"' else body
        # Unterminated quote: keep the text after the opening quote as-is.
        return raw[1:]
    # Unquoted: strip an inline comment that starts with whitespace + '#'.
    m = re.search(r"\s#", raw)
    if m:
        raw = raw[: m.start()]
    return raw.strip()


def parse_env_text(text: str) -> dict[str, str]:
    """Parse ``.env`` text into a dict. Malformed lines are skipped."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip().lstrip("\ufeff")
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export "):].lstrip()
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        if not _KEY_RE.match(key):
            continue
        result[key] = _parse_value(value)
    return result


def find_env_file(cwd: Path | None = None) -> Path | None:
    """Return the ``.env`` path to load, or ``None`` when there is none."""
    explicit = os.environ.get("ATTESTRA_ENV_FILE", "").strip()
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.is_file() else None
    for candidate in ((cwd or Path.cwd()) / ".env", REPO_ROOT / ".env"):
        if candidate.is_file():
            return candidate
    return None


def dotenv_disabled() -> bool:
    return os.environ.get("ATTESTRA_DOTENV", "").strip().lower() in ("0", "off", "false", "no")


def load_env_file(path: Path | str | None = None, *, override: bool = False) -> dict[str, str]:
    """Load ``path`` (or the discovered ``.env``) into ``os.environ``.

    Returns the keys that were actually set. Existing environment variables
    are kept unless ``override=True``.
    """
    if path is None:
        if dotenv_disabled():
            return {}
        path = find_env_file()
        if path is None:
            return {}
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        return {}
    applied: dict[str, str] = {}
    for key, value in parse_env_text(text).items():
        if not override and key in os.environ:
            continue
        os.environ[key] = value
        applied[key] = value
    return applied
