#!/usr/bin/env python3
"""Validate AASI-related env without printing secret values.

Checks ATTESTRA_AASI (on/off) and digest shape for AI scanner image vars.
Never prints env values — only variable names and pass/fail reasons.

Usage (from repo root):
  python scripts/aasi/validate_aasi_env.py
  python scripts/aasi/validate_aasi_env.py --require-aasi-on
  python scripts/aasi/validate_aasi_env.py --require-ai-images
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# AI scanners with adapters (Phase 2 + Phase 5 PyRIT).
_AI_IMAGE_KEYS = (
    "ATTESTRA_IMAGE_GARAK",
    "ATTESTRA_IMAGE_PROMPTFOO",
    "ATTESTRA_IMAGE_SAFELABS",
    "ATTESTRA_IMAGE_PYRIT",
)
_OPTIONAL_IMAGE_KEYS: tuple[str, ...] = ()

_ZEROS = "0" * 64


def _aasi_enabled() -> bool:
    return os.environ.get("ATTESTRA_AASI", "off").strip().lower() in ("1", "true", "yes", "on")


def _digest_status(value: str) -> str:
    """Return ok | empty | not_digest | placeholder. Never echoes value."""
    if not value or not value.strip():
        return "empty"
    img = value.strip()
    if "@sha256:" not in img:
        return "not_digest"
    digest = img.split("@sha256:", 1)[-1]
    # Match attestra.config.image_is_placeholder: all-zero-style trailing hex.
    if digest[:-1].strip("0") == "" or digest == _ZEROS or "REPLACE" in digest.upper():
        return "placeholder"
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
        return "not_digest"
    return "ok"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate AASI env (no secret output)")
    p.add_argument(
        "--require-aasi-on",
        action="store_true",
        help="Exit non-zero when ATTESTRA_AASI is off",
    )
    p.add_argument(
        "--require-ai-images",
        action="store_true",
        help="Exit non-zero unless GARAK/PROMPTFOO/SAFELABS are real digest pins",
    )
    p.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="Optional .env to load into the process env before checks (values never printed)",
    )
    args = p.parse_args(argv)

    if args.env_file is not None:
        _load_dotenv_keys(args.env_file)

    errors = 0
    enabled = _aasi_enabled()
    print(f"ATTESTRA_AASI: {'on' if enabled else 'off'}")
    if args.require_aasi_on and not enabled:
        print("FAIL: ATTESTRA_AASI must be on (--require-aasi-on)")
        errors += 1
    else:
        print("OK: ATTESTRA_AASI flag readable")

    for key in _AI_IMAGE_KEYS:
        raw = os.environ.get(key, "")
        status = _digest_status(raw)
        if status == "ok":
            print(f"OK: {key} digest-pinned")
        elif status == "empty":
            print(f"WARN: {key} unset (adapter will use config placeholder and refuse run)")
            if args.require_ai_images:
                print(f"FAIL: {key} required (--require-ai-images)")
                errors += 1
        elif status == "placeholder":
            print(f"WARN: {key} is still a placeholder / REPLACE digest")
            if args.require_ai_images:
                print(f"FAIL: {key} must be a real @sha256: pin")
                errors += 1
        else:
            print(f"FAIL: {key} must be repo@sha256:<64-hex>")
            errors += 1

    for key in _OPTIONAL_IMAGE_KEYS:
        raw = os.environ.get(key, "")
        if not raw.strip():
            print(f"INFO: {key} unset (optional)")
            continue
        status = _digest_status(raw)
        if status == "ok":
            print(f"OK: {key} digest-pinned")
        elif status == "placeholder":
            print(f"WARN: {key} is still a placeholder")
        else:
            print(f"FAIL: {key} must be repo@sha256:<64-hex> when set")
            errors += 1

    # Do not inspect or print session/pepper/fernet/mongo secrets.
    print("NOTE: secret vars (SESSION/PEPPER/FERNET/MONGODB_URI/…) are not inspected or printed")

    if errors:
        print(f"validate_aasi_env: {errors} failure(s)")
        return 1
    print("validate_aasi_env: pass")
    return 0


def _load_dotenv_keys(path: Path) -> None:
    """Load KEY=VALUE lines into os.environ without printing values.

    Only sets keys that are not already in the environment. Skips blank/comment lines.
    """
    if not path.is_file():
        raise SystemExit(f"env file not found: {path}")
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        key, _, _val = s.partition("=")
        key = key.strip()
        if not key or key in os.environ:
            continue
        val = _val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        os.environ[key] = val


if __name__ == "__main__":
    raise SystemExit(main())
