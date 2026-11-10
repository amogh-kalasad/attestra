#!/usr/bin/env python3
"""Ensure local ``.env`` has ATTESTRA_CREDENTIAL_FERNET_KEY (install / compose prep).

Creates ``.env`` from ``.env.example`` when missing, then generates a Fernet key
only if the variable is absent or empty. Never prints or overwrites an existing key.

Usage (from repo root):
  python scripts/ensure_env_secrets.py
  python scripts/ensure_env_secrets.py --env-file path/to/.env
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from attestra.env_bootstrap import (  # noqa: E402
    FERNET_KEY_NAME,
    ensure_credential_fernet_key,
    ensure_local_testing_env,
)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Ensure ATTESTRA_CREDENTIAL_FERNET_KEY in .env")
    p.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="Path to .env (default: repo or cwd .env)",
    )
    p.add_argument(
        "--example",
        type=Path,
        default=None,
        help="Path to .env.example used when creating a new .env",
    )
    p.add_argument(
        "--local-testing",
        action="store_true",
        help="Also fill recommended local Compose flags and session/pepper secrets",
    )
    p.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Absolute host data dir written as ATTESTRA_DOCKER_HOST_DATA_DIR",
    )
    args = p.parse_args(argv)

    if args.local_testing:
        local = ensure_local_testing_env(
            args.env_file, example_path=args.example, data_dir=args.data_dir
        )
        changed = ", ".join(local.changed_keys) if local.changed_keys else "none"
        print(f"ensure_env_secrets: env={local.env_path}; local-testing changed: {changed}")
        return 0

    result = ensure_credential_fernet_key(args.env_file, example_path=args.example)
    bits = [f"env={result.env_path}"]
    if result.created_env_file:
        bits.append("created .env from example")
    if result.generated:
        bits.append(f"generated {FERNET_KEY_NAME}")
    elif result.already_set:
        bits.append(f"{FERNET_KEY_NAME} already set (unchanged)")
    print("ensure_env_secrets: " + "; ".join(bits))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
