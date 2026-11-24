#!/usr/bin/env python3
"""Thin wrapper: install Promptfoo under the shared env npm prefix only.

Delegates to ``install_shared_env.py --promptfoo-only`` so Node/npm and the
Python half share one code path. Promptfoo is never a pip package.

Usage (from repo root):
  python scripts/aasi/install_promptfoo_npm.py
  python scripts/aasi/install_promptfoo_npm.py --root /opt/attestra/runtime
  python scripts/aasi/install_promptfoo_npm.py --skip-node
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from install_shared_env import main as shared_main  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if "--promptfoo-only" not in args:
        args = ["--promptfoo-only", *args]
    return shared_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
