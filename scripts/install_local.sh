#!/usr/bin/env bash
# Local (venv) install: deps + auto Fernet key in .env + Mongo schema init.
# Run from the repository root:
#   bash scripts/install_local.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Creating/using .venv"
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
PY=".venv/bin/python"

echo "==> Installing package (dev extras)"
"$PY" -m pip install --upgrade pip
"$PY" -m pip install -e ".[dev]"

echo "==> Ensuring ATTESTRA_CREDENTIAL_FERNET_KEY in .env"
"$PY" scripts/ensure_env_secrets.py

echo "==> Mongo schema init (requires reachable ATTESTRA_MONGODB_URI)"
"$PY" -m attestra.cli init

echo "Done. Activate with: source .venv/bin/activate"
echo "Then: python -m attestra.cli serve   and   python -m attestra.cli worker"
