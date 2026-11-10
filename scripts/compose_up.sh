#!/usr/bin/env bash
# Docker Compose install/up: ensure Fernet key in host .env, then build and start.
# Run from the repository root:
#   bash scripts/compose_up.sh
# Extra args are passed to `docker compose up` (default: -d --build).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -x .venv/bin/python ]]; then
  PY=".venv/bin/python"
else
  PY="python3"
fi

echo "==> Ensuring local-testing .env (Fernet, session, pepper, auth-web, VAPT, paths)"
"$PY" scripts/ensure_env_secrets.py --local-testing

if [[ "$#" -eq 0 ]]; then
  set -- -d --build
fi

echo "==> docker compose up $*"
docker compose up "$@"
echo "Done. UI: http://127.0.0.1:8000  Health: http://127.0.0.1:8000/api/health"
