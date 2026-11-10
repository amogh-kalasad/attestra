#!/usr/bin/env bash
# Wait until MongoDB accepts connections and (optionally) is PRIMARY.
# Intended to run inside Linux containers (Compose/dev), not on the Windows host.
set -euo pipefail

HOST="${1:-mongo}"
PORT="${2:-27017}"
REQUIRE_PRIMARY="${REQUIRE_PRIMARY:-1}"
TIMEOUT_SEC="${TIMEOUT_SEC:-90}"

deadline=$((SECONDS + TIMEOUT_SEC))

echo "Waiting for MongoDB at ${HOST}:${PORT} (primary=${REQUIRE_PRIMARY})..."

while (( SECONDS < deadline )); do
  if [[ "${REQUIRE_PRIMARY}" == "1" ]]; then
    eval_js='const ping = db.adminCommand({ ping: 1 }); if (!ping || ping.ok !== 1) { quit(2); } const h = db.hello(); if (!(h.isWritablePrimary || h.ismaster)) { quit(3); } quit(0);'
  else
    eval_js='const ping = db.adminCommand({ ping: 1 }); if (!ping || ping.ok !== 1) { quit(2); } quit(0);'
  fi
  if mongosh --host "${HOST}:${PORT}" --quiet --eval "${eval_js}" >/dev/null 2>&1; then
    echo "MongoDB ready at ${HOST}:${PORT}"
    exit 0
  fi
  sleep 1
done

echo "Timed out waiting for MongoDB at ${HOST}:${PORT}" >&2
exit 1
