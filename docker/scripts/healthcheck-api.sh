#!/usr/bin/env bash
# Probe Attestra API liveness. Runs inside the API container (no curl required).
set -euo pipefail

URL="${1:-http://127.0.0.1:8000/api/health}"

python -c "
import sys
import urllib.request
url = sys.argv[1]
with urllib.request.urlopen(url, timeout=4) as resp:
    body = resp.read()
    if resp.status != 200:
        raise SystemExit(1)
print(body[:200].decode('utf-8', errors='replace'))
" "$URL"
