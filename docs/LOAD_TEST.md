# Load test (Phase 8.2)

> **Local run, not staging.** These numbers come from one developer PC (16 GB RAM, Windows,
> Docker Desktop). Repeat the run against the staging Helm install before treating them as
> capacity figures.

## Setup

- App: `attestra serve --port 8765` (single uvicorn process), code as of Phase 7.
- Database: local Docker `postgres:16`, migrated to `0008_tuning`, seeded with `attestra demo`
  (1 engagement, 12 findings; findings grow as imports run).
- `ATTESTRA_API_RATE_LIMIT` raised so the limiter does not distort the run.
- Tool: k6, script `deploy/loadtest/attestra.js`.
- Load: ramp to **10 virtual users** over 30 s, hold 2 min, ramp down 15 s (about 2 min 45 s).
- Each iteration: form login, dashboard (`/`), 3 x findings list (API), import a ZAP file
  (20% of iterations), SARIF export.

## Command

```
k6 run -e BASE_URL=http://127.0.0.1:8765 -e ENG_ID=1 deploy/loadtest/attestra.js
```

Options: `VUS`, `RAMP`, `HOLD`, `LT_USER`, `LT_PASS`, `IMPORT_FILE`.
Only run against your own local or staging install.

## Results (2026-10-14, local)

| Request | p95 | avg | max |
| --- | --- | --- | --- |
| Login (POST /login) | 313 ms | 183 ms | 588 ms |
| Dashboard (GET /) | 145 ms | 70 ms | 357 ms |
| Findings list (GET /api/engagements/1/findings) | 145 ms | 58 ms | 453 ms |
| Import (POST .../imports, ZAP) | 296 ms | 140 ms | 411 ms |
| Export (GET .../export/sarif) | 205 ms | 73 ms | 540 ms |
| **All requests** | **220 ms** | 85 ms | 588 ms |

- Requests: 2,911 (17.6 req/s), iterations: 471.
- **Error rate: 0.00%** (0 of 2,911); all 2,911 checks passed.
- All k6 thresholds passed (errors < 1%, p95 limits per endpoint in the script).

## Still to do

- Run on staging (Helm install, Postgres with RLS, workers) with more VUs and report generation.
