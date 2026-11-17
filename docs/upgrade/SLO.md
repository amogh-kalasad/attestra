# Attestra workload classes, SLOs and load test (L-03)

This page defines the workload classes the platform serves, the service-level objectives
(SLOs) for each, the metrics that measure them (I-01), and how to run the staging load test
in `deploy/loadtest/attestra.js`. **The load test is for your own local or staging install
only.** It never targets scanned assets and refuses to run against a non-local URL unless
`ALLOW_REMOTE=1` is set on purpose for a staging host you own.

## Workload classes

| Class | Examples | Where it runs | Notes |
|---|---|---|---|
| **interactive** | login, dashboard, engagement page, findings list | API (`attestra serve`) | User-facing; latency matters most. |
| **api-read** | `GET /api/engagements/{id}/findings`, discovery candidate list, exports | API | Read-only JSON. |
| **api-write** | imports, report generation, candidate approve/reject | API | Bounded body size; audited. |
| **scan-job** | ZAP, nuclei, testssl, naabu, discovery adapters | Worker pool (`attestra worker --concurrency N`) | Minutes to hours; measured by queue age and duration. |
| **automated-run** | Elite automated VAPT execution | Worker pool (one at a time per worker) | Same slot pool as scan jobs. |
| **maintenance** | feed refresh, stuck-job scan | Worker housekeeping tick | Off unless `ATTESTRA_MAINTENANCE_ENABLED=1`. |

## SLOs (starting targets, revisit after a month of data)

| Class | SLI | Objective | Metric |
|---|---|---|---|
| interactive | p95 latency | < 2.0 s | `attestra_http_request_duration_seconds{route=...}` |
| interactive | error rate (5xx) | < 1% of requests | `attestra_http_requests_total{status=~"5.."}` |
| api-read | p95 latency | < 1.5 s | same histogram, API routes |
| api-write (import) | p95 latency | < 5 s for a 1 MB report | same histogram, `/api/engagements/{eid}/imports` |
| scan-job | queue age p90 | < 5 min when the pool is not saturated | `attestra_job_queue_age_seconds` |
| scan-job | stuck jobs | 0 for more than 10 min | `attestra_jobs_stuck` |
| scan-job | retry rate | < 5% of claimed jobs | `attestra_job_retries_total` / `attestra_events_total{kind="job.claimed"}` |
| worker | saturation | < 0.8 averaged over 15 min (scale out above) | `attestra_worker_saturation_ratio` |
| maintenance | task errors | 0 consecutive failures > 3 | `attestra_maintenance_runs_total{outcome="error"}` |

Queue age is reported only for job documents that carry an enqueue timestamp (`queued_at`
or `created_at`); see `WIRING_WP4.md` for the one-line enqueue change.

## Suggested alert rules (Prometheus)

```yaml
- alert: AttestraStuckJobs
  expr: max(attestra_jobs_stuck) > 0
  for: 10m
- alert: AttestraWorkerSaturated
  expr: avg_over_time(attestra_worker_saturation_ratio[15m]) > 0.8
  for: 15m
- alert: AttestraInteractiveLatency
  expr: histogram_quantile(0.95, sum by (le) (rate(attestra_http_request_duration_seconds_bucket[5m]))) > 2
  for: 10m
```

## Running the load test (staging only)

```
k6 run -e BASE_URL=http://127.0.0.1:8765 -e ENG_ID=1 deploy/loadtest/attestra.js
# staging host you own:
k6 run -e BASE_URL=https://attestra-staging.internal -e ALLOW_REMOTE=1 -e ENG_ID=3 \
       -e LT_USER=loadtest.lead -e LT_PASS=... deploy/loadtest/attestra.js
```

Scenarios map to the classes above: `interactive` (browse), `api_read` (findings, exports,
optional discovery list with `DISCOVERY=1`), `api_write` (imports at a low constant
rate). Thresholds in the script are the SLOs in this table. Running the script needs an
operator environment (k6 installed, a seeded engagement); nothing in CI runs it.
