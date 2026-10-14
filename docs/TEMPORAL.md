# Temporal scan orchestration (Phase 6.2)

Optional. The default stays `ATTESTRA_ORCHESTRATOR=inline`: `attestra worker` polls the
`jobs` table (single-node installs, all existing tests). With `temporal`, every scan request
starts one Temporal workflow and `attestra worker` runs a Temporal worker instead.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `ATTESTRA_ORCHESTRATOR` | `inline` | `inline` or `temporal` |
| `ATTESTRA_TEMPORAL_ADDRESS` | `localhost:7233` | Temporal frontend host:port |
| `ATTESTRA_TEMPORAL_NAMESPACE` | `default` | Temporal namespace |
| `ATTESTRA_TEMPORAL_TASK_QUEUE` | `attestra-scans` | task queue for workflows and activities |

Install: `pip install -e ".[temporal]"` (adds `temporalio`).

## How it works

- `services.request_scan` creates the ScanRun + Job as before, then `orchestration.dispatch_scan`
  starts workflow `attestra-scan-<scan_run_id>` **after the transaction commits**. If the start
  fails (server down), the job stays `queued` and the worker's sweep (every `--poll` s, min 5)
  starts it later. The sweep also enqueues due scan schedules. Starting is idempotent.
- `ScanWorkflow` (`attestra/orchestration/temporal_workflows.py`) runs activity
  `attestra.run_scan_job`, which claims that job and calls the existing
  `jobs.durable.run_one_job` (gate check, scanner, hash, import). The `jobs` / `scan_runs`
  rows stay the source of truth, so API, UI and reports are unchanged.
- Retries: a retryable failure (`fail_job(retry=True)`) raises to Temporal, which retries
  with backoff (5 s initial, x2, max 5 min, 3 attempts). When retries run out, activity
  `attestra.mark_scan_failed` closes the job. A worker crash mid-scan is retried by Temporal
  after the 30 s heartbeat timeout; the new attempt reclaims the `running` row.
- Cancel: cancelling the workflow (`temporal workflow cancel --workflow-id attestra-scan-<id>`
  or `orchestration.cancel_scan_workflow`) cancels the activity; it sets the scanner's cancel
  event (process killed) and `attestra.mark_scan_cancelled` records `cancelled`. The engagement
  kill switch (`halt_engagement`) also works: the activity polls `jobs.cancel_requested`
  and the in-process cancel event on every heartbeat.

## Local run (no Docker)

    temporal server start-dev --headless          # E:\tools\bin\temporal.exe, port 7233
    $env:ATTESTRA_ORCHESTRATOR = "temporal"
    attestra worker                               # second terminal
    attestra serve                                # third terminal; scan requests now start workflows

## Tests

`tests/jobs/test_temporal_orchestration.py` starts a local dev server through
`temporalio.testing.WorkflowEnvironment.start_local`, using the `temporal` CLI on PATH or
`ATTESTRA_TEMPORAL_CLI` (no binary download). Skipped if `temporalio` or the CLI is missing.
Covers: success + import, retry then success, retries exhausted -> failed, workflow cancel,
kill-switch event, inline no-op, dispatch only after commit.

## Not done yet

- Only the scan step is a workflow. The guide's full engagement chain (scope, triage, validate,
  map, report, retest) is still manual/API driven.
- Kill switch via the DB flag across processes needs Postgres; SQLite locks while a scan runs.
- No Helm values for a Temporal cluster yet; point `ATTESTRA_TEMPORAL_ADDRESS` at an existing one.