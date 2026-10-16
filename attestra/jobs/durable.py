"""Durable SQLAlchemy-backed job queue for ScanRuns."""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from attestra import audit, config, services
from attestra.models import Job, ScanRun, utcnow
from attestra.runner.authorization import scope_for_engagement
from attestra.runner.gate import GateError, check
from attestra.runner.scanners.registry import get_adapter

# engagement_id → Event set by kill switch so run_process exits quickly
_ENGAGEMENT_CANCEL: dict[int, threading.Event] = {}


def signal_engagement_cancel(engagement_id: int) -> None:
    ev = _ENGAGEMENT_CANCEL.setdefault(engagement_id, threading.Event())
    ev.set()


def clear_engagement_cancel(engagement_id: int) -> None:
    ev = _ENGAGEMENT_CANCEL.pop(engagement_id, None)
    if ev:
        ev.clear()


def cancel_event_for(engagement_id: int) -> threading.Event:
    return _ENGAGEMENT_CANCEL.setdefault(engagement_id, threading.Event())


def enqueue(s: Session, scan_run_id: int) -> Job:
    job = Job(scan_run_id=scan_run_id, status="queued")
    s.add(job)
    s.flush()
    audit.record(s, "system", "job.enqueue", "job", job.id, scan_run_id=scan_run_id)
    return job


def claim_job(s: Session, worker_id: str) -> Job | None:
    """Atomically claim the next queued job."""
    job = s.scalars(select(Job).where(Job.status == "queued").order_by(Job.id).limit(1)).first()
    if not job:
        return None
    result = s.execute(
        update(Job)
        .where(Job.id == job.id, Job.status == "queued")
        .values(
            status="running",
            worker_id=worker_id,
            heartbeat_at=utcnow(),
            attempts=job.attempts + 1,
        )
    )
    if result.rowcount != 1:
        return None
    s.refresh(job)
    return job


def mark_job_running(s: Session, job: Job) -> None:
    job.status = "running"
    job.heartbeat_at = utcnow()


def complete_job(s: Session, job: Job) -> None:
    job.status = "done"
    job.heartbeat_at = utcnow()
    audit.record(s, job.worker_id or "worker", "job.complete", "job", job.id)


def fail_job(s: Session, job: Job, error: str, *, retry: bool = True) -> None:
    job.error = error[:2000]
    if retry and job.attempts < config.JOB_MAX_ATTEMPTS and not job.cancel_requested:
        job.status = "queued"
        job.worker_id = ""
    else:
        job.status = "failed"
    audit.record(s, job.worker_id or "worker", "job.fail", "job", job.id, error=error[:500])


def request_cancel(s: Session, job_id: int) -> Job:
    job = s.get(Job, job_id)
    if not job:
        raise LookupError(f"job {job_id} not found")
    job.cancel_requested = True
    audit.record(s, "system", "job.cancel_requested", "job", job.id)
    return job


def recover_interrupted_jobs(s: Session) -> int:
    """Requeue jobs with stale heartbeats."""
    cutoff = utcnow() - timedelta(seconds=config.JOB_STALE_HEARTBEAT_S)
    jobs = list(s.scalars(select(Job).where(Job.status == "running", Job.heartbeat_at < cutoff)))
    for job in jobs:
        job.status = "queued"
        job.worker_id = ""
        audit.record(s, "system", "job.recover", "job", job.id)
    return len(jobs)


def resume_queued_jobs(s: Session, worker_id: str | None = None) -> int:
    """Re-check gate for queued jobs; refuse those outside the window."""
    n = 0
    for job in s.scalars(select(Job).where(Job.status == "queued")):
        run = s.get(ScanRun, job.scan_run_id)
        if not run:
            continue
        try:
            check(s, run.engagement_id, run.asset_id, tool=run.tool, profile=run.profile, actor=run.requested_by)
        except GateError as exc:
            run.status = "refused"
            run.refuse_reason = exc.reason
            job.status = "failed"
            job.error = exc.reason
            n += 1
    return n


def run_one_job(s: Session, job: Job, *, cancel: threading.Event | None = None) -> None:
    """Execute adapter → hash raw → import → complete (or quarantine/fail)."""
    run = s.get(ScanRun, job.scan_run_id)
    if not run:
        fail_job(s, job, "scan_run missing", retry=False)
        return
    if job.cancel_requested:
        run.status = "cancelled"
        job.status = "cancelled"
        return

    try:
        target = check(
            s, run.engagement_id, run.asset_id, tool=run.tool, profile=run.profile, actor=run.requested_by
        )
    except GateError as exc:
        run.status = "refused"
        run.refuse_reason = exc.reason
        fail_job(s, job, exc.reason, retry=False)
        return

    run.status = "running"
    run.started_at = utcnow()
    job.heartbeat_at = utcnow()
    # Commit before the scanner starts: the page shows "Running", and the database is not
    # held write-locked (SQLite) for the minutes a scan takes.
    s.commit()
    adapter = get_adapter(run.tool)
    out_dir = config.DATA_DIR / "raw" / f"scan-{run.id}"
    cancel = cancel or cancel_event_for(run.engagement_id)
    if job.cancel_requested:
        cancel.set()

    asset = run.asset
    kwargs = {"out_dir": out_dir, "cancel": cancel, "profile": run.profile}
    try:
        if run.tool == "nuclei":
            result = adapter.scan(target, intrusive_allowed=bool(asset.intrusive_allowed), **kwargs)  # type: ignore[call-arg]
        elif run.tool in ("zap", "webcheck"):
            scope = scope_for_engagement(s, run.engagement_id)
            result = adapter.scan(target, scope=scope, **kwargs)  # type: ignore[call-arg]
        else:
            result = adapter.scan(target, **kwargs)
    except Exception as exc:  # noqa: BLE001 - a broken scanner run must not stop the worker
        _fail_run(s, run, job, f"{run.tool} could not run: {exc}")
        return

    if result.extra.get("cancelled") or job.cancel_requested:
        run.status = "cancelled"
        job.status = "cancelled"
        run.ended_at = utcnow()
        return

    if result.error:
        _fail_run(s, run, job, result.error)
        return

    if result.quarantine:
        run.status = "quarantined"
        run.refuse_reason = result.quarantine_reason
        run.ended_at = utcnow()
        audit.record(s, run.requested_by, "scan.quarantined", "scan_run", run.id, reason=result.quarantine_reason)
        fail_job(s, job, result.quarantine_reason, retry=False)
        return

    if not result.raw_path or not result.raw_path.exists():
        run.status = "failed"
        run.ended_at = utcnow()
        fail_job(s, job, "no raw output")
        return

    sha = _hash_file(result.raw_path)
    run.raw_artifact_uri = str(result.raw_path)
    run.raw_sha256 = sha
    run.tool_version = result.tool_version
    run.image_digest = result.image_digest
    # C5: persist pass/fail check list from the scanner when present.
    check_rows = result.extra.get("checks") if isinstance(result.extra, dict) else None
    if not check_rows and result.raw_path:
        try:
            from attestra import checks as checklib

            doc = json.loads(result.raw_path.read_text(encoding="utf-8"))
            if isinstance(doc, dict):
                if run.tool == "webcheck" or (result.import_tool or "") == "webcheck":
                    check_rows = checklib.checks_from_webcheck_report(doc)
                elif run.tool == "zap":
                    check_rows = checklib.zap_checks_from_report(result.raw_path.read_bytes())
        except Exception:
            check_rows = None
    if check_rows:
        run.checks_json = json.dumps({"checks": check_rows})
        try:
            from attestra.checks import write_checks_sidecar

            write_checks_sidecar(result.raw_path, check_rows)
        except OSError:
            pass
    data = result.raw_path.read_bytes()
    try:
        imp = services.import_results(
            s,
            run.engagement_id,
            tool=result.import_tool or run.tool,
            filename=result.raw_path.name,
            data=data,
            actor=run.requested_by,
            default_asset_id=run.asset_id,
        )
        run.import_run_id = imp.id
        run.status = "done"
        run.ended_at = utcnow()
        complete_job(s, job)
    except Exception as exc:
        run.status = "failed"
        run.ended_at = utcnow()
        run.refuse_reason = f"import failed: {exc}"[:500]
        fail_job(s, job, str(exc))


def _fail_run(s: Session, run: ScanRun, job: Job, error: str) -> None:
    """Scanner did not produce a usable report: fail the run (no retry) and show why."""
    run.status = "failed"
    run.ended_at = utcnow()
    run.refuse_reason = error[:500]
    audit.record(s, run.requested_by, "scan.failed", "scan_run", run.id, error=error[:500])
    fail_job(s, job, error, retry=False)


def _hash_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def new_worker_id() -> str:
    return f"worker-{uuid.uuid4().hex[:12]}"
