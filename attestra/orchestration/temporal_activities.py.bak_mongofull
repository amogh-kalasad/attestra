"""Temporal activities wrapping the existing durable job steps (Phase 6.2).

Activities are synchronous (DB + subprocess work) and run in the worker's thread
pool. Each one opens its own session, so a retried attempt after a worker crash
starts from what is committed in the database.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from sqlalchemy import update
from temporalio import activity
from temporalio.exceptions import ApplicationError, CancelledError

from attestra import audit, db
from attestra.jobs import durable
from attestra.models import Job, ScanRun, utcnow

HEARTBEAT_EVERY_S = 2.0
TERMINAL = ("done", "failed", "cancelled")


@dataclass
class ScanActivityResult:
    job_status: str
    scan_status: str
    error: str = ""


def _claim(job_id: int, worker_id: str) -> str:
    """Claim this specific job. A row left 'running' by a dead attempt is reclaimed."""
    with db.session() as s:
        job = s.get(Job, job_id)
        if job is None:
            raise ApplicationError(f"job {job_id} not found", non_retryable=True)
        if job.status in TERMINAL:
            return job.status
        res = s.execute(
            update(Job)
            .where(Job.id == job_id, Job.status.in_(("queued", "running")))
            .values(status="running", worker_id=worker_id, heartbeat_at=utcnow(), attempts=Job.attempts + 1)
        )
        if res.rowcount != 1:
            return s.get(Job, job_id).status
        if job.status == "running":
            audit.record(s, "system", "job.recover", "job", job_id, via="temporal")
        return "running"


def _result(job_id: int) -> ScanActivityResult:
    with db.session() as s:
        job = s.get(Job, job_id)
        run = s.get(ScanRun, job.scan_run_id)
        return ScanActivityResult(job.status, run.status if run else "", job.error or "")


@activity.defn(name="attestra.run_scan_job")
def run_scan_job(job_id: int) -> ScanActivityResult:
    """Gate check, scanner run, hash and import for one job (``durable.run_one_job``)."""
    info = activity.info()
    worker_id = f"temporal:{info.workflow_id}:{info.attempt}"
    state = _claim(job_id, worker_id)
    if state in TERMINAL:
        return _result(job_id)

    with db.session() as s:
        engagement_id = s.get(Job, job_id).scan_run.engagement_id
    cancel = threading.Event()
    errors: list[BaseException] = []

    def _work() -> None:
        try:
            with db.session() as s:
                job = s.get(Job, job_id)
                durable.run_one_job(s, job, cancel=cancel)
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            errors.append(exc)

    t = threading.Thread(target=_work, name=f"attestra-scan-{job_id}", daemon=True)
    t.start()
    while t.is_alive():
        activity.heartbeat(job_id)
        if activity.is_cancelled() or _cancel_requested(job_id) or durable.cancel_event_for(engagement_id).is_set():
            cancel.set()
        t.join(HEARTBEAT_EVERY_S)

    if errors:
        _requeue(job_id, str(errors[0]))
        raise ApplicationError(f"scan job {job_id} crashed: {errors[0]}")
    result = _result(job_id)
    if result.job_status == "queued":
        # fail_job(retry=True) put it back in the queue: let Temporal own the retry/backoff.
        raise ApplicationError(f"scan job {job_id} failed, retrying: {result.error}")
    if result.job_status == "cancelled" and activity.is_cancelled():
        raise CancelledError("scan cancelled")
    return result


def _cancel_requested(job_id: int) -> bool:
    with db.session() as s:
        job = s.get(Job, job_id)
        return bool(job and job.cancel_requested)


def _requeue(job_id: int, error: str) -> None:
    with db.session() as s:
        job = s.get(Job, job_id)
        if job and job.status == "running":
            job.status = "queued"
            job.worker_id = ""
            job.error = error[:2000]


@activity.defn(name="attestra.mark_scan_cancelled")
def mark_scan_cancelled(job_id: int) -> ScanActivityResult:
    """Record a workflow cancel on the job + scan rows (idempotent)."""
    with db.session() as s:
        job = s.get(Job, job_id)
        if job is None:
            raise ApplicationError(f"job {job_id} not found", non_retryable=True)
        job.cancel_requested = True
        if job.status not in ("done", "failed"):
            job.status = "cancelled"
            run = s.get(ScanRun, job.scan_run_id)
            if run and run.status not in ("done", "failed", "refused", "quarantined"):
                run.status = "cancelled"
                run.ended_at = utcnow()
            audit.record(s, "system", "job.cancelled", "job", job.id, via="temporal")
    return _result(job_id)


@activity.defn(name="attestra.mark_scan_failed")
def mark_scan_failed(job_id: int, error: str) -> ScanActivityResult:
    """Retries exhausted: close the job as failed."""
    with db.session() as s:
        job = s.get(Job, job_id)
        if job and job.status not in TERMINAL:
            job.status = "failed"
            job.error = (error or job.error)[:2000]
            run = s.get(ScanRun, job.scan_run_id)
            if run and run.status in ("queued", "running"):
                run.status = "failed"
                run.ended_at = utcnow()
            audit.record(s, "system", "job.fail", "job", job.id, via="temporal", error=(error or "")[:500])
    return _result(job_id)


ACTIVITIES = [run_scan_job, mark_scan_cancelled, mark_scan_failed]
