"""Run several scan jobs at once in one worker process (``attestra worker --concurrency N``).

One main thread does the housekeeping (stale-job recovery, gate re-checks, due schedules),
claims jobs and keeps their heartbeats fresh. Each claimed job runs in its own thread with
its own database session. Claiming is atomic (see :func:`attestra.jobs.durable.claim_job`).

Ctrl+C stops the scanners that are running, removes their containers and puts those jobs
back in the queue, so the next ``attestra worker`` picks them up again. A second Ctrl+C
exits at once (stale heartbeats are recovered on the next start).
"""

from __future__ import annotations

import os
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.exc import OperationalError

from attestra import db
from attestra.jobs import durable
from attestra.models import Job, ScanRun

MAX_CONCURRENCY = 8
# Tools that share on-disk state between runs and must not run twice at the same time:
# nuclei containers all mount the same template cache folder and update it on start.
SERIAL_TOOLS = frozenset({"nuclei"})
HEARTBEAT_EVERY_S = 30.0
SHUTDOWN_JOIN_S = 90.0


def resolve_concurrency(value: int | str | None = None) -> int:
    """CLI flag, else ATTESTRA_WORKER_CONCURRENCY, else 2; clamped to 1..MAX_CONCURRENCY."""
    raw = value if value not in (None, "") else os.environ.get("ATTESTRA_WORKER_CONCURRENCY", "2")
    try:
        n = int(raw)
    except (TypeError, ValueError):
        n = 2
    return max(1, min(MAX_CONCURRENCY, n))


@dataclass
class _Active:
    job_id: int
    tool: str
    thread: threading.Thread


@dataclass
class WorkerPool:
    worker_id: str
    concurrency: int = 2
    poll: float = 2.0
    log: Callable[[str], None] = print
    # Test hook: replaces durable.run_one_job(s, job).
    run_job: Callable | None = None
    housekeeping: bool = True
    # Worker instance lock file: touched with every heartbeat pass so the web page can
    # tell an idle worker is alive. Stop file: written by the Stop Worker button.
    lock_file: Path | None = None
    stop_file: Path | None = None
    stop_event: threading.Event = field(default_factory=threading.Event)
    _active: dict[int, _Active] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _shutdown_ids: set[int] = field(default_factory=set)
    _last_heartbeat: float = 0.0

    # ------------------------------------------------------------------ main loop
    def run_forever(self) -> None:
        try:
            while not self.stop_event.is_set():
                if self._stop_requested():
                    self.log("worker stopping: Stop Worker was clicked on the web page")
                    break
                started = self.tick()
                self.stop_event.wait(0.2 if started else self.poll)
        except KeyboardInterrupt:
            self.log("worker stopping: stopping running scans (press Ctrl+C again to force)")
            self.shutdown()
            return
        self.shutdown()

    def tick(self) -> int:
        """One pass: reap, housekeeping, heartbeats, claim up to free slots. Returns jobs started."""
        self._reap()
        if self.housekeeping:
            self._safe("housekeeping", self._housekeeping)
        self._heartbeat()
        started = 0
        while len(self.active_job_ids()) < self.concurrency and not self.stop_event.is_set():
            claimed = self._safe("claim", self._claim_one)
            if not claimed:
                break
            started += 1
        return started

    def active_job_ids(self) -> list[int]:
        with self._lock:
            return [a.job_id for a in self._active.values() if a.thread.is_alive()]

    def wait_idle(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._reap()
            with self._lock:
                if not self._active:
                    return True
            time.sleep(0.05)
        return False

    # ------------------------------------------------------------------ steps
    def _housekeeping(self) -> None:
        from attestra import services

        with db.session() as s:
            durable.recover_interrupted_jobs(s, exclude_worker_id=self.worker_id)
            durable.resume_queued_jobs(s)
            services.enqueue_due_schedules(s, actor=f"worker:{self.worker_id}")

    def _heartbeat(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_heartbeat < HEARTBEAT_EVERY_S:
            return
        ids = self.active_job_ids()
        self._last_heartbeat = now
        self._touch_lock()
        if ids:
            self._safe("heartbeat", self._touch, ids)

    def _touch_lock(self) -> None:
        if self.lock_file is None:
            return
        try:
            os.utime(self.lock_file, None)
        except OSError:
            pass

    def _stop_requested(self) -> bool:
        if self.stop_file is None:
            return False
        try:
            if not self.stop_file.exists():
                return False
            self.stop_file.unlink(missing_ok=True)
        except OSError:
            pass
        return True

    def _touch(self, ids: list[int]) -> None:
        with db.session() as s:
            durable.touch_heartbeats(s, ids, self.worker_id)

    def _claim_one(self) -> bool:
        with self._lock:
            busy = {a.tool for a in self._active.values() if a.thread.is_alive()}
        exclude = sorted(busy & SERIAL_TOOLS)
        with db.session() as s:
            job = durable.claim_job(s, self.worker_id, exclude_tools=exclude)
            if job is None:
                return False
            job_id = job.id
            run = s.get(ScanRun, job.scan_run_id)
            tool = run.tool if run else ""
        # Claim committed (session closed) before the scan thread opens its own session.
        t = threading.Thread(target=self._run, args=(job_id,), name=f"attestra-job-{job_id}", daemon=True)
        with self._lock:
            self._active[job_id] = _Active(job_id=job_id, tool=tool, thread=t)
        self.log(f"job {job_id} started ({tool or 'unknown tool'}); running {len(self.active_job_ids()) + 1}/{self.concurrency}")
        t.start()
        return True

    def _run(self, job_id: int) -> None:
        runner = self.run_job or durable.run_one_job
        try:
            with db.session() as s:
                job = s.get(Job, job_id)
                if job is None or job.status != "running" or job.worker_id != self.worker_id:
                    return
                runner(s, job)
        except Exception as exc:  # noqa: BLE001 - one broken job must not stop the other threads
            self.log(f"job {job_id} crashed: {exc}\n{traceback.format_exc()}")
            self._safe("fail", self._fail_crashed, job_id, str(exc))

    def _fail_crashed(self, job_id: int, error: str) -> None:
        with db.session() as s:
            job = s.get(Job, job_id)
            if job is not None and job.status == "running":
                durable.fail_job(s, job, f"worker error: {error}")
                run = s.get(ScanRun, job.scan_run_id)
                if run is not None and job.status == "failed":
                    run.status = "failed"
                    run.refuse_reason = f"worker error: {error}"[:500]
                elif run is not None:
                    run.status = "queued"

    def _reap(self) -> None:
        with self._lock:
            done = [jid for jid, a in self._active.items() if not a.thread.is_alive()]
            for jid in done:
                self._active.pop(jid, None)
        for jid in done:
            if jid in self._shutdown_ids:
                self._safe("requeue", self._requeue_after_shutdown, jid)
            else:
                self.log(f"job {jid} finished")

    def _requeue_after_shutdown(self, job_id: int) -> None:
        """A scan stopped by Ctrl+C (not by a user cancel) goes back to the queue."""
        self._shutdown_ids.discard(job_id)
        with db.session() as s:
            job = s.get(Job, job_id)
            if job is None or job.cancel_requested:
                return
            if job.status in ("cancelled", "running"):
                job.status = "queued"
                job.worker_id = ""
                run = s.get(ScanRun, job.scan_run_id)
                if run is not None and run.status in ("cancelled", "running"):
                    run.status = "queued"
                    run.ended_at = None
                self.log(f"job {job_id} put back in the queue")

    def shutdown(self) -> None:
        self.stop_event.set()
        ids = self.active_job_ids()
        for jid in ids:
            self._shutdown_ids.add(jid)
            durable.signal_job_cancel(jid)
        try:
            deadline = time.monotonic() + SHUTDOWN_JOIN_S
            while self.active_job_ids() and time.monotonic() < deadline:
                time.sleep(0.2)
        except KeyboardInterrupt:
            self.log("forced stop: running jobs will be recovered on the next start")
            return
        self._reap()
        left = self.active_job_ids()
        if left:
            self.log(f"{len(left)} job(s) still stopping; they will be recovered on the next start")

    def _safe(self, what: str, fn, *args):
        try:
            return fn(*args)
        except OperationalError as exc:  # e.g. SQLite busy: try again on the next pass
            self.log(f"{what}: database busy, retrying ({exc.__class__.__name__})")
        except Exception as exc:  # noqa: BLE001 - keep the worker alive
            self.log(f"{what} failed: {exc}")
        return None
