"""Temporal workflow definitions (Phase 6.2). Deterministic code only; no DB access here."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, CancelledError

with workflow.unsafe.imports_passed_through():
    from attestra.orchestration.temporal_activities import ScanActivityResult


@dataclass
class ScanWorkflowInput:
    scan_run_id: int
    job_id: int
    max_attempts: int = 3
    scan_timeout_s: int = 3600
    heartbeat_timeout_s: int = 30


@workflow.defn(name="attestra.ScanWorkflow")
class ScanWorkflow:
    """One scan request: run the job with retries; record cancel or final failure."""

    def __init__(self) -> None:
        self._status = "queued"

    @workflow.query
    def status(self) -> str:
        return self._status

    @workflow.run
    async def run(self, inp: ScanWorkflowInput) -> ScanActivityResult:
        self._status = "running"
        try:
            result = await workflow.execute_activity(
                "attestra.run_scan_job",
                inp.job_id,
                result_type=ScanActivityResult,
                start_to_close_timeout=timedelta(seconds=inp.scan_timeout_s),
                heartbeat_timeout=timedelta(seconds=inp.heartbeat_timeout_s),
                cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=5),
                    backoff_coefficient=2.0,
                    maximum_interval=timedelta(minutes=5),
                    maximum_attempts=inp.max_attempts,
                ),
            )
        except (asyncio.CancelledError, CancelledError):
            self._status = "cancelled"
            await workflow.execute_activity(
                "attestra.mark_scan_cancelled",
                inp.job_id,
                result_type=ScanActivityResult,
                start_to_close_timeout=timedelta(seconds=60),
            )
            raise
        except ActivityError as exc:
            if isinstance(exc.cause, CancelledError):
                self._status = "cancelled"
                return await workflow.execute_activity(
                    "attestra.mark_scan_cancelled",
                    inp.job_id,
                    result_type=ScanActivityResult,
                    start_to_close_timeout=timedelta(seconds=60),
                )
            self._status = "failed"
            return await workflow.execute_activity(
                "attestra.mark_scan_failed",
                args=[inp.job_id, str(exc.cause or exc)],
                result_type=ScanActivityResult,
                start_to_close_timeout=timedelta(seconds=60),
            )
        self._status = result.job_status
        return result


WORKFLOWS = [ScanWorkflow]
