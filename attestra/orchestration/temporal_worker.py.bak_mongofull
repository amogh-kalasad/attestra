"""``attestra worker`` when ATTESTRA_ORCHESTRATOR=temporal (Phase 6.2)."""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging

from sqlalchemy import select

from attestra import config, db, services
from attestra.models import Job

log = logging.getLogger(__name__)


def build_worker(client, *, task_queue: str | None = None, max_workers: int = 4):
    from temporalio.worker import Worker
    from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

    from attestra.orchestration.temporal_activities import ACTIVITIES
    from attestra.orchestration.temporal_workflows import WORKFLOWS

    return Worker(
        client,
        task_queue=task_queue or config.TEMPORAL_TASK_QUEUE,
        workflows=WORKFLOWS,
        activities=ACTIVITIES,
        # attestra modules are side-effect free at import for workflow purposes; pass them through
        # so the sandbox does not re-import config (Path.cwd) per workflow run.
        workflow_runner=SandboxedWorkflowRunner(
            restrictions=SandboxRestrictions.default.with_passthrough_modules("attestra", "sqlalchemy")
        ),
        activity_executor=concurrent.futures.ThreadPoolExecutor(max_workers=max_workers),
    )


async def sweep(client, *, actor: str = "worker:temporal") -> int:
    """Enqueue due schedules and (re)start workflows for queued jobs. Idempotent."""
    from attestra.orchestration import start_scan_workflow

    with db.session() as s:
        services.enqueue_due_schedules(s, actor=actor)
    with db.session() as s:
        pending = [(j.scan_run_id, j.id) for j in s.scalars(select(Job).where(Job.status == "queued"))]
    for run_id, job_id in pending:
        await start_scan_workflow(run_id, job_id, client=client)
    return len(pending)


async def run_worker(*, poll: float = 15.0) -> None:
    from attestra.orchestration import connect

    client = await connect()
    worker = build_worker(client)
    print(f"temporal worker on {config.TEMPORAL_ADDRESS} queue={config.TEMPORAL_TASK_QUEUE}")

    async def _sweeper() -> None:
        while True:
            try:
                await sweep(client)
            except Exception as exc:  # noqa: BLE001
                log.warning("sweep failed: %s", exc)
            await asyncio.sleep(poll)

    sweeper = asyncio.create_task(_sweeper())
    try:
        await worker.run()
    finally:
        sweeper.cancel()
