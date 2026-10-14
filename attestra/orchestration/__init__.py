"""Scan orchestration: inline durable jobs (default) or Temporal workflows (Phase 6.2).

``ATTESTRA_ORCHESTRATOR=inline`` keeps the single-node behaviour: ``attestra worker``
polls the ``jobs`` table. ``ATTESTRA_ORCHESTRATOR=temporal`` starts one Temporal
workflow per ScanRun after the request transaction commits; ``attestra worker`` then
runs a Temporal worker. The ``jobs`` row stays the source of truth for status in both
modes, so the API, UI and kill switch work unchanged.
"""

from __future__ import annotations

import asyncio
import logging
import threading

from sqlalchemy import event
from sqlalchemy.orm import Session

from attestra import config

log = logging.getLogger(__name__)

ORCHESTRATORS = ("inline", "temporal")


def orchestrator() -> str:
    name = (config.ORCHESTRATOR or "inline").strip().lower()
    if name not in ORCHESTRATORS:
        raise ValueError(f"ATTESTRA_ORCHESTRATOR must be one of {ORCHESTRATORS}, got {name!r}")
    return name


def workflow_id_for(scan_run_id: int) -> str:
    return f"attestra-scan-{scan_run_id}"


def dispatch_scan(s: Session, scan_run_id: int, job_id: int) -> None:
    """Hand a freshly enqueued job to the configured orchestrator.

    Inline: nothing to do, the polling worker claims it. Temporal: start the
    workflow only after commit, so the activity can always see the rows. A failed
    start is logged; ``attestra worker`` re-dispatches queued jobs on its next sweep.
    """
    if orchestrator() != "temporal":
        return

    def _after_commit(_session) -> None:
        try:
            run_coro(start_scan_workflow(scan_run_id, job_id))
        except Exception as exc:  # noqa: BLE001 - logged; worker sweep retries
            log.warning("temporal dispatch for scan_run %s failed: %s", scan_run_id, exc)

    event.listen(s, "after_commit", _after_commit, once=True)


def run_coro(coro):
    """Run a coroutine from sync code, even when an event loop is already running."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    box: dict = {}

    def _target() -> None:
        try:
            box["value"] = asyncio.run(coro)
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join()
    if "error" in box:
        raise box["error"]
    return box.get("value")


async def connect():
    from temporalio.client import Client

    return await Client.connect(config.TEMPORAL_ADDRESS, namespace=config.TEMPORAL_NAMESPACE)


async def start_scan_workflow(scan_run_id: int, job_id: int, *, client=None) -> str:
    """Start ScanWorkflow; an already-running workflow for this scan is not an error."""
    from temporalio.exceptions import WorkflowAlreadyStartedError

    from attestra.orchestration.temporal_workflows import ScanWorkflow, ScanWorkflowInput

    client = client or await connect()
    wid = workflow_id_for(scan_run_id)
    try:
        await client.start_workflow(
            ScanWorkflow.run,
            ScanWorkflowInput(scan_run_id=scan_run_id, job_id=job_id),
            id=wid,
            task_queue=config.TEMPORAL_TASK_QUEUE,
        )
    except WorkflowAlreadyStartedError:
        pass
    return wid


async def cancel_scan_workflow(scan_run_id: int, *, client=None) -> None:
    client = client or await connect()
    await client.get_workflow_handle(workflow_id_for(scan_run_id)).cancel()
