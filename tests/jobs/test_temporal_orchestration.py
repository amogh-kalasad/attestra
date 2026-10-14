"""Phase 6.2: Temporal ScanWorkflow against the temporalio time-skipping/local test server.

Skipped when ``temporalio`` is not installed or the test server cannot be started
(it downloads a server binary on first use).
"""
from __future__ import annotations

import asyncio
import uuid

import pytest

pytest.importorskip("temporalio")

from attestra.runner.scanners.base import ScannerResult  # noqa: E402


def _make_job(engagement_id: int, tool: str = "trivy"):
    from sqlalchemy import select

    from attestra import db
    from attestra.jobs.durable import enqueue
    from attestra.models import Asset, ScanRun

    with db.session() as s:
        asset = s.scalars(select(Asset).where(Asset.engagement_id == engagement_id, Asset.kind == "image")).first()
        run = ScanRun(
            engagement_id=engagement_id, asset_id=asset.id, tool=tool, profile="baseline",
            status="queued", requested_by="tester",
        )
        s.add(run)
        s.flush()
        job = enqueue(s, run.id)
        return run.id, job.id


class _FakeAdapter:
    def __init__(self, raw, *, fail_times: int = 0, block: bool = False):
        self.raw, self.fail_times, self.block, self.calls = raw, fail_times, block, 0

    def scan(self, target, *, out_dir, cancel, profile, **kw):
        self.calls += 1
        if self.block:
            cancel.wait(30)
            return ScannerResult(tool="trivy", raw_path=None, extra={"cancelled": True})
        if self.calls <= self.fail_times:
            return ScannerResult(tool="trivy", raw_path=None)
        return ScannerResult(tool="trivy", raw_path=self.raw, tool_version="fake-1", import_tool="trivy")


@pytest.fixture
def fake_adapter(monkeypatch, tmp_path):
    from attestra.jobs import durable
    from tests.conftest import FIXTURES

    raw = tmp_path / "trivy.json"
    raw.write_bytes((FIXTURES / "trivy.json").read_bytes())
    holder: dict = {}

    def factory(**kw):
        holder["a"] = _FakeAdapter(raw, **kw)
        monkeypatch.setattr(durable, "get_adapter", lambda tool: holder["a"])
        return holder["a"]

    return factory


async def _env():
    import os
    import shutil

    from temporalio.testing import WorkflowEnvironment

    # Use a local `temporal` CLI (no binary download). Set ATTESTRA_TEMPORAL_CLI or put it on PATH.
    cli = os.environ.get("ATTESTRA_TEMPORAL_CLI") or shutil.which("temporal")
    if not cli:
        pytest.skip("temporal CLI not found (set ATTESTRA_TEMPORAL_CLI)")
    try:
        return await WorkflowEnvironment.start_local(dev_server_existing_path=cli, ui=False)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"temporal test server unavailable: {exc}")


def _run(coro):
    return asyncio.run(coro)


def _input(run_id, job_id, **kw):
    from attestra.orchestration.temporal_workflows import ScanWorkflowInput

    return ScanWorkflowInput(scan_run_id=run_id, job_id=job_id, heartbeat_timeout_s=10, **kw)


def _statuses(run_id, job_id):
    from attestra import db
    from attestra.models import Job, ScanRun

    with db.session() as s:
        return s.get(Job, job_id).status, s.get(ScanRun, run_id).status


def test_workflow_runs_scan_and_imports(engagement, fake_adapter):
    from attestra.orchestration.temporal_worker import build_worker
    from attestra.orchestration.temporal_workflows import ScanWorkflow

    fake_adapter()
    run_id, job_id = _make_job(engagement)

    async def go():
        env = await _env()
        async with env:
            q = f"t-{uuid.uuid4().hex[:8]}"
            async with build_worker(env.client, task_queue=q):
                return await env.client.execute_workflow(
                    ScanWorkflow.run, _input(run_id, job_id), id=f"wf-{q}", task_queue=q
                )

    result = _run(go())
    assert result.job_status == "done"
    assert _statuses(run_id, job_id) == ("done", "done")


def test_workflow_retries_then_succeeds(engagement, fake_adapter, monkeypatch):
    from temporalio.common import RetryPolicy  # noqa: F401

    from attestra.orchestration.temporal_worker import build_worker
    from attestra.orchestration.temporal_workflows import ScanWorkflow

    adapter = fake_adapter(fail_times=1)
    run_id, job_id = _make_job(engagement)

    async def go():
        env = await _env()
        async with env:
            q = f"t-{uuid.uuid4().hex[:8]}"
            async with build_worker(env.client, task_queue=q):
                return await env.client.execute_workflow(
                    ScanWorkflow.run, _input(run_id, job_id), id=f"wf-{q}", task_queue=q
                )

    result = _run(go())
    assert adapter.calls == 2
    assert result.job_status == "done"


def test_workflow_exhausts_retries_marks_failed(engagement, fake_adapter):
    from attestra.orchestration.temporal_worker import build_worker
    from attestra.orchestration.temporal_workflows import ScanWorkflow

    adapter = fake_adapter(fail_times=99)
    run_id, job_id = _make_job(engagement)

    async def go():
        env = await _env()
        async with env:
            q = f"t-{uuid.uuid4().hex[:8]}"
            async with build_worker(env.client, task_queue=q):
                return await env.client.execute_workflow(
                    ScanWorkflow.run, _input(run_id, job_id, max_attempts=2), id=f"wf-{q}", task_queue=q
                )

    result = _run(go())
    assert adapter.calls == 2
    assert result.job_status == "failed"
    assert _statuses(run_id, job_id)[0] == "failed"


def test_workflow_cancel_stops_scanner(engagement, fake_adapter):
    from attestra.orchestration.temporal_worker import build_worker
    from attestra.orchestration.temporal_workflows import ScanWorkflow

    fake_adapter(block=True)
    run_id, job_id = _make_job(engagement)

    async def go():
        env = await _env()
        async with env:
            q = f"t-{uuid.uuid4().hex[:8]}"
            async with build_worker(env.client, task_queue=q):
                h = await env.client.start_workflow(
                    ScanWorkflow.run, _input(run_id, job_id), id=f"wf-{q}", task_queue=q
                )
                for _ in range(50):
                    if _statuses(run_id, job_id)[0] == "running":
                        break
                    await asyncio.sleep(0.2)
                await h.cancel()
                try:
                    await h.result()
                except Exception:  # noqa: BLE001 - WorkflowFailureError(cancelled) is expected
                    pass

    _run(go())
    assert _statuses(run_id, job_id) == ("cancelled", "cancelled")


def test_kill_switch_via_db_flag_cancels(engagement, fake_adapter):
    """Kill switch event (what halt_engagement signals in-process) stops the running scanner.

    halt_engagement also sets jobs.cancel_requested, which the activity polls for
    cross-process halts; that write needs Postgres (SQLite locks during the scan).
    """
    from attestra.jobs import durable
    from attestra.orchestration.temporal_worker import build_worker
    from attestra.orchestration.temporal_workflows import ScanWorkflow

    fake_adapter(block=True)
    run_id, job_id = _make_job(engagement)

    async def go():
        env = await _env()
        async with env:
            q = f"t-{uuid.uuid4().hex[:8]}"
            async with build_worker(env.client, task_queue=q):
                h = await env.client.start_workflow(
                    ScanWorkflow.run, _input(run_id, job_id), id=f"wf-{q}", task_queue=q
                )
                for _ in range(50):
                    if _statuses(run_id, job_id)[0] == "running":
                        break
                    await asyncio.sleep(0.2)
                durable.signal_engagement_cancel(engagement)
                return await asyncio.wait_for(h.result(), 30)

    try:
        result = _run(go())
    finally:
        durable.clear_engagement_cancel(engagement)
    assert result.job_status == "cancelled"


def test_dispatch_inline_is_noop(engagement, monkeypatch):
    from attestra import config
    from attestra.orchestration import dispatch_scan, orchestrator

    monkeypatch.setattr(config, "ORCHESTRATOR", "inline")
    assert orchestrator() == "inline"
    called = []
    monkeypatch.setattr("attestra.orchestration.start_scan_workflow", lambda *a, **k: called.append(a))
    from attestra import db

    with db.session() as s:
        dispatch_scan(s, 1, 1)
    assert called == []


def test_orchestrator_rejects_unknown(monkeypatch):
    from attestra import config
    from attestra.orchestration import orchestrator

    monkeypatch.setattr(config, "ORCHESTRATOR", "celery")
    with pytest.raises(ValueError):
        orchestrator()


def test_dispatch_temporal_starts_after_commit(engagement, monkeypatch):
    from attestra import config, db
    from attestra.orchestration import dispatch_scan

    monkeypatch.setattr(config, "ORCHESTRATOR", "temporal")
    started = []

    async def fake_start(run_id, job_id, **kw):
        started.append((run_id, job_id))

    monkeypatch.setattr("attestra.orchestration.start_scan_workflow", fake_start)
    with db.session() as s:
        dispatch_scan(s, 7, 9)
        assert started == []
    assert started == [(7, 9)]
