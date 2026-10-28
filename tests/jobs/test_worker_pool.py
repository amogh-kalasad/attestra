"""Worker concurrency: atomic claims across threads, parallel runs, nuclei serialised, clean stop."""
from __future__ import annotations

import threading
import time
from datetime import timedelta

import pytest
from sqlalchemy import select

from attestra import db
from attestra.jobs import durable
from attestra.jobs.pool import WorkerPool, resolve_concurrency
from attestra.models import Asset, Job, ScanRun, utcnow


def _make_jobs(engagement: int, n: int, tool: str = "trivy") -> list[int]:
    ids = []
    with db.session() as s:
        asset = s.scalars(select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "repo")).first()
        for _ in range(n):
            run = ScanRun(engagement_id=engagement, asset_id=asset.id, tool=tool, profile="baseline",
                          status="queued", requested_by="tester")
            s.add(run)
            s.flush()
            ids.append(durable.enqueue(s, run.id).id)
    return ids


def _finish(s, job, status="done"):
    job.status = status
    run = s.get(ScanRun, job.scan_run_id)
    run.status = status


# ---------------------------------------------------------------- claim safety


def test_concurrent_claims_never_hand_out_the_same_job(engagement):
    job_ids = _make_jobs(engagement, 24)
    claimed: dict[str, list[int]] = {}
    errors: list[BaseException] = []
    start = threading.Barrier(8)

    def claimer(name: str):
        mine: list[int] = []
        try:
            start.wait()
            misses = 0
            while misses < 3:
                with db.session() as s:
                    job = durable.claim_job(s, name)
                    jid = job.id if job else None
                if jid is None:
                    misses += 1
                    time.sleep(0.01)
                else:
                    mine.append(jid)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
        claimed[name] = mine

    threads = [threading.Thread(target=claimer, args=(f"w{i}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not errors, errors
    flat = [j for ids in claimed.values() for j in ids]
    assert sorted(flat) == sorted(job_ids), "every job claimed exactly once"
    assert len(flat) == len(set(flat))
    with db.session() as s:
        for name, ids in claimed.items():
            for jid in ids:
                job = s.get(Job, jid)
                assert job.status == "running" and job.worker_id == name and job.attempts == 1


def test_claim_skips_excluded_tools(engagement):
    nuclei = _make_jobs(engagement, 1, tool="nuclei")[0]
    trivy = _make_jobs(engagement, 1, tool="trivy")[0]
    with db.session() as s:
        job = durable.claim_job(s, "w", exclude_tools=["nuclei"])
        assert job.id == trivy
    with db.session() as s:
        assert durable.claim_job(s, "w", exclude_tools=["nuclei"]) is None
        assert durable.claim_job(s, "w").id == nuclei


def test_recover_leaves_own_running_jobs_alone(engagement):
    jid = _make_jobs(engagement, 1)[0]
    with db.session() as s:
        durable.claim_job(s, "me")
        s.get(Job, jid).heartbeat_at = utcnow() - timedelta(hours=2)
    with db.session() as s:
        assert durable.recover_interrupted_jobs(s, exclude_worker_id="me") == 0
    with db.session() as s:
        assert durable.recover_interrupted_jobs(s, exclude_worker_id="someone-else") == 1
        assert s.get(Job, jid).status == "queued"


def test_touch_heartbeats_only_own_running_jobs(engagement):
    a, b = _make_jobs(engagement, 2)
    old = utcnow() - timedelta(hours=1)
    with db.session() as s:
        durable.claim_job(s, "me")
        durable.claim_job(s, "other")
        for jid in (a, b):
            s.get(Job, jid).heartbeat_at = old
    with db.session() as s:
        assert durable.touch_heartbeats(s, [a, b], "me") == 1
    with db.session() as s:
        hb_a = s.get(Job, a).heartbeat_at
        hb_b = s.get(Job, b).heartbeat_at
        assert hb_a.replace(tzinfo=None) > old.replace(tzinfo=None) + timedelta(minutes=30)
        assert hb_b.replace(tzinfo=None) == old.replace(tzinfo=None)


def test_job_cancel_is_per_job_but_follows_engagement_halt():
    eng = threading.Event()
    one, two = durable.JobCancel(eng), durable.JobCancel(eng)
    one.set()
    assert one.is_set() and not two.is_set() and not eng.is_set()
    eng.set()
    assert two.is_set()


# ---------------------------------------------------------------- pool


def test_pool_runs_jobs_in_parallel(engagement):
    _make_jobs(engagement, 2)
    both_running = threading.Barrier(2, timeout=10)
    seen = []

    def fake_run(s, job):
        both_running.wait()  # only passes when two jobs are in flight together
        seen.append(job.id)
        _finish(s, job)

    pool = WorkerPool(worker_id="pool-a", concurrency=2, run_job=fake_run, housekeeping=False, log=lambda m: None)
    assert pool.tick() == 2
    assert pool.wait_idle(15)
    assert len(seen) == 2
    with db.session() as s:
        assert {j.status for j in s.scalars(select(Job))} == {"done"}


def test_pool_respects_concurrency_limit(engagement):
    _make_jobs(engagement, 3)
    gate = threading.Event()

    def fake_run(s, job):
        gate.wait(10)
        _finish(s, job)

    pool = WorkerPool(worker_id="pool-b", concurrency=2, run_job=fake_run, housekeeping=False, log=lambda m: None)
    assert pool.tick() == 2
    assert pool.tick() == 0
    gate.set()
    assert pool.wait_idle(15)
    assert pool.tick() == 1
    assert pool.wait_idle(15)


def test_pool_runs_nuclei_one_at_a_time(engagement):
    _make_jobs(engagement, 2, tool="nuclei")
    trivy = _make_jobs(engagement, 1, tool="trivy")[0]
    gate = threading.Event()

    def fake_run(s, job):
        gate.wait(10)
        _finish(s, job)

    pool = WorkerPool(worker_id="pool-c", concurrency=3, run_job=fake_run, housekeeping=False, log=lambda m: None)
    assert pool.tick() == 2  # one nuclei + the trivy job, second nuclei waits
    assert trivy in pool.active_job_ids()
    gate.set()
    assert pool.wait_idle(15)
    assert pool.tick() == 1
    assert pool.wait_idle(15)


def test_pool_shutdown_puts_running_jobs_back_in_queue(engagement):
    jid = _make_jobs(engagement, 1)[0]
    started = threading.Event()

    def fake_run(s, job):
        ev = threading.Event()
        durable._ACTIVE_JOB_CANCEL[job.id] = ev
        started.set()
        ev.wait(10)
        durable._ACTIVE_JOB_CANCEL.pop(job.id, None)
        _finish(s, job, "cancelled")  # what run_one_job does when its scanner is stopped

    pool = WorkerPool(worker_id="pool-d", concurrency=2, run_job=fake_run, housekeeping=False, log=lambda m: None)
    pool.tick()
    assert started.wait(5)
    pool.shutdown()
    with db.session() as s:
        job = s.get(Job, jid)
        assert job.status == "queued" and job.worker_id == ""
        assert s.get(ScanRun, job.scan_run_id).status == "queued"


def test_pool_survives_a_crashing_job(engagement):
    jid = _make_jobs(engagement, 1)[0]

    def boom(s, job):
        raise RuntimeError("scanner exploded")

    pool = WorkerPool(worker_id="pool-e", concurrency=2, run_job=boom, housekeeping=False, log=lambda m: None)
    pool.tick()
    assert pool.wait_idle(10)
    with db.session() as s:
        job = s.get(Job, jid)
        assert job.status in ("queued", "failed")  # retried (attempt 1 of 3) instead of stuck running
        assert "scanner exploded" in job.error


@pytest.mark.parametrize(
    ("flag", "env", "want"),
    [(None, None, 2), (None, "4", 4), (3, "4", 3), (0, None, 1), (99, None, 8), (None, "junk", 2)],
)
def test_resolve_concurrency(monkeypatch, flag, env, want):
    if env is None:
        monkeypatch.delenv("ATTESTRA_WORKER_CONCURRENCY", raising=False)
    else:
        monkeypatch.setenv("ATTESTRA_WORKER_CONCURRENCY", env)
    assert resolve_concurrency(flag) == want


def test_cli_worker_has_concurrency_flag(monkeypatch):
    from attestra import cli

    captured = {}
    monkeypatch.setattr(cli, "cmd_worker", lambda args: captured.setdefault("concurrency", args.concurrency))
    cli.main(["worker", "--concurrency", "3"])
    assert captured["concurrency"] == 3
