"""I-01: queue/worker metrics recorded by durable + pool (no database)."""
# @lat: [[attack-surface-and-platform#Queue metrics and stuck jobs]]

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from attestra import observability as obs
from attestra.jobs import durable
from attestra.jobs.pool import WorkerPool


@pytest.fixture(autouse=True)
def clean_registry():
    obs.REGISTRY.reset()
    yield
    obs.REGISTRY.reset()


def test_queue_age_from_queued_or_created():
    now = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
    assert durable.queue_age_seconds({"queued_at": now - timedelta(seconds=90)}, now=now) == 90
    naive = (now - timedelta(seconds=30)).replace(tzinfo=None)
    assert durable.queue_age_seconds({"created_at": naive}, now=now) == 30
    assert durable.queue_age_seconds({}, now=now) is None
    assert durable.queue_age_seconds({"queued_at": now + timedelta(seconds=5)}, now=now) == 0.0


def test_record_helpers_and_render():
    obs.record_job_claimed("zap", 12.0)
    obs.record_job_claimed("zap", None)
    obs.record_job_finished("zap", "done", 3.5)
    obs.record_job_finished("zap", "cancelled", 1.0)
    obs.record_job_retry("zap")
    obs.record_worker_load({"scan": 2, "automated": 1}, 4)
    obs.record_stuck_jobs(3)
    R = obs.REGISTRY
    assert R.hist_count("attestra_job_queue_age_seconds", {"tool": "zap"}) == 1
    assert R.counter_value("attestra_job_outcomes_total", {"tool": "zap", "outcome": "done"}) == 1
    assert R.counter_value("attestra_job_cancellations_total", {"tool": "zap"}) == 1
    assert R.counter_value("attestra_job_retries_total", {"tool": "zap"}) == 1
    assert R.gauge_value("attestra_worker_active_jobs", {"kind": "scan"}) == 2
    assert R.gauge_value("attestra_worker_saturation_ratio") == 0.75
    assert R.gauge_value("attestra_jobs_stuck") == 3
    text = R.render()
    assert "# TYPE attestra_jobs_stuck gauge" in text and "attestra_job_duration_seconds_count" in text


def test_tool_label_is_bounded():
    obs.record_job_retry("Weird Tool/" + "x" * 200)
    names = [k for k in obs.REGISTRY._counters["attestra_job_retries_total"]]
    (label,) = names[0]
    assert label[0] == "tool" and len(label[1]) <= 40 and "/" not in label[1] and " " not in label[1]


def test_run_one_job_records_outcome_and_duration(monkeypatch):
    def fake_inner(s, job, cancel=None):
        job.status = "done"

    monkeypatch.setattr(durable, "_run_one_job", fake_inner)
    job = SimpleNamespace(tool="trivy", status="running")
    durable.run_one_job(None, job)
    assert obs.REGISTRY.counter_value("attestra_job_outcomes_total", {"tool": "trivy", "outcome": "done"}) == 1
    assert obs.REGISTRY.hist_count("attestra_job_duration_seconds", {"tool": "trivy", "outcome": "done"}) == 1


def test_run_one_job_requeued_and_exception_paths(monkeypatch):
    def requeue(s, job, cancel=None):
        job.status = "queued"

    monkeypatch.setattr(durable, "_run_one_job", requeue)
    durable.run_one_job(None, SimpleNamespace(tool="zap", status="running"))
    assert obs.REGISTRY.counter_value("attestra_job_outcomes_total", {"tool": "zap", "outcome": "requeued"}) == 1

    def boom(s, job, cancel=None):
        raise RuntimeError("adapter crashed")

    monkeypatch.setattr(durable, "_run_one_job", boom)
    with pytest.raises(RuntimeError):
        durable.run_one_job(None, SimpleNamespace(tool="zap", status="running"))
    assert obs.REGISTRY.counter_value("attestra_job_outcomes_total", {"tool": "zap", "outcome": "running"}) == 1


def test_metrics_failure_never_breaks_job(monkeypatch):
    monkeypatch.setattr(durable, "_run_one_job", lambda s, job, cancel=None: setattr(job, "status", "done"))
    monkeypatch.setattr(obs, "record_job_finished", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    job = SimpleNamespace(tool="zap", status="running")
    durable.run_one_job(None, job)
    assert job.status == "done"


def test_fail_job_counts_retry_only_when_requeued(monkeypatch):
    import attestra.persistence.mongo.adapters as ad

    seq = iter([{"status": "queued", "error": "e", "worker_id": ""}, {"status": "failed", "error": "e"}])
    monkeypatch.setattr(ad, "mongo_fail_job", lambda *a, **k: next(seq))
    durable.fail_job(None, SimpleNamespace(id=1, tool="nuclei", worker_id="w", status="running", error=""), "e")
    durable.fail_job(None, SimpleNamespace(id=2, tool="nuclei", worker_id="w", status="running", error=""), "e")
    assert obs.REGISTRY.counter_value("attestra_job_retries_total", {"tool": "nuclei"}) == 1


def test_pool_publishes_worker_load_without_db():
    gate = threading.Event()
    pool = WorkerPool(worker_id="t", concurrency=4, housekeeping=False, log=lambda m: None)
    pool._claim_one = lambda: False  # type: ignore[method-assign]
    pool._claim_automated = lambda: False  # type: ignore[method-assign]
    pool._heartbeat = lambda force=False: None  # type: ignore[method-assign]
    t = threading.Thread(target=gate.wait)
    t.start()
    try:
        from attestra.jobs.pool import _Active

        pool._active[1] = _Active(job_id=1, tool="zap", thread=t)
        pool.tick()
        assert obs.REGISTRY.gauge_value("attestra_worker_active_jobs", {"kind": "scan"}) == 1
        assert obs.REGISTRY.gauge_value("attestra_worker_saturation_ratio") == 0.25
        assert pool.load_by_kind() == {"scan": 1, "automated": 0}
    finally:
        gate.set()
        t.join()


def test_instrument_engine_noop_when_otel_off(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    assert obs.instrument_engine(None) is False
