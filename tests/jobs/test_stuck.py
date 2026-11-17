"""I-02: stuck-job detection and the launcher summary (fake job documents, no database)."""
# @lat: [[attack-surface-and-platform#Queue metrics and stuck jobs]]

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from attestra import observability as obs
from attestra.jobs import durable, launcher

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def clean():
    obs.REGISTRY.reset()
    yield
    obs.REGISTRY.reset()


def test_is_stuck_rules():
    assert durable.is_stuck({"status": "running", "heartbeat_at": NOW - timedelta(seconds=901)}, now=NOW, stale_s=900)
    assert not durable.is_stuck({"status": "running", "heartbeat_at": NOW - timedelta(seconds=60)}, now=NOW, stale_s=900)
    assert durable.is_stuck({"status": "running", "heartbeat_at": None}, now=NOW, stale_s=900)
    assert not durable.is_stuck({"status": "queued"}, now=NOW, stale_s=900)
    assert not durable.is_stuck({"status": "done", "heartbeat_at": None}, now=NOW)
    obj = SimpleNamespace(status="running", heartbeat_at=(NOW - timedelta(hours=2)).replace(tzinfo=None))
    assert durable.is_stuck(obj, now=NOW, stale_s=900)


def _docs(now=NOW):
    return [
        {"id": 1, "scan_run_id": 10, "tool": "zap", "status": "running", "worker_id": "w1", "heartbeat_at": now - timedelta(hours=1), "error": "secret-ish detail"},
        {"id": 2, "scan_run_id": 11, "tool": "trivy", "status": "running", "worker_id": "w1", "heartbeat_at": now - timedelta(seconds=10)},
        {"id": 3, "scan_run_id": 12, "tool": "nuclei", "status": "running", "worker_id": "", "heartbeat_at": None},
    ]


def test_stuck_jobs_rows_and_gauge(monkeypatch):
    import attestra.persistence.mongo.adapters as ad

    monkeypatch.setattr(ad, "mongo_jobs_by_status", lambda status: _docs() if status == "running" else [])
    rows = durable.stuck_jobs(now=NOW, stale_s=900)
    assert [r["job_id"] for r in rows] == [1, 3]
    assert rows[0]["heartbeat_age_s"] == 3600.0 and rows[1]["heartbeat_age_s"] is None
    assert set(rows[0]) == {"job_id", "scan_run_id", "tool", "worker_id", "heartbeat_age_s"}  # no error text
    assert obs.REGISTRY.gauge_value("attestra_jobs_stuck") == 2


def test_launcher_summary_hints(monkeypatch):
    import attestra.persistence.mongo.adapters as ad

    monkeypatch.setattr(ad, "mongo_jobs_by_status", lambda status: _docs(datetime.now(UTC)))
    monkeypatch.setattr(launcher, "worker_status", lambda s=None: SimpleNamespace(running=False))
    out = launcher.stuck_job_summary()
    assert out["count"] == 2 and out["worker_running"] is False and "attestra worker" in out["hint"]
    monkeypatch.setattr(launcher, "worker_status", lambda s=None: SimpleNamespace(running=True))
    assert "re-queue" in launcher.stuck_job_summary()["hint"] or "queue" in launcher.stuck_job_summary()["hint"]


def test_launcher_summary_never_raises(monkeypatch):
    import attestra.persistence.mongo.adapters as ad

    def broken(status):
        raise RuntimeError("mongo auth")

    monkeypatch.setattr(ad, "mongo_jobs_by_status", broken)
    out = launcher.stuck_job_summary()
    assert out["count"] == 0 and out["jobs"] == []


def test_pool_stuck_scan_is_throttled(monkeypatch):
    from attestra.jobs.pool import WorkerPool

    calls = []
    monkeypatch.setattr(durable, "stuck_jobs", lambda s=None, **k: calls.append(1) or [{"job_id": 9}])
    logs: list[str] = []
    pool = WorkerPool(worker_id="t", log=logs.append)
    pool._scan_stuck()
    pool._scan_stuck()
    assert len(calls) == 1 and "9" in logs[0]
