"""Tests for durable job queue: enqueue/claim/complete, stale heartbeat recovery, resume."""
from __future__ import annotations

from datetime import timedelta

from attestra.jobs.durable import (
    claim_job,
    complete_job,
    enqueue,
    recover_interrupted_jobs,
    resume_queued_jobs,
)

# ---------------------------------------------------------------- enqueue / claim / complete


def test_enqueue_creates_queued_job(engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset, ScanRun

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "repo")
        ).first()
        asset_id = asset.id
        run = ScanRun(
            engagement_id=engagement,
            asset_id=asset_id,
            tool="trivy",
            profile="baseline",
            status="queued",
            requested_by="tester",
        )
        s.add(run)
        s.flush()
        job = enqueue(s, run.id)
        job_id = job.id
        assert job.status == "queued"

    with db.session() as s:
        from attestra.models import Job
        j = s.get(Job, job_id)
        assert j is not None
        assert j.status == "queued"


def test_claim_job_transitions_to_running(engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset, ScanRun

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "repo")
        ).first()
        asset_id = asset.id
        run = ScanRun(
            engagement_id=engagement,
            asset_id=asset_id,
            tool="trivy",
            profile="baseline",
            status="queued",
            requested_by="tester",
        )
        s.add(run)
        s.flush()
        job = enqueue(s, run.id)
        job_id = job.id

    with db.session() as s:
        claimed = claim_job(s, "test-worker")
        assert claimed is not None
        assert claimed.id == job_id
        assert claimed.status == "running"
        assert claimed.worker_id == "test-worker"


def test_complete_job(engagement):
    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset, Job, ScanRun

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "repo")
        ).first()
        run = ScanRun(
            engagement_id=engagement,
            asset_id=asset.id,
            tool="trivy",
            profile="baseline",
            status="queued",
            requested_by="tester",
        )
        s.add(run)
        s.flush()
        job = enqueue(s, run.id)
        job_id = job.id

    with db.session() as s:
        j = claim_job(s, "worker-x")
        assert j is not None
        complete_job(s, j)
        assert j.status == "done"

    with db.session() as s:
        j = s.get(Job, job_id)
        assert j.status == "done"


# ---------------------------------------------------------------- stale heartbeat recovery


def test_recover_stale_heartbeat(engagement):
    from sqlalchemy import select

    from attestra import config, db
    from attestra.models import Asset, Job, ScanRun, utcnow

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "repo")
        ).first()
        run = ScanRun(
            engagement_id=engagement,
            asset_id=asset.id,
            tool="trivy",
            profile="baseline",
            status="queued",
            requested_by="tester",
        )
        s.add(run)
        s.flush()
        job = enqueue(s, run.id)
        # Simulate a running job with a stale heartbeat
        job.status = "running"
        job.worker_id = "dead-worker"
        job.heartbeat_at = utcnow() - timedelta(seconds=config.JOB_STALE_HEARTBEAT_S + 10)
        s.flush()
        job_id = job.id

    with db.session() as s:
        recovered = recover_interrupted_jobs(s)
        assert recovered >= 1

    with db.session() as s:
        j = s.get(Job, job_id)
        assert j.status == "queued"


# ---------------------------------------------------------------- resume_queued_jobs refuses out-of-window


def test_resume_outside_window_refuses(engagement):
    """A queued job whose engagement window has passed is refused on resume."""
    import datetime

    from sqlalchemy import select

    from attestra import db
    from attestra.models import Asset, Engagement, ScanRun

    with db.session() as s:
        asset = s.scalars(
            select(Asset).where(Asset.engagement_id == engagement, Asset.kind == "repo")
        ).first()
        run = ScanRun(
            engagement_id=engagement,
            asset_id=asset.id,
            tool="trivy",
            profile="baseline",
            status="queued",
            requested_by="tester",
        )
        s.add(run)
        s.flush()
        enqueue(s, run.id)
        run_id = run.id

        # Move window to the past
        eng = s.get(Engagement, engagement)
        eng.window_end = datetime.date.today() - datetime.timedelta(days=1)
        s.flush()

    with db.session() as s:
        refused = resume_queued_jobs(s)
        assert refused >= 1

    with db.session() as s:
        r = s.get(ScanRun, run_id)
        assert r.status == "refused"
