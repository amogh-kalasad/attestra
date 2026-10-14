"""Thin wrappers around durable job operations (API clarity)."""

from attestra.jobs.durable import claim_job, complete_job, enqueue, fail_job

__all__ = ["enqueue", "claim_job", "complete_job", "fail_job"]
