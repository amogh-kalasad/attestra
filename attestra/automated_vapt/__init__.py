"""Elite automated security-testing orchestration (reuse-first façade).

Thin package over auth_web scope, proof/evidence, credits, and findings.
Off by default via ``ATTESTRA_AUTOMATED_VAPT_ENABLED``.
"""

from __future__ import annotations

__all__ = ["STATUSES"]

STATUSES = ("QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED")
