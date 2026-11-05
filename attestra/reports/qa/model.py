"""Dataclasses for automated report QA results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class QaIssue:
    """One QA finding against a sealed report or its engagement data."""

    code: str  # e.g. "finding_count_mismatch"
    severity: str  # "critical" | "warning" | "info"
    message: str
    finding_id: int | None = None
    details: dict | None = None


@dataclass
class QaResult:
    """Aggregated QA outcome for one sealed report."""

    report_id: int
    engagement_id: int
    ok: bool  # True iff no critical issues
    issues: list[QaIssue]
    checked_at: datetime
    summary: dict = field(default_factory=dict)  # counts by severity, finding_count, etc.
