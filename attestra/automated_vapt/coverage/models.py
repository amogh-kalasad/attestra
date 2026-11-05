"""Coverage snapshot models — separate from finding / vuln counts."""
# @lat: [[architecture#World-class PT coverage honesty (Phase 3)]]

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class CoverageSnapshot:
    """Lightweight engagement coverage totals for reports and APIs.

    Endpoint fields may be zero when no route inventory exists yet; checklist
    and automated-case counts still reflect honesty status. Vulnerability
    counts are intentionally omitted — callers must not treat this as a
    severity scorecard.
    """

    engagement_id: int
    endpoints_discovered: int = 0
    endpoints_tested: int = 0
    endpoints_untested: int = 0
    tested_roles: list[str] = field(default_factory=list)
    checklist_total: int = 0
    checklist_passed: int = 0
    checklist_failed: int = 0
    checklist_blocked: int = 0
    checklist_skipped: int = 0  # checklist status ``not_tested`` (closest to skipped)
    checklist_not_started: int = 0
    checklist_not_applicable: int = 0
    automated_cases_successful: int = 0
    automated_cases_failed: int = 0
    automated_cases_skipped: int = 0
    incomplete: bool = True
    exclusions_note: str = (
        "Skipped, blocked, limited, and not-executed checks are not counted as passed. "
        "Coverage is tracked separately from vulnerability counts."
    )

    def to_dict(self) -> dict:
        """JSON-friendly dict for services / future report chapters."""
        return asdict(self)
