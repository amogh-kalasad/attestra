"""Coverage snapshot models — separate from finding / vuln counts."""
# @lat: [[architecture#World-class PT coverage honesty (Phase 3)]]
# @lat: [[architecture#World-class coverage execution engine (Phase 4)]]

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class CoverageSnapshot:
    """Lightweight engagement coverage totals for reports and APIs.

    Endpoint fields may be zero when no route inventory exists yet; checklist
    and automated-case counts still reflect honesty status. Vulnerability
    counts are intentionally omitted — callers must not treat this as a
    severity scorecard. A 100% scan completion rate is never security-testing
    coverage (``scan_completion_is_not_security_coverage`` is always True).
    """

    engagement_id: int
    endpoints_discovered: int = 0
    endpoints_tested: int = 0
    endpoints_untested: int = 0
    endpoints_authenticated: int = 0
    endpoints_unauthenticated: int = 0
    methods_tested: list[str] = field(default_factory=list)
    parameters_discovered: int = 0
    parameters_tested: int = 0
    roles_discovered: int = 0
    roles_tested: int = 0
    tested_roles: list[str] = field(default_factory=list)
    coverage_pct_endpoints: float = 0.0
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
    automated_cases_blocked: int = 0  # DEFERRED (policy/blocked), distinct from SKIPPED
    test_cases_blocked: int = 0  # alias of automated_cases_blocked for Phase 4 trackers
    ledger_entry_count: int = 0
    scan_completion_is_not_security_coverage: bool = True
    incomplete: bool = True
    exclusions_note: str = (
        "Skipped, blocked, limited, and not-executed checks are not counted as passed. "
        "Coverage is tracked separately from vulnerability counts. "
        "A 100% automated scan completion rate is never 100% security testing coverage."
    )

    def to_dict(self) -> dict:
        """JSON-friendly dict for services / future report chapters."""
        return asdict(self)
