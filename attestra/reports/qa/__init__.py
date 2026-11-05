"""Automated report QA: sealed HTML consistency vs engagement findings."""

from __future__ import annotations

from sqlalchemy.orm import Session

from attestra.reports.qa.model import QaIssue, QaResult
from attestra.reports.qa.runner import assert_qa_allows_approval, qa_result_dict, run_report_qa

__all__ = [
    "QaIssue",
    "QaResult",
    "assert_qa_allows_approval",
    "check_report_qa",
    "qa_result_dict",
    "run_report_qa",
]


def check_report_qa(s: Session, report_id: int) -> QaResult:
    """Thin helper: run QA and return the result (does not raise)."""
    return run_report_qa(s, report_id)
