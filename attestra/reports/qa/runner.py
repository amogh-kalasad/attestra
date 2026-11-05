"""Orchestrate sealed-report QA checks for approval / signing gates."""
# @lat: [[reports#World-class report QA (Phase 9)]]

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from attestra import services
from attestra.models import OPEN_STATUSES
from attestra.reports.qa.checks import ALL_CHECKS, QaContext, load_reportable_findings
from attestra.reports.qa.model import QaIssue, QaResult
from attestra.reports.render import _counts_as_open_vuln, _get_report


def run_report_qa(s: Session, report_id: int) -> QaResult:
    """Load a sealed report + engagement findings and run all data-level QA checks.

    Visual / PDF blank-page / page-numbering checks are deferred (not in this package).
    ``ok`` is True iff no critical issues were raised.
    """
    # @lat: [[reports#World-class report QA (Phase 9)]]
    r = _get_report(s, report_id)
    eng = services.get_engagement(s, r.engagement_id)
    path = Path(r.path)
    try:
        html = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    except OSError:
        html = ""

    reportable = load_reportable_findings(s, r.engagement_id)
    open_f = [f for f in reportable if getattr(f, "status", None) in OPEN_STATUSES]
    open_vulns = [f for f in open_f if _counts_as_open_vuln(f)]
    by_sev = Counter(getattr(f, "severity", None) or "info" for f in open_vulns)

    ctx = QaContext(
        s=s,
        report=r,
        html=html,
        engagement=eng,
        reportable=reportable,
        open_vulns=open_vulns,
        by_sev=by_sev,
        tenant_id=int(eng.tenant_id),
        kind=(getattr(r, "kind", None) or "").strip().lower(),
    )
    for check in ALL_CHECKS:
        check(ctx)

    issues = list(ctx.issues)
    critical = [i for i in issues if i.severity == "critical"]
    warning = [i for i in issues if i.severity == "warning"]
    info = [i for i in issues if i.severity == "info"]
    checked_at = datetime.now(timezone.utc)
    result = QaResult(
        report_id=int(r.id),
        engagement_id=int(r.engagement_id),
        ok=not critical,
        issues=issues,
        checked_at=checked_at,
        summary={
            "critical": len(critical),
            "warning": len(warning),
            "info": len(info),
            "finding_count": len(reportable),
            "open_vuln_count": len(open_vulns),
            "by_sev": {k: int(by_sev.get(k, 0)) for k in ("critical", "high", "medium", "low", "info")},
            "kind": ctx.kind,
            "status": getattr(r, "status", None),
            "deferred_visual_qa": (
                "PDF blank-page, broken-layout, and page-numbering automation are deferred"
            ),
        },
    )
    return result


def qa_result_dict(result: QaResult) -> dict:
    """JSON-friendly dict for API responses."""

    def _issue(i: QaIssue) -> dict:
        out = {
            "code": i.code,
            "severity": i.severity,
            "message": i.message,
            "finding_id": i.finding_id,
        }
        if i.details is not None:
            out["details"] = i.details
        return out

    return {
        "report_id": result.report_id,
        "engagement_id": result.engagement_id,
        "ok": result.ok,
        "checked_at": result.checked_at.isoformat(),
        "summary": dict(result.summary or {}),
        "issues": [_issue(i) for i in result.issues],
    }


def assert_qa_allows_approval(result: QaResult) -> None:
    """Raise ServiceError when critical QA issues block approval / signing.

    Message lists critical codes/messages and is capped near 500 characters.
    """
    if result.ok:
        return
    critical = [i for i in result.issues if i.severity == "critical"]
    parts = [f"{i.code}: {i.message}" for i in critical]
    body = "; ".join(parts)
    prefix = f"report QA blocked approval ({len(critical)} critical): "
    max_body = max(0, 500 - len(prefix))
    if len(body) > max_body:
        body = body[: max(0, max_body - 3)] + "..."
    raise services.ServiceError(prefix + body)
