"""Step 7.1: read-only client portal and auditor views.

``client_viewer`` users see triaged findings, compliance status and signed
reports for their own tenant. ``auditor`` users additionally see every
report version with hashes and signature state, the engagement audit trail
and the result of the hash-chain verification. Nothing here writes.
"""

from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import or_, select

from attestra import audit, db, services
from attestra.auth.roles import has_permission
from attestra.compliance import load_library
from attestra.models import OPEN_STATUSES, AuditEvent, Engagement, Finding, Report

router = APIRouter(include_in_schema=False)

READ_ONLY_ROLES = frozenset({"client_viewer", "auditor"})
# Untriaged or rejected results are tester work-in-progress, not client-facing.
CLIENT_HIDDEN_STATUSES = frozenset({"new", "false_positive"})
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _login(request: Request, permission: str):
    from attestra.web.ui import _require_login

    principal, redirect = _require_login(request)
    if redirect:
        return None, redirect
    if not has_permission(principal.role, permission):
        raise HTTPException(403, f"permission denied: {permission}")
    return principal, None


def visible_findings(findings: list[Finding], role: str) -> list[Finding]:
    rows = list(findings)
    if role == "client_viewer":
        rows = [f for f in rows if f.status not in CLIENT_HIDDEN_STATUSES]
    return sorted(rows, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -(f.risk_score or 0)))


def visible_reports(reports: list[Report], role: str) -> list[Report]:
    if role == "client_viewer":
        return [r for r in reports if r.status == "signed"]
    return list(reports)


@router.get("/portal", response_class=HTMLResponse)
def portal_home(request: Request):
    from attestra.web.ui import _render

    principal, redirect = _login(request, "engagement.read")
    if redirect:
        return redirect
    with db.session() as s:
        rows = []
        for e in s.scalars(services.scoped(s, Engagement, principal).order_by(Engagement.id.desc())):
            shown = visible_findings(e.findings, principal.role)
            rows.append({
                "e": e,
                "open": Counter(f.severity for f in shown if f.status in OPEN_STATUSES),
                "closed": sum(1 for f in shown if f.status not in OPEN_STATUSES),
            })
        return _render(request, "portal_home.html", {"rows": rows, "role": principal.role})


@router.get("/portal/engagements/{eid}", response_class=HTMLResponse)
def portal_engagement(request: Request, eid: int, framework: str | None = None):
    from attestra.web.ui import _render

    principal, redirect = _login(request, "engagement.read")
    if redirect:
        return redirect
    with db.session() as s:
        try:
            e = services.get_engagement(s, eid, principal)
        except LookupError:
            raise HTTPException(404, "engagement not found") from None
        lib = load_library()
        fw = framework if framework in lib.frameworks else (e.frameworks[0] if e.frameworks else "pci_dss_4")
        results = services.compliance(s, eid, fw)
        findings = visible_findings(services.list_findings(s, eid), principal.role)
        reports = visible_reports(
            list(s.scalars(select(Report).where(Report.engagement_id == eid).order_by(Report.id.desc()))),
            principal.role,
        )
        return _render(request, "portal_engagement.html", {
            "e": e,
            "role": principal.role,
            "findings": findings,
            "reports": reports,
            "results": results,
            "fw": fw,
            "fw_names": {k: v["name"] for k, v in lib.frameworks.items()},
            "counts": Counter(r.status for r in results),
            "sev": Counter(f.severity for f in findings if f.status in OPEN_STATUSES),
        })


@router.get("/auditor/engagements/{eid}", response_class=HTMLResponse)
def auditor_engagement(request: Request, eid: int):
    from attestra.web.ui import _render

    principal, redirect = _login(request, "audit.read")
    if redirect:
        return redirect
    with db.session() as s:
        try:
            e = services.get_engagement(s, eid, principal)
        except LookupError:
            raise HTTPException(404, "engagement not found") from None
        finding_ids = [f.id for f in e.findings]
        report_ids = [r.id for r in s.scalars(select(Report).where(Report.engagement_id == eid))]
        clauses = [(AuditEvent.entity == "engagement") & (AuditEvent.entity_id == eid)]
        if finding_ids:
            clauses.append((AuditEvent.entity == "finding") & AuditEvent.entity_id.in_(finding_ids))
        if report_ids:
            clauses.append((AuditEvent.entity == "report") & AuditEvent.entity_id.in_(report_ids))
        events = list(s.scalars(select(AuditEvent).where(or_(*clauses)).order_by(AuditEvent.id.desc()).limit(500)))
        ok, bad = audit.verify(s)
        reports = list(s.scalars(select(Report).where(Report.engagement_id == eid).order_by(Report.id.desc())))
        return _render(request, "auditor_engagement.html", {
            "e": e,
            "events": events,
            "chain_ok": ok,
            "chain_bad": bad,
            "reports": reports,
            "status_counts": Counter(f.status for f in e.findings),
        })
