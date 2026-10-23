"""Client portal: read views plus remediation actions for client_viewer.

``client_viewer`` users see triaged findings, compliance status and signed
reports for their own tenant, and may comment, upload fix evidence, and
request retests. ``auditor`` users see every report version with hashes and
signature state, the engagement audit trail and the hash-chain check — but
remain read-only (no write forms).
"""
# @lat: [[interfaces#Client remediation portal]]

from __future__ import annotations

from collections import Counter
from urllib.parse import quote

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import or_, select

from attestra import audit, comments, db, retest, services
from attestra.auth.roles import has_permission
from attestra.compliance import load_library
from attestra.models import OPEN_STATUSES, AuditEvent, Engagement, Finding, Report

router = APIRouter(include_in_schema=False)

READ_ONLY_ROLES = frozenset({"client_viewer", "auditor"})
# Untriaged or rejected results are tester work-in-progress, not client-facing.
CLIENT_HIDDEN_STATUSES = frozenset({"new", "false_positive"})
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Client fix uploads are capped; scanner screenshots stay staff-only.
PORTAL_EVIDENCE_MAX_BYTES = 5 * 1024 * 1024
PORTAL_EVIDENCE_KIND = "client_fix"


def _login(request: Request, permission: str):
    from attestra.web.ui import _require_login

    principal, redirect = _require_login(request)
    if redirect:
        return None, redirect
    if not has_permission(principal.role, permission):
        raise HTTPException(403, f"permission denied: {permission}")
    return principal, None


def _back(url: str, *, msg: str | None = None, error: str | None = None, anchor: str = "") -> RedirectResponse:
    flash = f"msg={quote(msg)}" if msg else f"error={quote(error)}" if error else ""
    if not flash:
        return RedirectResponse(f"{url}{anchor}", status_code=303)
    sep = "&" if "?" in url else "?"
    return RedirectResponse(f"{url}{sep}{flash}{anchor}", status_code=303)


def visible_findings(findings: list[Finding], role: str) -> list[Finding]:
    rows = list(findings)
    if role == "client_viewer":
        rows = [f for f in rows if f.status not in CLIENT_HIDDEN_STATUSES]
    return sorted(rows, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -(f.risk_score or 0)))


def visible_reports(reports: list[Report], role: str) -> list[Report]:
    if role == "client_viewer":
        return [r for r in reports if r.status == "signed"]
    return list(reports)


def tenant_branding(s, tenant_id: int | None) -> dict:
    """Logo / cover title from the tenant ReportTemplate, else Attestra defaults."""
    empty = {"cover_title": "", "logo": "", "has_logo": False}
    if tenant_id is None:
        return empty
    from attestra.library.templates import _pick

    t = _pick(s, tenant_id, "technical")
    if t is None:
        return empty
    logo = t.logo or ""
    return {
        "cover_title": t.cover_title or "",
        "logo": logo,
        "has_logo": bool(logo),
    }


def _portal_can_write(role: str) -> bool:
    """Auditor stays read-only; writers and client_viewer may act on portal routes."""
    return role != "auditor"


def _visible_portal_finding(s, eid: int, fid: int, principal) -> Finding:
    services.get_engagement(s, eid, principal)
    f = s.get(Finding, fid)
    if not f or f.engagement_id != eid:
        raise LookupError(f"finding {fid} not found")
    if principal.role == "client_viewer" and f.status in CLIENT_HIDDEN_STATUSES:
        raise LookupError(f"finding {fid} not found")
    return f


@router.get("/portal", response_class=HTMLResponse)
def portal_home(request: Request):
    from attestra.web.ui import _render

    principal, redirect = _login(request, "engagement.read")
    if redirect:
        return redirect
    with db.session() as s:
        rows = []
        branding = {"cover_title": "", "logo": "", "has_logo": False}
        for e in s.scalars(services.scoped(s, Engagement, principal).order_by(Engagement.id.desc())):
            shown = visible_findings(e.findings, principal.role)
            rows.append({
                "e": e,
                "open": Counter(f.severity for f in shown if f.status in OPEN_STATUSES),
                "closed": sum(1 for f in shown if f.status not in OPEN_STATUSES),
            })
            if not branding["has_logo"] and e.tenant_id is not None:
                branding = tenant_branding(s, e.tenant_id)
        return _render(request, "portal_home.html", {
            "rows": rows,
            "role": principal.role,
            "branding": branding,
            "can_write": _portal_can_write(principal.role),
        })


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
            "branding": tenant_branding(s, e.tenant_id),
            "can_write": _portal_can_write(principal.role),
        })


@router.get("/portal/engagements/{eid}/findings/{fid}", response_class=HTMLResponse)
def portal_finding(request: Request, eid: int, fid: int):
    from attestra.web.ui import _render

    principal, redirect = _login(request, "finding.read")
    if redirect:
        return redirect
    with db.session() as s:
        try:
            e = services.get_engagement(s, eid, principal)
            f = _visible_portal_finding(s, eid, fid, principal)
        except LookupError:
            raise HTTPException(404, "finding not found") from None
        _ = list(f.evidence)
        comment_rows = comments.list_comments(s, fid, principal)
        open_retests = retest.open_retests(s, fid)
        can_write = _portal_can_write(principal.role)
        return _render(request, "portal_finding.html", {
            "e": e,
            "f": f,
            "role": principal.role,
            "comments": comment_rows,
            "open_retests": open_retests,
            "branding": tenant_branding(s, e.tenant_id),
            "can_write": can_write,
            "can_add_comment": can_write and comments.can_add_comment(principal.role),
            "can_upload_evidence": can_write and has_permission(principal.role, "portal.evidence"),
            "can_request_retest": (
                can_write
                and has_permission(principal.role, "portal.retest_request")
                and f.status in ("validated", "fixed")
            ),
            "evidence_max_bytes": PORTAL_EVIDENCE_MAX_BYTES,
        })


@router.post("/portal/engagements/{eid}/findings/{fid}/comments")
async def portal_add_comment(request: Request, eid: int, fid: int, body: str = Form("")):
    principal, redirect = _login(request, "finding.read")
    if redirect:
        return redirect
    detail = f"/portal/engagements/{eid}/findings/{fid}"
    if not _portal_can_write(principal.role) or not comments.can_add_comment(principal.role):
        raise HTTPException(403, "permission denied: cannot add comments")
    try:
        with db.session() as s:
            _visible_portal_finding(s, eid, fid, principal)
            comments.add_comment(s, fid, body=body, principal=principal)
    except LookupError:
        raise HTTPException(404, "finding not found") from None
    except services.ServiceError as exc:
        return _back(detail, error=str(exc), anchor="#comments")
    return _back(detail, msg="Comment posted.", anchor="#comments")


@router.post("/portal/engagements/{eid}/findings/{fid}/evidence")
async def portal_add_evidence(
    request: Request,
    eid: int,
    fid: int,
    note: str = Form(""),
    file: UploadFile = File(...),
):
    principal, redirect = _login(request, "finding.read")
    if redirect:
        return redirect
    detail = f"/portal/engagements/{eid}/findings/{fid}"
    if not _portal_can_write(principal.role) or not has_permission(principal.role, "portal.evidence"):
        raise HTTPException(403, "permission denied: portal.evidence")
    data = await file.read()
    if not data:
        return _back(detail, error="Evidence file is empty.", anchor="#evidence")
    if len(data) > PORTAL_EVIDENCE_MAX_BYTES:
        return _back(
            detail,
            error=f"Evidence must be at most {PORTAL_EVIDENCE_MAX_BYTES // (1024 * 1024)} MB.",
            anchor="#evidence",
        )
    filename = (file.filename or "client_fix.bin").strip() or "client_fix.bin"
    try:
        with db.session() as s:
            _visible_portal_finding(s, eid, fid, principal)
            # Always store as client_fix — never screenshot (scanner proof).
            services.add_evidence(
                s,
                fid,
                kind=PORTAL_EVIDENCE_KIND,
                filename=filename[:300],
                data=data,
                note=(note or "").strip(),
                actor=principal.actor,
            )
    except LookupError:
        raise HTTPException(404, "finding not found") from None
    except services.ServiceError as exc:
        return _back(detail, error=str(exc), anchor="#evidence")
    return _back(detail, msg="Fix evidence uploaded.", anchor="#evidence")


@router.post("/portal/engagements/{eid}/findings/{fid}/retest")
async def portal_request_retest(request: Request, eid: int, fid: int, note: str = Form("")):
    principal, redirect = _login(request, "finding.read")
    if redirect:
        return redirect
    detail = f"/portal/engagements/{eid}/findings/{fid}"
    if not _portal_can_write(principal.role) or not has_permission(principal.role, "portal.retest_request"):
        raise HTTPException(403, "permission denied: portal.retest_request")
    text = (note or "").strip()
    if not text:
        return _back(detail, error="A note is required when requesting a retest.", anchor="#retest")
    try:
        with db.session() as s:
            f = _visible_portal_finding(s, eid, fid, principal)
            row = retest.request_retest(
                s,
                f.id,
                actor=principal.actor,
                user_id=principal.user_id,
                note=text,
            )
            audit.record(
                s,
                principal.actor,
                "portal.retest_request",
                "retest",
                row.id,
                finding_id=f.id,
                engagement_id=eid,
                via="client_portal",
            )
    except LookupError:
        raise HTTPException(404, "finding not found") from None
    except services.ServiceError as exc:
        return _back(detail, error=str(exc), anchor="#retest")
    return _back(detail, msg="Retest requested.", anchor="#retest")


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
            "branding": tenant_branding(s, e.tenant_id),
            "can_write": False,
        })
