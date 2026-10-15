"""API and dashboard routes for optional AI-drafted narratives (Step 8.5).

API routes return 404 when ``ATTESTRA_AI_NARRATIVES`` is off (or off for the tenant); the dashboard
page shows a friendly "AI drafts are switched off" page instead.
Drafts are internal: client_viewer, auditor and reviewer cannot see or change them.
"""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

from attestra import ai_narratives as ai
from attestra import audit, db, services
from attestra.auth.keys import Principal
from attestra.auth.roles import has_permission

PERM_DRAFT = "report.generate"  # admin, lead, tester
PERM_APPROVE = "finding.write"  # admin, lead, tester


class DraftIn(BaseModel):
    kind: str  # executive_summary | finding
    finding_id: int | None = None


class ApproveIn(BaseModel):
    text: str | None = None


def _draft_dict(d: ai.Draft) -> dict:
    return {
        "id": d.id,
        "kind": d.kind,
        "engagement_id": d.engagement_id,
        "finding_id": d.finding_id,
        "text": d.text,
        "label": d.label,
        "status": d.status,
        "provider": d.provider,
        "created_at": d.created_at,
        "approved_by": d.approved_by,
        "approved_at": d.approved_at,
    }


def _check_enabled(s, eid: int, principal: Principal):
    eng = services.get_engagement(s, eid, principal)
    if not ai.is_enabled(tenant_id=eng.tenant_id):
        raise HTTPException(404, "AI narratives are disabled")
    return eng


def _create(s, eid: int, principal: Principal, kind: str, finding_id: int | None) -> ai.Draft:
    eng = _check_enabled(s, eid, principal)
    provider = ai.get_provider(eng.tenant_id)
    if provider is None:
        raise HTTPException(404, "AI narratives are disabled")
    store = ai.DraftStore()
    findings = [f for f in services.list_findings(s, eid) if f.status != "false_positive"]
    if kind == "executive_summary":
        d = ai.draft_executive_summary(provider, store, eid, findings, tenant_id=eng.tenant_id)
    elif kind == "finding":
        f = next((f for f in findings if f.id == finding_id), None)
        if f is None:
            raise HTTPException(404, "finding not found in this engagement")
        d = ai.draft_finding_narrative(provider, store, eid, f, tenant_id=eng.tenant_id)
    else:
        raise HTTPException(422, "kind must be executive_summary or finding")
    audit.record(s, principal.username, "ai_draft.create", "engagement", eid, kind=kind, draft=d.id)
    return d


def _decide(s, eid: int, did: str, principal: Principal, *, approve: bool, text: str | None) -> ai.Draft:
    _check_enabled(s, eid, principal)
    store = ai.DraftStore()
    try:
        if approve:
            d = store.approve(eid, did, user=principal.username, role=principal.role, edited_text=text)
        else:
            if principal.role not in ai.APPROVER_ROLES:
                raise PermissionError("only a tester (or lead/admin) can reject AI drafts")
            d = store.reject(eid, did, user=principal.username)
    except PermissionError as e:
        raise HTTPException(403, str(e)) from e
    except ai.AINarrativesError as e:
        raise HTTPException(404, str(e)) from e
    audit.record(
        s, principal.username, "ai_draft.approve" if approve else "ai_draft.reject", "engagement", eid, draft=did
    )
    return d


def _with_session(fn, *args, **kwargs):
    try:
        with db.session() as s:
            return fn(s, *args, **kwargs)
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except services.ServiceError as e:
        raise HTTPException(403 if "not allowed" in str(e) else 409, str(e)) from e


# ---------------------------------------------------------------- REST API

api_router = APIRouter()


def _require(permission: str):
    from attestra.api import get_principal

    def dep(request: Request) -> Principal:
        principal = get_principal(request)
        if not has_permission(principal.role, permission):
            raise HTTPException(403, f"permission denied: {permission}")
        return principal

    return dep


@api_router.get("/api/engagements/{eid}/ai-drafts")
def list_drafts(eid: int, principal: Principal = Depends(_require(PERM_DRAFT))):
    def fn(s):
        _check_enabled(s, eid, principal)
        return [_draft_dict(d) for d in ai.DraftStore().list(eid)]

    return _with_session(fn)


@api_router.post("/api/engagements/{eid}/ai-drafts", status_code=201)
def create_draft(eid: int, body: DraftIn, principal: Principal = Depends(_require(PERM_DRAFT))):
    return _with_session(lambda s: _draft_dict(_create(s, eid, principal, body.kind, body.finding_id)))


@api_router.post("/api/engagements/{eid}/ai-drafts/{did}/approve")
def approve_draft(eid: int, did: str, body: ApproveIn, principal: Principal = Depends(_require(PERM_APPROVE))):
    return _with_session(lambda s: _draft_dict(_decide(s, eid, did, principal, approve=True, text=body.text)))


@api_router.post("/api/engagements/{eid}/ai-drafts/{did}/reject")
def reject_draft(eid: int, did: str, principal: Principal = Depends(_require(PERM_APPROVE))):
    return _with_session(lambda s: _draft_dict(_decide(s, eid, did, principal, approve=False, text=None)))


# ---------------------------------------------------------------- dashboard

ui_router = APIRouter(include_in_schema=False)


def _ui_principal(request: Request, permission: str) -> Principal:
    from attestra.web.ui import _principal

    principal = _principal(request)
    if principal is None:
        raise HTTPException(401, "sign in to continue")
    if not has_permission(principal.role, permission):
        raise HTTPException(403, f"permission denied: {permission}")
    return principal


def _ui_enabled(eid: int, principal: Principal) -> bool:
    def fn(s):
        eng = services.get_engagement(s, eid, principal)
        return ai.is_enabled(tenant_id=eng.tenant_id)

    return _with_session(fn)


def _finding_ok(s, eid: int, fid: int) -> bool:
    return any(f.id == fid and f.status != "false_positive" for f in services.list_findings(s, eid))


def _ui_back(eid: int, *, msg: str = "", error: str = "") -> RedirectResponse:
    q = f"?msg={quote(msg)}" if msg else f"?error={quote(error)}" if error else ""
    return RedirectResponse(f"/engagements/{eid}/ai-drafts{q}", status_code=303)


@ui_router.get("/engagements/{eid}/ai-drafts", response_class=HTMLResponse)
def ui_drafts(request: Request, eid: int):
    from attestra.web.ui import _login_redirect, _principal, _render

    if _principal(request) is None:
        return _login_redirect(f"/engagements/{eid}/ai-drafts")
    principal = _ui_principal(request, PERM_DRAFT)

    def fn(s):
        eng = services.get_engagement(s, eid, principal)
        enabled = ai.is_enabled(tenant_id=eng.tenant_id)
        if not enabled:
            # A friendly page (200), not "Page not found": the feature exists but is switched off.
            return _render(request, "ai_drafts_off.html", {"e": eng, "globally_on": ai.is_enabled()})
        findings = [f for f in services.list_findings(s, eid) if f.status != "false_positive"]
        return _render(
            request,
            "ai_drafts.html",
            {
                "e": eng,
                "drafts": list(reversed(ai.DraftStore().list(eid))),
                "findings": findings,
                "finding_titles": {f.id: f.title for f in findings},
                "can_decide": principal.role in ai.APPROVER_ROLES and has_permission(principal.role, PERM_APPROVE),
            },
        )

    return _with_session(fn)


@ui_router.post("/engagements/{eid}/ai-drafts")
def ui_create(request: Request, eid: int, kind: str = Form(...), finding_id: str = Form("")):
    principal = _ui_principal(request, PERM_DRAFT)
    if not _ui_enabled(eid, principal):
        return _ui_back(eid)
    fid = int(finding_id) if finding_id.strip().isdigit() else None
    if kind == "finding" and (fid is None or not _with_session(lambda s: _finding_ok(s, eid, fid))):
        # A missing or wrong id goes back to the page with an inline error, not a 404 page.
        return _ui_back(eid, error="Pick a finding from the list.")
    try:
        _with_session(lambda s: _create(s, eid, principal, kind, fid))
    except (ai.AINarrativesError, OSError, ValueError) as e:
        why = type(e).__name__
        error = f"The AI service could not write a draft ({why}). Check the AI settings and try again."
        return _ui_back(eid, error=error)
    return _ui_back(eid, msg="Draft created. Review it below before approving.")


@ui_router.post("/engagements/{eid}/ai-drafts/{did}/approve")
def ui_approve(request: Request, eid: int, did: str, text: str = Form("")):
    principal = _ui_principal(request, PERM_APPROVE)
    if not _ui_enabled(eid, principal):
        return _ui_back(eid)
    _with_session(lambda s: _decide(s, eid, did, principal, approve=True, text=text or None))
    return _ui_back(eid, msg="Draft approved. It will be used in the next report you generate.")


@ui_router.post("/engagements/{eid}/ai-drafts/{did}/reject")
def ui_reject(request: Request, eid: int, did: str):
    principal = _ui_principal(request, PERM_APPROVE)
    if not _ui_enabled(eid, principal):
        return _ui_back(eid)
    _with_session(lambda s: _decide(s, eid, did, principal, approve=False, text=None))
    return _ui_back(eid, msg="Draft rejected. It will not be used in any report.")
