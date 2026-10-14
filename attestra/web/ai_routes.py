"""API and dashboard routes for optional AI-drafted narratives (Step 8.5).

All routes return 404 when ``ATTESTRA_AI_NARRATIVES`` is off (or off for the tenant).
Drafts are internal: client_viewer, auditor and reviewer cannot see or change them.
"""

from __future__ import annotations

from html import escape

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


def _page(eid: int, drafts: list[ai.Draft], msg: str = "") -> str:
    rows = []
    for d in drafts:
        target = "Executive summary" if d.kind == "executive_summary" else f"Finding F-{d.finding_id}"
        actions = ""
        if d.status == "draft":
            actions = (
                f'<form method="post" action="/engagements/{eid}/ai-drafts/{escape(d.id)}/approve">'
                f'<textarea name="text" rows="5" cols="90">{escape(d.text)}</textarea><br>'
                '<button type="submit">Approve (with edits)</button></form>'
                f'<form method="post" action="/engagements/{eid}/ai-drafts/{escape(d.id)}/reject">'
                '<button type="submit">Reject</button></form>'
            )
        else:
            actions = f"<p>{escape(d.text)}</p>"
        who = f" by {escape(d.approved_by)}" if d.approved_by else ""
        rows.append(
            f'<div class="draft"><h3>{target} <span class="pill">{escape(d.label)}</span> '
            f"<small>{escape(d.status)}{who}</small></h3>{actions}</div>"
        )
    body = "".join(rows) or "<p>No drafts yet.</p>"
    note = f'<p class="note">{escape(msg)}</p>' if msg else ""
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>AI drafts</title></head><body>"
        f'<p><a href="/engagements/{eid}">Back to engagement</a></p>'
        f"<h1>AI drafts: engagement {eid}</h1>{note}"
        "<p>Drafts never appear in a report until a tester approves them.</p>"
        f'<form method="post" action="/engagements/{eid}/ai-drafts">'
        '<select name="kind"><option value="executive_summary">Executive summary</option>'
        '<option value="finding">Finding narrative</option></select> '
        'Finding id <input name="finding_id" size="6"> <button type="submit">Create draft</button></form>'
        f"{body}</body></html>"
    )


@ui_router.get("/engagements/{eid}/ai-drafts", response_class=HTMLResponse)
def ui_drafts(request: Request, eid: int):
    principal = _ui_principal(request, PERM_DRAFT)

    def fn(s):
        _check_enabled(s, eid, principal)
        return _page(eid, ai.DraftStore().list(eid), request.query_params.get("msg", ""))

    return HTMLResponse(_with_session(fn))


@ui_router.post("/engagements/{eid}/ai-drafts")
def ui_create(request: Request, eid: int, kind: str = Form(...), finding_id: str = Form("")):
    principal = _ui_principal(request, PERM_DRAFT)
    fid = int(finding_id) if finding_id.strip().isdigit() else None
    _with_session(lambda s: _create(s, eid, principal, kind, fid))
    return RedirectResponse(f"/engagements/{eid}/ai-drafts?msg=Draft+created", status_code=303)


@ui_router.post("/engagements/{eid}/ai-drafts/{did}/approve")
def ui_approve(request: Request, eid: int, did: str, text: str = Form("")):
    principal = _ui_principal(request, PERM_APPROVE)
    _with_session(lambda s: _decide(s, eid, did, principal, approve=True, text=text or None))
    return RedirectResponse(f"/engagements/{eid}/ai-drafts?msg=Approved", status_code=303)


@ui_router.post("/engagements/{eid}/ai-drafts/{did}/reject")
def ui_reject(request: Request, eid: int, did: str):
    principal = _ui_principal(request, PERM_APPROVE)
    _with_session(lambda s: _decide(s, eid, did, principal, approve=False, text=None))
    return RedirectResponse(f"/engagements/{eid}/ai-drafts?msg=Rejected", status_code=303)
