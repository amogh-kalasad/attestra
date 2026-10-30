"""API and UI routes for Elite automated security-testing executions."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from attestra import db, services
from attestra.auth.roles import has_permission
from attestra.automated_vapt.core import orchestrator as orch
from attestra.automated_vapt.core import test_registry

api_router = APIRouter(prefix="/api/automated-vapt", tags=["automated-vapt"])
ui_router = APIRouter(tags=["automated-vapt-ui"])


def _principal(request: Request):
    from attestra.api import get_principal

    return get_principal(request)


def _err(e: Exception) -> HTTPException:
    msg = str(e)
    if isinstance(e, LookupError):
        return HTTPException(404, msg.strip("'\""))
    lower = msg.lower()
    if "not found" in lower:
        return HTTPException(404, msg)
    if "not allowed" in lower or "permission" in lower or "disabled" in lower:
        return HTTPException(403, msg)
    return HTTPException(400, msg)


class CreateExecutionIn(BaseModel):
    asset_id: int
    test_case_ids: list[str] = Field(..., min_length=1)
    profile: str = "baseline"
    allow_private: bool | None = None


@api_router.get("/categories")
def get_categories(principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.read"):
        raise HTTPException(403, "permission denied: engagement.read")
    try:
        from attestra.automated_vapt.core import authorization_guard as guard

        guard.require_feature_enabled()
        return {"categories": test_registry.list_categories()}
    except services.ServiceError as e:
        raise _err(e) from e


@api_router.get("/test-cases")
def get_test_cases(category: str | None = None, principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.read"):
        raise HTTPException(403, "permission denied: engagement.read")
    try:
        from attestra.automated_vapt.core import authorization_guard as guard

        guard.require_feature_enabled()
        cases = test_registry.list_test_cases(category=category)
        return {
            "test_cases": [
                {"id": c.id, "category": c.category, "title": c.title, "description": c.description}
                for c in cases
            ]
        }
    except services.ServiceError as e:
        raise _err(e) from e


@api_router.get("/engagements/{eid}/executions")
def list_engagement_executions(eid: int, principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.read"):
        raise HTTPException(403, "permission denied: engagement.read")
    try:
        with db.session() as s:
            rows = orch.list_executions(s, eid, principal=principal)
            return [orch.execution_public_dict(r) for r in rows]
    except services.ServiceError as e:
        raise _err(e) from e


@api_router.post("/engagements/{eid}/executions", status_code=201)
def create_engagement_execution(eid: int, body: CreateExecutionIn, principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.write"):
        raise HTTPException(403, "permission denied: engagement.write")
    try:
        with db.session() as s:
            ex = orch.create_execution(
                s,
                engagement_id=eid,
                asset_id=body.asset_id,
                test_case_ids=body.test_case_ids,
                actor=getattr(principal, "actor", None) or getattr(principal, "username", "") or "api",
                principal=principal,
                profile=body.profile,
                allow_private=body.allow_private,
            )
            return orch.execution_public_dict(ex)
    except services.ServiceError as e:
        raise _err(e) from e


@api_router.get("/executions/{xid}")
def get_one_execution(xid: int, principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.read"):
        raise HTTPException(403, "permission denied: engagement.read")
    try:
        with db.session() as s:
            ex = orch.get_execution(s, xid, principal=principal)
            return orch.execution_public_dict(ex)
    except services.ServiceError as e:
        raise _err(e) from e


@api_router.post("/executions/{xid}/run")
def run_one_execution(xid: int, principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.write"):
        raise HTTPException(403, "permission denied: engagement.write")
    try:
        with db.session() as s:
            ex = orch.run_execution(
                s,
                xid,
                actor=getattr(principal, "actor", None) or getattr(principal, "username", "") or "api",
                principal=principal,
            )
            return orch.execution_public_dict(ex)
    except services.ServiceError as e:
        raise _err(e) from e


@api_router.post("/executions/{xid}/cancel")
def cancel_one_execution(xid: int, principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.write"):
        raise HTTPException(403, "permission denied: engagement.write")
    try:
        with db.session() as s:
            ex = orch.cancel_execution(
                s,
                xid,
                actor=getattr(principal, "actor", None) or getattr(principal, "username", "") or "api",
                principal=principal,
            )
            return orch.execution_public_dict(ex)
    except services.ServiceError as e:
        raise _err(e) from e


def _ui_principal(request: Request):
    from attestra.web.ui import _principal, _require_login

    principal, redirect = _require_login(request)
    if redirect is not None:
        return None, redirect
    return principal, None


@ui_router.post("/engagements/{eid}/automated-vapt/executions")
async def ui_create_execution(
    request: Request,
    eid: int,
    asset_id: int = Form(...),
    profile: str = Form("baseline"),
):
    principal, redirect = _ui_principal(request)
    if redirect is not None:
        return redirect
    assert principal is not None
    form = await request.form()
    ids = [str(v) for v in form.getlist("test_case_id")]
    try:
        with db.session() as s:
            orch.create_execution(
                s,
                engagement_id=eid,
                asset_id=asset_id,
                test_case_ids=ids,
                actor=principal.username,
                principal=principal,
                profile=profile,
            )
        return RedirectResponse(f"/engagements/{eid}#automated-testing", status_code=303)
    except services.ServiceError as e:
        return RedirectResponse(
            f"/engagements/{eid}?error={str(e)[:180]}#automated-testing",
            status_code=303,
        )


@ui_router.post("/engagements/{eid}/automated-vapt/executions/{xid}/run")
def ui_run_execution(request: Request, eid: int, xid: int):
    principal, redirect = _ui_principal(request)
    if redirect is not None:
        return redirect
    assert principal is not None
    try:
        with db.session() as s:
            orch.run_execution(s, xid, actor=principal.username, principal=principal)
        return RedirectResponse(f"/engagements/{eid}#automated-testing", status_code=303)
    except services.ServiceError as e:
        return RedirectResponse(
            f"/engagements/{eid}?error={str(e)[:180]}#automated-testing",
            status_code=303,
        )


@ui_router.post("/engagements/{eid}/automated-vapt/executions/{xid}/cancel")
def ui_cancel_execution(request: Request, eid: int, xid: int):
    principal, redirect = _ui_principal(request)
    if redirect is not None:
        return redirect
    assert principal is not None
    try:
        with db.session() as s:
            orch.cancel_execution(s, xid, actor=principal.username, principal=principal)
        return RedirectResponse(f"/engagements/{eid}#automated-testing", status_code=303)
    except services.ServiceError as e:
        return RedirectResponse(
            f"/engagements/{eid}?error={str(e)[:180]}#automated-testing",
            status_code=303,
        )
