"""API and UI for Super Admin ownership validity settings."""
# @lat: [[authorization#Target ownership#Validity window]]

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from attestra import db, services
from attestra.auth.roles import has_permission
from attestra.models import Tenant
from attestra.runner import ownership

api_router = APIRouter(prefix="/api/settings/ownership", tags=["ownership-settings"])
ui_router = APIRouter(include_in_schema=False)


def _principal(request: Request):
    from attestra.api import get_principal

    return get_principal(request)


def _err(e: Exception) -> HTTPException:
    msg = str(e)
    if isinstance(e, LookupError):
        return HTTPException(404, msg.strip("'\""))
    if isinstance(e, PermissionError) or "Super Admin" in msg or "not allowed" in msg or "only a" in msg:
        return HTTPException(403, msg)
    return HTTPException(400, msg)


class OwnershipSettingsIn(BaseModel):
    ownership_validity_days: int = Field(..., ge=ownership.OWNERSHIP_VALIDITY_DAYS_MIN, le=ownership.OWNERSHIP_VALIDITY_DAYS_MAX)


def _default_tenant(s, principal) -> int:
    allowed = services.tenant_ids_for(s, principal)
    q = select(Tenant).order_by(Tenant.name)
    if allowed is not None:
        q = q.where(Tenant.id.in_(allowed))
    row = s.scalars(q).first()
    if row is None:
        raise LookupError("no tenant in scope for ownership settings")
    return row.id


@api_router.get("")
def get_ownership_settings(tenant_id: int | None = None, principal=Depends(_principal)):
    """Read ownership validity days for a tenant (Super Admin only)."""
    if not has_permission(principal.role, "ownership.configure"):
        raise HTTPException(403, "only a Super Admin can view ownership settings")
    try:
        with db.session() as s:
            tid = tenant_id if tenant_id is not None else _default_tenant(s, principal)
            allowed = services.tenant_ids_for(s, principal)
            if allowed is not None and tid not in allowed:
                raise LookupError(f"tenant {tid} not found")
            t = s.get(Tenant, tid)
            if t is None:
                raise LookupError(f"tenant {tid} not found")
            days = services.ownership_validity_days_for_tenant(s, tid)
            return {
                "tenant_id": tid,
                "tenant_name": t.name,
                "ownership_validity_days": days,
                "default_days": ownership.DEFAULT_OWNERSHIP_VALIDITY_DAYS,
                "min_days": ownership.OWNERSHIP_VALIDITY_DAYS_MIN,
                "max_days": ownership.OWNERSHIP_VALIDITY_DAYS_MAX,
            }
    except LookupError as e:
        raise _err(e) from e


@api_router.put("")
def put_ownership_settings(
    body: OwnershipSettingsIn,
    tenant_id: int = Query(...),
    principal=Depends(_principal),
):
    """Set ownership validity days for a tenant (Super Admin only)."""
    try:
        with db.session() as s:
            t = services.set_ownership_validity_days(s, principal, tenant_id, body.ownership_validity_days)
            days = services.ownership_validity_days_for_tenant(s, t.id)
            return {
                "tenant_id": t.id,
                "tenant_name": t.name,
                "ownership_validity_days": days,
                "default_days": ownership.DEFAULT_OWNERSHIP_VALIDITY_DAYS,
                "min_days": ownership.OWNERSHIP_VALIDITY_DAYS_MIN,
                "max_days": ownership.OWNERSHIP_VALIDITY_DAYS_MAX,
            }
    except (LookupError, PermissionError, services.ServiceError) as e:
        raise _err(e) from e


def _ui_admin(request: Request):
    from attestra.web.ui import _principal as ui_principal

    p = ui_principal(request)
    if p is None or not has_permission(p.role, "ownership.configure"):
        return None
    return p


def _back(url: str, **kw) -> RedirectResponse:
    from attestra.web.ui import _back as ui_back

    return ui_back(url, **kw)


def _render(request: Request, template: str, ctx: dict) -> HTMLResponse:
    from attestra.web.ui import _render as ui_render

    return ui_render(request, template, ctx)


@ui_router.get("/settings/ownership", response_class=HTMLResponse)
def ui_ownership_settings(request: Request, tenant_id: int | None = None):
    p = _ui_admin(request)
    if p is None:
        return _back("/login", error="Sign in as a Super Admin to manage ownership settings.")
    with db.session() as s:
        try:
            tid = tenant_id if tenant_id is not None else _default_tenant(s, p)
            allowed = services.tenant_ids_for(s, p)
            if allowed is not None and tid not in allowed:
                raise LookupError(f"tenant {tid} not found")
            t = s.get(Tenant, tid)
            if t is None:
                raise LookupError(f"tenant {tid} not found")
        except LookupError as e:
            return _back("/", error=str(e))
        days = services.ownership_validity_days_for_tenant(s, tid)
        q = select(Tenant).order_by(Tenant.name)
        if allowed is not None:
            q = q.where(Tenant.id.in_(allowed))
        tenants = [{"id": row.id, "name": row.name} for row in s.scalars(q)]
    return _render(
        request,
        "ownership_settings.html",
        {
            "tenant_id": tid,
            "tenant_name": t.name,
            "tenants": tenants,
            "ownership_validity_days": days,
            "default_days": ownership.DEFAULT_OWNERSHIP_VALIDITY_DAYS,
            "min_days": ownership.OWNERSHIP_VALIDITY_DAYS_MIN,
            "max_days": ownership.OWNERSHIP_VALIDITY_DAYS_MAX,
        },
    )


@ui_router.post("/settings/ownership")
def ui_ownership_settings_save(
    request: Request,
    tenant_id: int = Form(...),
    ownership_validity_days: str = Form(...),
):
    p = _ui_admin(request)
    if p is None:
        return _back("/login", error="Sign in as a Super Admin to manage ownership settings.")
    try:
        days = int(str(ownership_validity_days).strip())
    except ValueError:
        return _back(
            f"/settings/ownership?tenant_id={tenant_id}",
            error="Ownership validity days must be a whole number.",
        )
    try:
        with db.session() as s:
            services.set_ownership_validity_days(s, p, tenant_id, days)
    except (LookupError, PermissionError, services.ServiceError) as e:
        return _back(f"/settings/ownership?tenant_id={tenant_id}", error=str(e))
    return _back(
        f"/settings/ownership?tenant_id={tenant_id}",
        msg=f"Ownership proof validity saved: {days} days for this tenant.",
    )
