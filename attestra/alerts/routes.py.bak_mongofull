"""API and UI routes for per-tenant email alert settings."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from attestra import db, services
from attestra.alerts import service as alerts
from attestra.auth.roles import has_permission

api_router = APIRouter(prefix="/api/alerts", tags=["alerts"])
ui_router = APIRouter(include_in_schema=False)


def _principal(request: Request):
    from attestra.api import get_principal

    return get_principal(request)


def _err(e: Exception) -> HTTPException:
    if isinstance(e, LookupError):
        return HTTPException(404, str(e).strip("'\""))
    msg = str(e)
    return HTTPException(403 if "not allowed" in msg else 400, msg)


class SettingsIn(BaseModel):
    notify_new_high: bool | None = None
    notify_header_change: bool | None = None
    notify_sla_missed: bool | None = None
    recipients: list[str] | None = Field(default=None, max_length=50)


def _default_tenant(s, principal) -> int:
    """Pick a tenant for settings when the caller did not pass tenant_id.

    ``tenant_ids_for`` returns ``None`` for unrestricted platform leads/admins —
    that means every tenant, so we take the first by name, not an error.
    """
    from sqlalchemy import select

    from attestra.models import Tenant

    if principal.tenant_id:
        return int(principal.tenant_id)
    allowed = services.tenant_ids_for(s, principal)
    if allowed is not None:
        if not allowed:
            raise alerts.AlertError("no tenant in scope for email alert settings")
        return sorted(allowed)[0]
    row = s.scalars(select(Tenant).order_by(Tenant.name, Tenant.id)).first()
    if row is None:
        raise alerts.AlertError("no tenant in scope for email alert settings")
    return int(row.id)


@api_router.get("/settings")
def get_settings(tenant_id: int | None = None, principal=Depends(_principal)):
    try:
        with db.session() as s:
            tid = tenant_id if tenant_id is not None else _default_tenant(s, principal)
            alerts._check_tenant(s, principal, tid)
            row = alerts.get_settings(s, tid)
            out = alerts.settings_dict(row, tid)
            out["known_emails"] = alerts.known_tenant_emails(s, tid)
            return out
    except (LookupError, alerts.AlertError) as e:
        raise _err(e) from e


@api_router.put("/settings")
def put_settings(body: SettingsIn, tenant_id: int | None = None, principal=Depends(_principal)):
    try:
        with db.session() as s:
            tid = tenant_id if tenant_id is not None else _default_tenant(s, principal)
            row = alerts.update_settings(s, principal, tid, **body.model_dump(exclude_unset=True))
            return alerts.settings_dict(row, tid)
    except (LookupError, alerts.AlertError) as e:
        raise _err(e) from e


# ---------------------------------------------------------------- UI


def _ui_principal(request: Request):
    from attestra.web.ui import _principal as ui_principal

    p = ui_principal(request)
    if p is None or not has_permission(p.role, "webhook.manage"):
        return None
    return p


def _back(url: str, **kw) -> RedirectResponse:
    from attestra.web.ui import _back as ui_back

    return ui_back(url, **kw)


def _render(request: Request, template: str, ctx: dict) -> HTMLResponse:
    from attestra.web.ui import _render as ui_render

    return ui_render(request, template, ctx)


@ui_router.get("/settings/alerts", response_class=HTMLResponse)
def ui_alerts(request: Request, tenant_id: int | None = None):
    p = _ui_principal(request)
    if p is None:
        return _back("/login", error="Sign in as an admin or lead to manage email alerts.")
    with db.session() as s:
        try:
            tid = tenant_id if tenant_id is not None else _default_tenant(s, p)
            alerts._check_tenant(s, p, tid)
        except (LookupError, alerts.AlertError) as e:
            return _back("/", error=str(e))
        row = alerts.get_settings(s, tid)
        settings = alerts.settings_dict(row, tid)
        tenants = []
        allowed = services.tenant_ids_for(s, p)
        from sqlalchemy import select

        from attestra.models import Tenant

        q = select(Tenant).order_by(Tenant.name)
        if allowed is not None:
            q = q.where(Tenant.id.in_(allowed))
        tenants = [{"id": t.id, "name": t.name} for t in s.scalars(q)]
        known = alerts.known_tenant_emails(s, tid)
        from attestra.users import mailer

        smtp = mailer.smtp_configured()
    return _render(
        request,
        "alerts_settings.html",
        {
            "settings": settings,
            "tenants": tenants,
            "tenant_id": tid,
            "known_emails": known,
            "smtp": smtp,
        },
    )


@ui_router.post("/settings/alerts")
def ui_alerts_save(
    request: Request,
    tenant_id: int = Form(...),
    notify_new_high: str = Form(""),
    notify_header_change: str = Form(""),
    notify_sla_missed: str = Form(""),
    recipients: str = Form(""),
):
    p = _ui_principal(request)
    if p is None:
        return _back("/login", error="Sign in as an admin or lead to manage email alerts.")
    try:
        with db.session() as s:
            alerts.update_settings(
                s,
                p,
                tenant_id,
                notify_new_high=bool(notify_new_high),
                notify_header_change=bool(notify_header_change),
                notify_sla_missed=bool(notify_sla_missed),
                recipients=recipients,
            )
    except (LookupError, alerts.AlertError) as e:
        return _back(f"/settings/alerts?tenant_id={tenant_id}", error=str(e))
    return _back(f"/settings/alerts?tenant_id={tenant_id}", msg="Email alert settings saved.")
