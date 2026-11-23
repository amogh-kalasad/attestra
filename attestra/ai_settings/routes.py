"""API and UI routes for per-tenant AI provider settings (admin / lead)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from attestra.ai_settings import service as ai_settings
from attestra.auth.roles import has_permission
from attestra.web import data_access
from attestra.web import settings_store as store

api_router = APIRouter(prefix="/api/ai", tags=["ai-settings"])
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
    enabled: bool | None = None
    provider: str | None = Field(default=None, max_length=64)
    base_url: str | None = Field(default=None, max_length=500)
    model: str | None = Field(default=None, max_length=200)
    api_key: str | None = Field(default=None, max_length=8000)
    clear_api_key: bool | None = None


def _default_tenant(s, principal) -> int:
    return store.ai_default_tenant(s, principal)


@api_router.get("/settings")
def get_settings(tenant_id: int | None = None, principal=Depends(_principal)):
    try:
        with data_access.identity_session() as s:
            tid = tenant_id if tenant_id is not None else _default_tenant(s, principal)
            store.ai_check_tenant(s, principal, tid)
            return store.ai_settings(s, tid)
    except (LookupError, ai_settings.AiSettingsError) as e:
        raise _err(e) from e


@api_router.put("/settings")
def put_settings(body: SettingsIn, tenant_id: int | None = None, principal=Depends(_principal)):
    try:
        with data_access.identity_session() as s:
            tid = tenant_id if tenant_id is not None else _default_tenant(s, principal)
            data = body.model_dump(exclude_unset=True)
            clear = bool(data.pop("clear_api_key", False))
            return store.ai_update(s, principal, tid, clear_api_key=clear, **data)
    except (LookupError, ai_settings.AiSettingsError) as e:
        raise _err(e) from e


def _ui_principal(request: Request):
    from attestra.web.ui import _principal as ui_principal

    p = ui_principal(request)
    if p is None or not has_permission(p.role, "ai.configure"):
        return None
    return p


def _back(url: str, **kw) -> RedirectResponse:
    from attestra.web.ui import _back as ui_back

    return ui_back(url, **kw)


def _render(request: Request, template: str, ctx: dict) -> HTMLResponse:
    from attestra.web.ui import _render as ui_render

    return ui_render(request, template, ctx)


@ui_router.get("/settings/ai", response_class=HTMLResponse)
def ui_ai_settings(request: Request, tenant_id: int | None = None):
    p = _ui_principal(request)
    if p is None:
        return _back("/login", error="Sign in as an admin or lead to manage AI provider settings.")
    with data_access.identity_session() as s:
        try:
            tid = tenant_id if tenant_id is not None else _default_tenant(s, p)
            store.ai_check_tenant(s, p, tid)
        except (LookupError, ai_settings.AiSettingsError) as e:
            return _back("/", error=str(e))
        settings = store.ai_settings(s, tid)
        tenants = store.ai_tenants(s, p)
    return _render(
        request,
        "ai_settings.html",
        {"settings": settings, "tenants": tenants, "tenant_id": tid},
    )


@ui_router.post("/settings/ai")
def ui_ai_settings_save(
    request: Request,
    tenant_id: int = Form(...),
    enabled: str = Form(""),
    provider: str = Form("ollama"),
    base_url: str = Form(""),
    model: str = Form(""),
    api_key: str = Form(""),
    clear_api_key: str = Form(""),
):
    p = _ui_principal(request)
    if p is None:
        return _back("/login", error="Sign in as an admin or lead to manage AI provider settings.")
    try:
        with data_access.identity_session() as s:
            store.ai_update(
                s,
                p,
                tenant_id,
                enabled=bool(enabled),
                provider=provider,
                base_url=base_url,
                model=model,
                api_key=api_key if api_key.strip() else None,
                clear_api_key=bool(clear_api_key),
            )
    except (LookupError, ai_settings.AiSettingsError) as e:
        return _back(f"/settings/ai?tenant_id={tenant_id}", error=str(e))
    return _back(
        f"/settings/ai?tenant_id={tenant_id}",
        msg="AI provider settings saved for this tenant. API and worker use them automatically (no Docker restart).",
    )
