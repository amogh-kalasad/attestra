"""Share-link HTTP routes: public /share/{token}, management under /api/v1/shares."""
# @lat: [[interfaces#Share links]]

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from attestra import db, services
from attestra.auth.roles import has_permission
from attestra.share import service as share

api_router = APIRouter(prefix="/api/v1/shares", tags=["shares"])
public_router = APIRouter(include_in_schema=False)
ui_router = APIRouter(include_in_schema=False)

_INVALID = "link not valid"
_NO_CACHE = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "X-Robots-Tag": "noindex, nofollow",
}


def _principal(request: Request):
    from attestra.api import get_principal

    return get_principal(request)


def _err(e: Exception) -> HTTPException:
    if isinstance(e, LookupError):
        return HTTPException(404, str(e).strip("'\""))
    msg = str(e)
    denied = ("not allowed",)
    return HTTPException(403 if any(d in msg for d in denied) else 400, msg)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for") or ""
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    if request.client:
        return (request.client.host or "")[:64]
    return ""


class ShareCreateIn(BaseModel):
    kind: str = Field(description="grade | scan")
    asset_id: int | None = None
    scan_run_id: int | None = None
    ttl_days: int = share.DEFAULT_TTL_DAYS
    label: str = ""
    tenant_id: int | None = None


@api_router.post("", status_code=201)
def create_share(body: ShareCreateIn, principal=Depends(_principal)):
    if not has_permission(principal.role, "share.create"):
        raise HTTPException(403, "permission denied: share.create")
    try:
        with db.session() as s:
            row, token = share.create_share(
                s,
                principal,
                kind=body.kind,
                asset_id=body.asset_id,
                scan_run_id=body.scan_run_id,
                ttl_days=body.ttl_days,
                label=body.label,
            )
            item = share.to_list_item(row)
            item["token"] = token
            item["url"] = f"/share/{token}"
            item["badge_url"] = f"/share/{token}/badge.svg"
            return item
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


def _default_share_tenant(s, principal) -> int:
    """Resolve tenant for list when query param omitted. ``None`` scope = all tenants."""
    from sqlalchemy import select

    from attestra.models import Tenant

    if getattr(principal, "tenant_id", None):
        return int(principal.tenant_id)
    allowed = services.tenant_ids_for(s, principal)
    if allowed is not None:
        if not allowed:
            raise services.ServiceError("no tenant in scope for share list")
        return sorted(allowed)[0]
    row = s.scalars(select(Tenant).order_by(Tenant.name, Tenant.id)).first()
    if row is None:
        raise services.ServiceError("no tenant in scope for share list")
    return int(row.id)


@api_router.get("")
def list_shares(tenant_id: int | None = Query(None), principal=Depends(_principal)):
    if not has_permission(principal.role, "share.manage"):
        raise HTTPException(403, "permission denied: share.manage")
    try:
        with db.session() as s:
            tid = tenant_id if tenant_id is not None else _default_share_tenant(s, principal)
            rows = share.list_shares(s, principal, tid)
            return [share.to_list_item(r) for r in rows]
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


@api_router.post("/{share_id}/revoke")
def revoke_share(share_id: int, principal=Depends(_principal)):
    if not has_permission(principal.role, "share.manage"):
        raise HTTPException(403, "permission denied: share.manage")
    try:
        with db.session() as s:
            return share.to_list_item(share.revoke_share(s, principal, share_id))
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


# ------------------------------------------------------------------ public


@public_router.get("/share/{token}", response_class=HTMLResponse)
def public_share_page(request: Request, token: str):
    from attestra.web.ui import templates

    with db.session() as s:
        view = share.public_view(s, token, ip=_client_ip(request))
    if view is None:
        return HTMLResponse(
            _invalid_html(),
            status_code=410,
            headers=_NO_CACHE,
        )
    resp = templates.TemplateResponse(
        request,
        "share_public.html",
        {"v": view},
    )
    for k, val in _NO_CACHE.items():
        resp.headers[k] = val
    return resp


@public_router.get("/share/{token}/badge.svg")
def public_badge(request: Request, token: str):
    with db.session() as s:
        svg = share.badge_svg(s, token, ip=_client_ip(request))
    if svg is None:
        return HTMLResponse(_INVALID, status_code=410, headers=_NO_CACHE)
    headers = dict(_NO_CACHE)
    headers["Content-Type"] = "image/svg+xml; charset=utf-8"
    return Response(content=svg, media_type="image/svg+xml", headers=headers)


def _invalid_html() -> str:
    return (
        "<!doctype html><html lang=\"en\"><head>"
        "<meta charset=\"utf-8\">"
        "<meta name=\"robots\" content=\"noindex,nofollow\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>Link not valid</title></head>"
        "<body><p>link not valid</p></body></html>"
    )


# ------------------------------------------------------------------ UI list / revoke


def _ui_principal(request: Request):
    from attestra.web.ui import _principal as ui_principal

    p = ui_principal(request)
    if p is None or not has_permission(p.role, "share.manage"):
        return None
    return p


def _render(request: Request, template: str, ctx: dict) -> HTMLResponse:
    from attestra.web.ui import _render as ui_render

    return ui_render(request, template, ctx)


def _back(url: str, **kw):
    from attestra.web.ui import _back as ui_back

    return ui_back(url, **kw)


def _collect_shares(s, principal) -> tuple[list[dict], int]:
    from sqlalchemy import select

    from attestra.models import Tenant

    allowed = services.tenant_ids_for(s, principal)
    rows: list = []
    tenant_id = principal.tenant_id or 0
    if allowed is None:
        for t in s.scalars(select(Tenant).order_by(Tenant.id)):
            rows.extend(share.list_shares(s, principal, t.id))
            if not tenant_id:
                tenant_id = t.id
    elif principal.tenant_id is not None:
        rows = share.list_shares(s, principal, principal.tenant_id)
        tenant_id = principal.tenant_id
    else:
        for tid in sorted(allowed):
            rows.extend(share.list_shares(s, principal, tid))
            if not tenant_id:
                tenant_id = tid
    return [share.to_list_item(r) for r in rows], tenant_id or 0


@ui_router.get("/shares", response_class=HTMLResponse)
def shares_page(request: Request):
    p = _ui_principal(request)
    if p is None:
        return _back("/login", error="Sign in to manage share links.")
    with db.session() as s:
        items, tenant_id = _collect_shares(s, p)
    return _render(request, "shares_list.html", {"shares": items, "tenant_id": tenant_id})


@ui_router.post("/shares/{share_id}/revoke")
def shares_revoke(request: Request, share_id: int):
    p = _ui_principal(request)
    if p is None:
        return _back("/login", error="Sign in to manage share links.")
    try:
        with db.session() as s:
            share.revoke_share(s, p, share_id)
    except (LookupError, services.ServiceError) as e:
        return _back("/shares", error=str(e))
    return _back("/shares", msg="Share link revoked.")


@ui_router.post("/shares/create")
def shares_create(
    request: Request,
    kind: str = Form("grade"),
    asset_id: str = Form(""),
    scan_run_id: str = Form(""),
    ttl_days: int = Form(share.DEFAULT_TTL_DAYS),
    label: str = Form(""),
):
    p = _ui_principal(request)
    if p is None:
        return _back("/login", error="Sign in to manage share links.")
    aid = int(asset_id) if str(asset_id).strip().isdigit() else None
    sid = int(scan_run_id) if str(scan_run_id).strip().isdigit() else None
    try:
        with db.session() as s:
            _row, token = share.create_share(
                s, p, kind=kind, asset_id=aid, scan_run_id=sid, ttl_days=ttl_days, label=label
            )
            items, tenant_id = _collect_shares(s, p)
    except (LookupError, services.ServiceError) as e:
        with db.session() as s:
            items, tenant_id = _collect_shares(s, p)
        return _render(
            request,
            "shares_list.html",
            {"shares": items, "tenant_id": tenant_id, "error": str(e)},
        )
    return _render(
        request,
        "shares_list.html",
        {
            "shares": items,
            "tenant_id": tenant_id,
            "new_token": token,
            "msg": "Share link created. Copy the token now; it is shown only once.",
        },
    )
