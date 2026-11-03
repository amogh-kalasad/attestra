"""UI routes for organization Domain ownership (lead/admin)."""
# @lat: [[authorization#Target ownership#Organization domain ownership]]
# @lat: [[interfaces#Web dashboard]]

from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from sqlalchemy import select

from attestra import db, services
from attestra.auth.roles import has_permission
from attestra.models import Tenant
from attestra.org_ownership import service as org_own
from attestra.runner import ownership

ui_router = APIRouter(include_in_schema=False)


def _ui_principal(request: Request):
    from attestra.web.ui import _principal as ui_principal

    return ui_principal(request)


def _back(url: str, **kw) -> RedirectResponse:
    from attestra.web.ui import _back as ui_back

    return ui_back(url, **kw)


def _render(request: Request, template: str, ctx: dict) -> HTMLResponse:
    from attestra.web.ui import _render as ui_render

    return ui_render(request, template, ctx)


def _can_manage(p) -> bool:
    return p is not None and has_permission(p.role, "asset.verify_ownership")


def _default_tenant(s, principal) -> int:
    allowed = services.tenant_ids_for(s, principal)
    q = select(Tenant).order_by(Tenant.name)
    if allowed is not None:
        q = q.where(Tenant.id.in_(allowed))
    row = s.scalars(q).first()
    if row is None:
        raise LookupError("no organization in scope for domain ownership")
    return row.id


@ui_router.get("/settings/domain-ownership", response_class=HTMLResponse)
def ui_domain_ownership(request: Request, tenant_id: int | None = None):
    p = _ui_principal(request)
    if not _can_manage(p):
        return _back("/login", error="Sign in as a lead or admin to manage domain ownership.")
    with db.session() as s:
        try:
            tid = tenant_id if tenant_id is not None else _default_tenant(s, p)
            org_own._require_tenant(s, p, tid)
        except LookupError as e:
            return _back("/", error=str(e))
        org_own.backfill_ownership_hosts(s, tid, actor=p.actor)
        rows = org_own.list_ownership_hosts(s, tid)
        cards = [org_own.host_card(s, r) for r in rows]
        allowed = services.tenant_ids_for(s, p)
        q = select(Tenant).order_by(Tenant.name)
        if allowed is not None:
            q = q.where(Tenant.id.in_(allowed))
        tenants = [{"id": t.id, "name": t.name} for t in s.scalars(q)]
        validity_days = services.ownership_validity_days_for_tenant(s, tid)
    return _render(
        request,
        "domain_ownership.html",
        {
            "tenant_id": tid,
            "tenants": tenants,
            "hosts": cards,
            "validity_days": validity_days,
            "file_name": org_own.WELL_KNOWN_DOWNLOAD_NAME,
            "txt_prefix": ownership.TXT_PREFIX,
        },
    )


@ui_router.post("/settings/domain-ownership/hosts")
def ui_add_host(request: Request, tenant_id: int = Form(...), hostname: str = Form(...)):
    p = _ui_principal(request)
    if not _can_manage(p):
        return _back("/login", error="Sign in as a lead or admin to manage domain ownership.")
    try:
        with db.session() as s:
            row = org_own.add_ownership_host(s, p, tenant_id, hostname)
            hid = row.id
    except (LookupError, PermissionError, org_own.OrgOwnershipError, services.ServiceError) as e:
        return _back(f"/settings/domain-ownership?tenant_id={tenant_id}", error=str(e))
    return _back(
        f"/settings/domain-ownership?tenant_id={tenant_id}",
        msg=f"Hostname saved. Publish the DNS TXT value or download {org_own.WELL_KNOWN_DOWNLOAD_NAME}, then click Check now.",
        anchor=f"#host-{hid}",
    )


@ui_router.get("/settings/domain-ownership/hosts/{host_id}/attestra-verify.txt")
def ui_download_verify_file(request: Request, host_id: int):
    p = _ui_principal(request)
    if not _can_manage(p):
        return _back("/login", error="Sign in as a lead or admin to download the verification file.")
    with db.session() as s:
        try:
            row = org_own.get_ownership_host(s, host_id, p)
            org_own.renew_org_ownership_host_if_expired(s, row, actor=p.actor)
            body = row.ownership_token or ""
            audit_tid = row.tenant_id
            hostname = row.hostname
        except (LookupError, PermissionError) as e:
            return _back("/settings/domain-ownership", error=str(e))
        from attestra import audit

        audit.record(
            s,
            p.actor,
            "tenant.ownership_file_downloaded",
            "tenant_ownership_host",
            host_id,
            tenant_id=audit_tid,
            hostname=hostname,
            filename=org_own.WELL_KNOWN_DOWNLOAD_NAME,
        )
    return PlainTextResponse(
        body,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{org_own.WELL_KNOWN_DOWNLOAD_NAME}"',
            "Cache-Control": "no-store",
        },
    )


@ui_router.post("/settings/domain-ownership/hosts/{host_id}/verify")
def ui_verify_host(request: Request, host_id: int):
    p = _ui_principal(request)
    if not _can_manage(p):
        return _back("/login", error="Sign in as a lead or admin to verify domain ownership.")
    try:
        with db.session() as s:
            row = org_own.get_ownership_host(s, host_id, p)
            tid = row.tenant_id
            result = org_own.verify_ownership_host(s, p, host_id)
            hostname = row.hostname
    except (LookupError, PermissionError, org_own.OrgOwnershipError) as e:
        return _back("/settings/domain-ownership", error=str(e))
    if result.ok:
        days = None
        with db.session() as s:
            days = services.ownership_validity_days_for_tenant(s, tid)
        return _back(
            f"/settings/domain-ownership?tenant_id={tid}",
            msg=(
                f"Ownership of {hostname} verified"
                + (f" using {result.method}" if result.method else "")
                + f". Valid for {days} days. Engagements for this hostname can use this proof."
            ),
            anchor=f"#host-{host_id}",
        )
    return _back(
        f"/settings/domain-ownership?tenant_id={tid}",
        error="Not verified yet. " + result.message,
        anchor=f"#host-{host_id}",
    )


@ui_router.post("/settings/domain-ownership/hosts/{host_id}/confirm")
def ui_confirm_host(
    request: Request,
    host_id: int,
    confirm: str = Form(""),
    confirmed_by: str = Form(""),
):
    p = _ui_principal(request)
    if not _can_manage(p):
        return _back("/login", error="Sign in as a lead or admin to confirm domain ownership.")
    try:
        with db.session() as s:
            row = org_own.confirm_ownership_host(
                s, p, host_id, confirmed=bool(confirm), confirmed_by=confirmed_by
            )
            tid = row.tenant_id
            hostname = row.hostname
    except (LookupError, PermissionError, org_own.OrgOwnershipError) as e:
        return _back("/settings/domain-ownership", error=str(e))
    return _back(
        f"/settings/domain-ownership?tenant_id={tid}",
        msg=f"Ownership of {hostname} confirmed for this organization.",
        anchor=f"#host-{host_id}",
    )
