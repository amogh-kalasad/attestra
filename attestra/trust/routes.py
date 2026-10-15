"""Trust center HTTP routes: public pages under /trust, management under /api/v1/trust."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from attestra import db, services
from attestra.trust import service as trust
from attestra.trust.models import TrustItem

public_router = APIRouter(include_in_schema=False)
api_router = APIRouter(prefix="/api/v1/trust", tags=["trust"])


def _principal(request: Request):
    from attestra.api import get_principal

    return get_principal(request)


def _err(e: Exception) -> HTTPException:
    if isinstance(e, LookupError):
        return HTTPException(404, str(e).strip("'\""))
    msg = str(e)
    denied = ("not allowed", "not approved", "access request required")
    return HTTPException(403 if any(d in msg for d in denied) else 400, msg)


def _item_json(it: TrustItem) -> dict:
    return {"id": it.id, "kind": it.kind, "title": it.title, "summary": it.summary, "access": it.access,
            "ref_id": it.ref_id, "ref_key": it.ref_key, "sha256": it.sha256, "published": it.published,
            "published_by": it.published_by}


class ConfigIn(BaseModel):
    enabled: bool
    slug: str | None = None
    title: str | None = None
    description: str | None = None


class PublishIn(BaseModel):
    kind: str
    title: str
    summary: str = ""
    access: str = "public"
    ref_id: int | None = None
    ref_key: str = ""


@api_router.put("/tenants/{tenant_id}")
def configure(tenant_id: int, body: ConfigIn, principal=Depends(_principal)):
    try:
        with db.session() as s:
            c = trust.configure(s, principal, tenant_id, **body.model_dump())
            return {"tenant_id": tenant_id, "slug": c.slug, "enabled": c.enabled, "title": c.title}
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


@api_router.get("/tenants/{tenant_id}/items")
def items(tenant_id: int, principal=Depends(_principal)):
    try:
        with db.session() as s:
            trust._check_tenant(s, principal, tenant_id)
            return [_item_json(i) for i in trust.list_items(s, tenant_id, published_only=False)]
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


@api_router.post("/tenants/{tenant_id}/items")
def publish(tenant_id: int, body: PublishIn, principal=Depends(_principal)):
    try:
        with db.session() as s:
            return _item_json(trust.publish(s, principal, tenant_id, **body.model_dump()))
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


@api_router.post("/tenants/{tenant_id}/documents")
async def publish_document(tenant_id: int, title: str = Form(...), access: str = Form("nda"),
                           summary: str = Form(""), file: UploadFile = File(...),
                           principal=Depends(_principal)):
    data = await file.read()
    try:
        with db.session() as s:
            return _item_json(trust.publish(s, principal, tenant_id, kind="document", title=title, summary=summary,
                                            access=access, filename=file.filename or "", data=data))
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


@api_router.post("/items/{item_id}/unpublish")
def unpublish(item_id: int, principal=Depends(_principal)):
    try:
        with db.session() as s:
            return _item_json(trust.unpublish(s, principal, item_id))
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


@api_router.get("/tenants/{tenant_id}/requests")
def requests(tenant_id: int, principal=Depends(_principal)):
    try:
        with db.session() as s:
            return [{"id": r.id, "item_id": r.item_id, "name": r.requester_name, "email": r.requester_email,
                     "company": r.company, "reason": r.reason, "status": r.status, "decided_by": r.decided_by}
                    for r in trust.list_requests(s, principal, tenant_id)]
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


def _decide(request_id: int, principal, approve: bool):
    try:
        with db.session() as s:
            req, token = trust.decide(s, principal, request_id, approve=approve)
            return {"id": req.id, "status": req.status, "token": token}
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


@api_router.post("/requests/{request_id}/approve")
def approve(request_id: int, principal=Depends(_principal)):
    return _decide(request_id, principal, True)


@api_router.post("/requests/{request_id}/deny")
def deny(request_id: int, principal=Depends(_principal)):
    return _decide(request_id, principal, False)


# ------------------------------------------------------------------ public


@public_router.get("/trust/{slug}", response_class=HTMLResponse)
def public_page(request: Request, slug: str):
    from attestra.web.ui import templates

    with db.session() as s:
        view = trust.public_view(s, slug)
        if view is None:
            raise HTTPException(404, "not found")
        return templates.TemplateResponse(request, "trust_public.html", {"v": view, "slug": slug})


@public_router.post("/trust/{slug}/items/{item_id}/request", response_class=HTMLResponse)
def public_request(request: Request, slug: str, item_id: int, name: str = Form(...), email: str = Form(...),
                   company: str = Form(""), reason: str = Form(""), nda_accepted: bool = Form(False)):
    from attestra.web.ui import templates

    try:
        with db.session() as s:
            trust.request_access(s, slug, item_id, name=name, email=email, company=company, reason=reason,
                                 nda_accepted=nda_accepted)
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e
    return templates.TemplateResponse(request, "trust_request.html", {"slug": slug})


@public_router.get("/trust/{slug}/items/{item_id}/download")
def public_download(slug: str, item_id: int, token: str | None = None):
    try:
        with db.session() as s:
            path, name = trust.download(s, slug, item_id, token)
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e
    return FileResponse(path, filename=name)
