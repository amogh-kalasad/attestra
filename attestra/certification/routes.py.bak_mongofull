"""API and UI routes for Super Admin Certification Authority settings."""
# @lat: [[reports#Certification Authority branding]]
# @lat: [[interfaces#REST API]]

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from attestra import db
from attestra.auth.roles import has_permission
from attestra.certification import service as ca

api_router = APIRouter(prefix="/api/certification-authority", tags=["certification-authority"])
ui_router = APIRouter(include_in_schema=False)


def _principal(request: Request):
    from attestra.api import get_principal

    return get_principal(request)


def _err(e: Exception) -> HTTPException:
    msg = str(e)
    if isinstance(e, LookupError):
        return HTTPException(404, msg.strip("'\""))
    if "Super Admin" in msg or "not allowed" in msg or "only a" in msg:
        return HTTPException(403, msg)
    return HTTPException(400, msg)


class SettingsIn(BaseModel):
    """JSON body for partial updates without a logo upload."""

    legal_name: str | None = Field(default=None, max_length=200)
    signer_name: str | None = Field(default=None, max_length=200)
    signer_title: str | None = Field(default=None, max_length=200)
    authorization_statement: str | None = Field(default=None, max_length=4000)
    clear_logo: bool = False
    address_line1: str | None = Field(default=None, max_length=300)
    address_line2: str | None = Field(default=None, max_length=300)
    city: str | None = Field(default=None, max_length=120)
    state: str | None = Field(default=None, max_length=120)
    postal_code: str | None = Field(default=None, max_length=40)
    country: str | None = Field(default=None, max_length=120)
    contact_name: str | None = Field(default=None, max_length=200)
    contact_email: str | None = Field(default=None, max_length=200)
    contact_phone: str | None = Field(default=None, max_length=80)
    website: str | None = Field(default=None, max_length=300)


@api_router.get("")
def get_ca_settings(principal=Depends(_principal)):
    """Read Certification Authority settings (Super Admin only)."""
    if not has_permission(principal.role, "certification.manage"):
        raise HTTPException(403, "only a Super Admin can view Certification Authority settings")
    with db.session() as s:
        return ca.settings_dict(ca.get_settings(s))


@api_router.put("")
def put_ca_settings(body: SettingsIn, principal=Depends(_principal)):
    """Partial JSON update (Super Admin only). Use POST …/logo to upload a logo."""
    try:
        with db.session() as s:
            row = ca.update_settings(s, principal, **body.model_dump(exclude_unset=True))
            return ca.settings_dict(row)
    except ca.CertificationError as e:
        raise _err(e) from e


@api_router.post("/logo")
async def post_ca_logo(logo: UploadFile = File(...), principal=Depends(_principal)):
    """Replace the brand logo (Super Admin only)."""
    data = await logo.read()
    try:
        with db.session() as s:
            row = ca.update_settings(s, principal, logo=data)
            return ca.settings_dict(row)
    except ca.CertificationError as e:
        raise _err(e) from e


# ---------------------------------------------------------------- UI


def _ui_admin(request: Request):
    from attestra.web.ui import _principal as ui_principal

    p = ui_principal(request)
    if p is None or not has_permission(p.role, "certification.manage"):
        return None
    return p


def _back(url: str, **kw) -> RedirectResponse:
    from attestra.web.ui import _back as ui_back

    return ui_back(url, **kw)


def _render(request: Request, template: str, ctx: dict) -> HTMLResponse:
    from attestra.web.ui import _render as ui_render

    return ui_render(request, template, ctx)


@ui_router.get("/settings/certification-authority", response_class=HTMLResponse)
def ui_ca_page(request: Request):
    p = _ui_admin(request)
    if p is None:
        from attestra.web.ui import _principal as ui_principal

        if ui_principal(request) is None:
            return _back("/login", error="Sign in as a Super Admin to manage Certification Authority.")
        return _back("/", error="Only a Super Admin can manage Certification Authority settings.")
    with db.session() as s:
        settings = ca.settings_dict(ca.get_settings(s))
    return _render(request, "certification_authority.html", {"settings": settings})


@ui_router.post("/settings/certification-authority")
async def ui_ca_save(
    request: Request,
    legal_name: str = Form(""),
    signer_name: str = Form(""),
    signer_title: str = Form(""),
    authorization_statement: str = Form(""),
    clear_logo: str = Form(""),
    address_line1: str = Form(""),
    address_line2: str = Form(""),
    city: str = Form(""),
    state: str = Form(""),
    postal_code: str = Form(""),
    country: str = Form(""),
    contact_name: str = Form(""),
    contact_email: str = Form(""),
    contact_phone: str = Form(""),
    website: str = Form(""),
    logo: UploadFile | None = File(None),
):
    p = _ui_admin(request)
    if p is None:
        return _back("/", error="Only a Super Admin can manage Certification Authority settings.")
    logo_bytes = await logo.read() if logo and logo.filename else None
    try:
        with db.session() as s:
            ca.update_settings(
                s,
                p,
                legal_name=legal_name,
                signer_name=signer_name,
                signer_title=signer_title,
                authorization_statement=authorization_statement,
                logo=logo_bytes,
                clear_logo=bool(clear_logo),
                address_line1=address_line1,
                address_line2=address_line2,
                city=city,
                state=state,
                postal_code=postal_code,
                country=country,
                contact_name=contact_name,
                contact_email=contact_email,
                contact_phone=contact_phone,
                website=website,
            )
    except ca.CertificationError as e:
        return _back("/settings/certification-authority", error=str(e))
    return _back("/settings/certification-authority", msg="Certification Authority settings saved.")
