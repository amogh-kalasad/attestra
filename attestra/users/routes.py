"""User management routes: JSON API (``api_router``) and admin UI (``ui_router``)."""

from __future__ import annotations

from contextlib import contextmanager

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from attestra.api_security import RateLimiter
from attestra.users import mailer
from attestra.users import service as us
from attestra.web import data_access

# Accept/reset endpoints are public, so they get a tight per-IP limit.
LIMITER = RateLimiter(limit=10, window_s=60.0)


def _rate_limit(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    if not LIMITER.allow(f"token:{client}"):
        raise HTTPException(429, "rate limit exceeded")


def _principal(request: Request):
    from attestra.api import get_principal

    return get_principal(request)


def _link(request: Request, purpose: str, raw: str) -> str:
    base = str(request.base_url).rstrip("/")
    return f"{base}/{'reset' if purpose == 'reset' else 'invite'}/{raw}"


def _svc(name: str):
    """User-admin function by name from ``users.mongo_service`` (takes the Mongo db, returns dicts).

    Error types are shared with ``users.service`` (``us.UserAdminError``).
    """
    from attestra.users import mongo_service

    return getattr(mongo_service, name)


@contextmanager
def _uow():
    """The Mongo database handle (the ``mongo_service`` unit of work)."""
    yield data_access.mongo_db()


def _run(name: str, *args, **kwargs):
    with _uow() as uow:
        return _svc(name)(uow, *args, **kwargs)


def _call(name: str, *args, **kwargs):
    """API call; a single Mongo dict result is returned as an attribute row (``u.id``)."""
    try:
        out = _run(name, *args, **kwargs)
        return data_access.as_obj(out) if isinstance(out, dict) else out
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except us.UserAdminError as e:
        msg = str(e)
        raise HTTPException(403 if "not allowed" in msg else 400, msg) from e


def _issue(request: Request, name: str, *args, **kwargs) -> dict:
    with _uow() as uow:
        inv, raw = _svc(name)(uow, *args, **kwargs)
        inv = data_access.as_obj(inv)
        out = {"id": inv.id, "purpose": inv.purpose, "email": inv.email, "role": inv.role,
               "tenant_id": inv.tenant_id, "engagement_id": inv.engagement_id,
               "expires_at": us._aware(inv.expires_at).isoformat()}
    link = _link(request, out["purpose"], raw)
    out.update(token=raw, link=link, emailed=False)
    if out["email"] and mailer.smtp_configured():
        try:
            out["emailed"] = mailer.send_link(out["email"], link, purpose=out["purpose"])
        except Exception:  # email is best-effort; the link is still shown
            out["emailed"] = False
    return out


def _issue_safe(request: Request, name: str, *args, **kwargs) -> dict:
    try:
        return _issue(request, name, *args, **kwargs)
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except us.UserAdminError as e:
        msg = str(e)
        raise HTTPException(403 if "not allowed" in msg else 400, msg) from e


# ---------------------------------------------------------------- API

api_router = APIRouter(prefix="/api", tags=["users"])


class InviteIn(BaseModel):
    email: str = Field(max_length=254)
    role: str
    tenant_id: int | None = None
    engagement_id: int | None = None
    ttl_hours: int | None = None


class RoleIn(BaseModel):
    role: str


class AcceptIn(BaseModel):
    token: str = Field(max_length=200)
    username: str = Field(max_length=100)
    password: str = Field(max_length=500)
    display_name: str = Field(default="", max_length=200)


class ResetIn(BaseModel):
    token: str = Field(max_length=200)
    password: str = Field(max_length=500)


@api_router.get("/users")
def api_list_users(tenant_id: int | None = None, principal=Depends(_principal)):
    return _call("list_users", principal, tenant_id)


@api_router.get("/users/invites")
def api_list_invites(principal=Depends(_principal)):
    return _call("list_invites", principal)


@api_router.post("/users/invites", status_code=201)
def api_invite(body: InviteIn, request: Request, principal=Depends(_principal)):
    return _issue_safe(request, "create_invite", principal, email=body.email, role=body.role,
                       tenant_id=body.tenant_id, engagement_id=body.engagement_id, ttl_hours=body.ttl_hours)


@api_router.delete("/users/invites/{iid}")
def api_revoke_invite(iid: int, principal=Depends(_principal)):
    _call("revoke_invite", principal, iid)
    return {"revoked": iid}


@api_router.post("/users/{uid}/role")
def api_set_role(uid: int, body: RoleIn, principal=Depends(_principal)):
    u = _call("set_role", principal, uid, body.role)
    return {"id": u.id, "role": u.role}


@api_router.post("/users/{uid}/disable")
def api_disable(uid: int, principal=Depends(_principal)):
    u = _call("set_active", principal, uid, False)
    return {"id": u.id, "active": u.active}


@api_router.post("/users/{uid}/enable")
def api_enable(uid: int, principal=Depends(_principal)):
    u = _call("set_active", principal, uid, True)
    return {"id": u.id, "active": u.active}


@api_router.post("/users/{uid}/reset-password")
def api_reset(uid: int, request: Request, principal=Depends(_principal)):
    return _issue_safe(request, "create_reset", principal, uid)


@api_router.post("/invites/accept", status_code=201, dependencies=[Depends(_rate_limit)])
def api_accept(body: AcceptIn):
    u = _call("accept_invite", body.token, username=body.username, password=body.password,
              display_name=body.display_name)
    return {"id": u.id, "username": u.username, "role": u.role}


@api_router.post("/password-reset", dependencies=[Depends(_rate_limit)])
def api_password_reset(body: ResetIn):
    u = _call("complete_reset", body.token, password=body.password)
    return {"id": u.id, "username": u.username}


# ---------------------------------------------------------------- UI

ui_router = APIRouter(include_in_schema=False)


def _ui_principal(request: Request):
    from attestra.web.ui import _principal as ui_principal

    p = ui_principal(request)
    if p is None or p.role not in us.MANAGER_ROLES:
        return None
    return p


def _back(url: str, **kw) -> RedirectResponse:
    from attestra.web.ui import _back as ui_back

    return ui_back(url, **kw)


def _render(request: Request, template: str, ctx: dict) -> HTMLResponse:
    from attestra.web.ui import _render as ui_render

    return ui_render(request, template, ctx)


@ui_router.get("/users", response_class=HTMLResponse)
def ui_users(request: Request, tenant_id: int | None = None):
    p = _ui_principal(request)
    if p is None:
        return _back("/login", error="Sign in as an admin or lead to manage users.")
    with _uow() as uow:
        ctx = {
            "users": _svc("list_users")(uow, p, tenant_id),
            "invites": _svc("list_invites")(uow, p),
            "tenants": _svc("tenants_for_form")(uow, p),
            "engagements": _svc("engagements_for_form")(uow, p),
            "roles": us.assignable_roles(p),
            "all_roles": us.ROLES,
            "is_admin": p.role == "admin",
            "tenant_filter": tenant_id,
            "smtp": mailer.smtp_configured(),
        }
    return _render(request, "users_list.html", ctx)


def _opt_int(v: str) -> int | None:
    v = (v or "").strip()
    return int(v) if v.isdigit() else None


def _ui_issue(request: Request, name: str, *args, **kwargs):
    try:
        out = _issue(request, name, *args, **kwargs)
    except (us.UserAdminError, LookupError) as e:
        return _back("/users", error=str(e))
    return _render(request, "users_link.html", {"inv": out})


@ui_router.post("/users/invite")
def ui_invite(request: Request, email: str = Form(...), role: str = Form(...), tenant_id: str = Form(""),
              engagement_id: str = Form("")):
    p = _ui_principal(request)
    if p is None:
        return _back("/login", error="Sign in as an admin or lead to manage users.")
    return _ui_issue(request, "create_invite", p, email=email, role=role, tenant_id=_opt_int(tenant_id),
                     engagement_id=_opt_int(engagement_id))


@ui_router.post("/users/{uid}/reset")
def ui_reset(request: Request, uid: int):
    p = _ui_principal(request)
    if p is None:
        return _back("/login", error="Sign in as an admin or lead to manage users.")
    return _ui_issue(request, "create_reset", p, uid)


def _ui_do(request: Request, ok: str, name: str, *args):
    p = _ui_principal(request)
    if p is None:
        return _back("/login", error="Sign in as an admin or lead to manage users.")
    try:
        _run(name, p, *args)
    except (us.UserAdminError, LookupError) as e:
        return _back("/users", error=str(e))
    return _back("/users", msg=ok)


@ui_router.post("/users/{uid}/role")
def ui_role(request: Request, uid: int, role: str = Form(...)):
    return _ui_do(request, "Role updated.", "set_role", uid, role)


@ui_router.post("/users/{uid}/disable")
def ui_disable(request: Request, uid: int):
    return _ui_do(request, "User disabled.", "set_active", uid, False)


@ui_router.post("/users/{uid}/enable")
def ui_enable(request: Request, uid: int):
    return _ui_do(request, "User enabled.", "set_active", uid, True)


@ui_router.post("/users/invites/{iid}/revoke")
def ui_revoke(request: Request, iid: int):
    return _ui_do(request, "Invite revoked.", "revoke_invite", iid)


def _token_page(request: Request, token: str, purpose: str, template: str, error: str | None = None):
    try:
        info = _run("peek", token, purpose)
    except us.UserAdminError as e:
        return _render(request, template, {"invalid": str(e), "token": "", "info": {}})
    return _render(request, template, {"invalid": None, "token": token, "info": info, "form_error": error})


@ui_router.get("/invite/{token}", response_class=HTMLResponse)
def ui_accept_form(request: Request, token: str):
    return _token_page(request, token, "invite", "invite_accept.html")


@ui_router.post("/invite/{token}", dependencies=[Depends(_rate_limit)])
def ui_accept(request: Request, token: str, username: str = Form(...), password: str = Form(...),
              confirm: str = Form(...), display_name: str = Form("")):
    if password != confirm:
        return _token_page(request, token, "invite", "invite_accept.html", "Passwords do not match.")
    try:
        _run("accept_invite", token, username=username, password=password, display_name=display_name)
    except us.UserAdminError as e:
        return _token_page(request, token, "invite", "invite_accept.html", str(e))
    return _back("/login", msg="Account created. Sign in with your new username and password.")


@ui_router.get("/reset/{token}", response_class=HTMLResponse)
def ui_reset_form(request: Request, token: str):
    return _token_page(request, token, "reset", "invite_reset.html")


@ui_router.post("/reset/{token}", dependencies=[Depends(_rate_limit)])
def ui_reset_submit(request: Request, token: str, password: str = Form(...), confirm: str = Form(...)):
    if password != confirm:
        return _token_page(request, token, "reset", "invite_reset.html", "Passwords do not match.")
    try:
        _run("complete_reset", token, password=password)
    except us.UserAdminError as e:
        return _token_page(request, token, "reset", "invite_reset.html", str(e))
    return _back("/login", msg="Password updated. Sign in with your new password.")
