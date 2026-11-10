"""API routes for engagement auth credential profiles."""
# @lat: [[interfaces#Auth-web credential profiles]]

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from attestra import db, services
from attestra.auth.roles import has_permission
from attestra.auth_web import profiles as svc

api_router = APIRouter(prefix="/api/auth-web", tags=["auth-web"])


def _principal(request: Request):
    from attestra.api import get_principal

    return get_principal(request)


def _err(e: Exception) -> HTTPException:
    if isinstance(e, LookupError):
        return HTTPException(404, str(e).strip("'\""))
    msg = str(e)
    return HTTPException(403 if "not allowed" in msg else 400, msg)


class ProfileCreateIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=200)
    role_name: str = ""
    purpose: str = ""
    method: str = "form"
    login_url: str = ""
    username_selector: str = ""
    password_selector: str = ""
    submit_selector: str = ""
    success_url_contains: str = ""
    secret: str | None = Field(default=None, description="Accepted once; never echoed")
    secret_ref: str | None = None
    asset_id: int | None = None
    config: dict | None = None
    extra_headers: str | None = Field(default=None, description="Non-secret 'Name: value' lines")
    extra_cookies: str | None = Field(
        default=None, description="Encrypted 'name=value; name2=value2' cookies; accepted once, never echoed"
    )


class RotateIn(BaseModel):
    secret: str = Field(..., min_length=1, description="New secret; never echoed")


@api_router.get("/engagements/{eid}/auth-profiles")
def list_auth_profiles(eid: int, principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.read"):
        raise HTTPException(403, "permission denied: engagement.read")
    try:
        with db.session() as s:
            rows = svc.list_profiles(s, eid, principal)
            return [svc.profile_dict(r) for r in rows]
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


@api_router.post("/engagements/{eid}/auth-profiles", status_code=201)
def create_auth_profile(eid: int, body: ProfileCreateIn, principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.write"):
        raise HTTPException(403, "permission denied: engagement.write")
    try:
        with db.session() as s:
            row = svc.create_profile(
                s,
                eid,
                label=body.label,
                role_name=body.role_name,
                purpose=body.purpose,
                method=body.method,
                login_url=body.login_url,
                username_selector=body.username_selector,
                password_selector=body.password_selector,
                submit_selector=body.submit_selector,
                success_url_contains=body.success_url_contains,
                secret_value=body.secret,
                secret_ref=body.secret_ref,
                asset_id=body.asset_id,
                config_json=body.config,
                extra_headers=body.extra_headers,
                extra_cookies=body.extra_cookies,
                actor=principal.actor,
                principal=principal,
            )
            return svc.profile_dict(row)
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


@api_router.post("/engagements/{eid}/auth-profiles/{pid}/validate")
def validate_auth_profile(eid: int, pid: int, principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.write"):
        raise HTTPException(403, "permission denied: engagement.write")
    try:
        with db.session() as s:
            row = svc.validate_profile(s, eid, pid, principal=principal, actor=principal.actor)
            return svc.profile_dict(row)
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


@api_router.post("/engagements/{eid}/auth-profiles/{pid}/rotate")
def rotate_auth_profile(eid: int, pid: int, body: RotateIn, principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.write"):
        raise HTTPException(403, "permission denied: engagement.write")
    try:
        with db.session() as s:
            row = svc.rotate_secret(
                s,
                eid,
                pid,
                secret_value=body.secret,
                principal=principal,
                actor=principal.actor,
            )
            return svc.profile_dict(row)
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


@api_router.post("/engagements/{eid}/auth-profiles/{pid}/revoke")
def revoke_auth_profile(eid: int, pid: int, principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.write"):
        raise HTTPException(403, "permission denied: engagement.write")
    try:
        with db.session() as s:
            row = svc.revoke_profile(s, eid, pid, principal=principal, actor=principal.actor)
            return svc.profile_dict(row)
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e


@api_router.delete("/engagements/{eid}/auth-profiles/{pid}", status_code=204)
def delete_auth_profile(eid: int, pid: int, principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.write"):
        raise HTTPException(403, "permission denied: engagement.write")
    try:
        with db.session() as s:
            svc.delete_profile(s, eid, pid, principal=principal, actor=principal.actor)
    except (LookupError, services.ServiceError) as e:
        raise _err(e) from e
