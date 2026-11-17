"""API and UI routes for Elite automated security-testing executions."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
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
    auth_profile_id: int | None = None
    secondary_auth_profile_id: int | None = None


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
                auth_profile_id=body.auth_profile_id,
                secondary_auth_profile_id=body.secondary_auth_profile_id,
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
    """Mark/keep execution QUEUED for the worker (does not run in the HTTP request)."""
    if not has_permission(principal.role, "engagement.write"):
        raise HTTPException(403, "permission denied: engagement.write")
    try:
        with db.session() as s:
            ex = orch.get_execution(s, xid, principal=principal)
            if ex.status == "CANCELLED":
                raise services.ServiceError("execution was cancelled")
            if ex.status not in ("QUEUED", "RUNNING"):
                raise services.ServiceError(f"execution status {ex.status} cannot be started")
            # Already QUEUED or RUNNING — worker claims QUEUED; no sync orch.run_execution.
            out = orch.execution_public_dict(ex)
            out["queued_for_worker"] = ex.status == "QUEUED"
            out["note"] = (
                "queued for worker"
                if ex.status == "QUEUED"
                else "already running on worker"
            )
            return out
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


def _optional_form_id(raw, *, field: str) -> int | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        pid = int(text)
    except (TypeError, ValueError):
        raise services.ServiceError(f"{field} must be a profile id") from None
    if pid <= 0:
        raise services.ServiceError(f"{field} must be a profile id")
    return pid


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
        primary_pid = _optional_form_id(form.get("auth_profile_id"), field="auth profile")
        secondary_pid = _optional_form_id(
            form.get("secondary_auth_profile_id"), field="secondary auth profile"
        )
        with db.session() as s:
            orch.create_execution(
                s,
                engagement_id=eid,
                asset_id=asset_id,
                test_case_ids=ids,
                actor=principal.username,
                principal=principal,
                profile=profile,
                auth_profile_id=primary_pid,
                secondary_auth_profile_id=secondary_pid,
            )
        return RedirectResponse(f"/engagements/{eid}#automated-testing", status_code=303)
    except services.ServiceError as e:
        return RedirectResponse(
            f"/engagements/{eid}?error={str(e)[:180]}#automated-testing",
            status_code=303,
        )


@ui_router.get("/engagements/{eid}/automated-vapt/executions/{xid}/evidence/{filename}")
def ui_execution_evidence(request: Request, eid: int, xid: int, filename: str):
    """Session-auth view of one saved run evidence image (only files in that run's folder)."""
    principal, redirect = _ui_principal(request)
    if redirect is not None:
        return redirect
    assert principal is not None
    if not has_permission(principal.role, "engagement.read"):
        raise HTTPException(403, "not allowed")
    if not services.client_may_download_evidence(principal.role, "screenshot"):
        raise HTTPException(403, "not allowed")
    from attestra.automated_vapt.evidence.run_evidence import safe_evidence_path

    try:
        with db.session() as s:
            ex = orch.get_execution(s, xid, principal=principal)
            if ex.engagement_id != eid:
                raise HTTPException(404, "evidence not found")
    except (services.ServiceError, LookupError):
        raise HTTPException(404, "evidence not found") from None
    path = safe_evidence_path(xid, filename)
    if path is None:
        raise HTTPException(404, "evidence not found")
    return FileResponse(
        str(path),
        media_type="image/png",
        headers={"Cache-Control": "private, max-age=300", "X-Content-Type-Options": "nosniff"},
    )


@ui_router.post("/engagements/{eid}/automated-vapt/executions/{xid}/run")
def ui_run_execution(request: Request, eid: int, xid: int):
    """Keep execution QUEUED; the background worker claims and runs it (non-blocking)."""
    principal, redirect = _ui_principal(request)
    if redirect is not None:
        return redirect
    assert principal is not None
    try:
        with db.session() as s:
            ex = orch.get_execution(s, xid, principal=principal)
            if ex.engagement_id != eid:
                raise services.ServiceError("execution not found")
            if ex.status == "CANCELLED":
                raise services.ServiceError("execution was cancelled")
            if ex.status not in ("QUEUED", "RUNNING"):
                raise services.ServiceError(f"execution status {ex.status} cannot be started")
        return RedirectResponse(
            f"/engagements/{eid}?msg=Automated+test+queued+for+worker#automated-testing",
            status_code=303,
        )
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


# ---------------------------------------------------------------- API spec import (C-04)
# @lat: [[web-api-probes#API spec upload route]]
# Upload an OpenAPI 3.x / Swagger 2.0, Postman v2.1 or HAR 1.2 file for one asset. The file
# is size-capped, validated and stored as a versioned inventory (sha256 dedup) in
# ``api_inventories``. Nothing is requested from the target here. Behind
# ``ATTESTRA_API_IMPORT_ENABLED`` (default off) and ``asset.write``.


def _api_spec_import(s, *, eid: int, aid: int, principal, filename: str, data: bytes) -> dict:
    from attestra.automated_vapt.api_inventory import SpecError, parse_spec
    from attestra.automated_vapt.api_inventory import store as inv_store
    from attestra.automated_vapt.testing._probe_base import api_import_enabled

    if not api_import_enabled():
        raise services.ServiceError("API spec import is disabled (ATTESTRA_API_IMPORT_ENABLED=0)")
    eng = services.get_engagement(s, eid, principal)
    asset = services.get_asset(s, aid, principal)
    if asset.engagement_id != eid:
        raise LookupError(f"target {aid} not found")
    if getattr(asset, "kind", "") not in ("web_app", "api"):
        raise services.ServiceError("API specs can only be attached to web app or API targets")
    allowed = [str(asset.identifier or "")]
    if getattr(asset, "api_base_url", ""):
        allowed.append(str(asset.api_base_url))
    try:
        inv = parse_spec(data, filename, allowed_origins=allowed)
    except SpecError as exc:
        raise services.ServiceError(f"invalid API spec: {exc}") from None
    actor = getattr(principal, "actor", None) or getattr(principal, "username", "") or "api"
    saved = inv_store.save(inv, tenant_id=eng.tenant_id, engagement_id=eid, asset_id=aid, actor=str(actor))
    try:
        from attestra import audit

        audit.record(
            s,
            str(actor),
            "api_spec.import",
            "asset",
            aid,
            sha256=inv.sha256,
            kind=inv.kind,
            version=saved.version,
            duplicate=saved.duplicate,
            operations=len(inv.operations),
        )
    except Exception:  # noqa: BLE001 - audit failure must not lose the upload
        pass
    return saved.public()


async def _read_upload(file: UploadFile) -> bytes:
    from attestra.automated_vapt.api_inventory.model import max_spec_bytes

    cap = max_spec_bytes()
    data = await file.read(cap + 1)
    if len(data) > cap:
        raise services.ServiceError(f"API spec larger than {cap} bytes")
    return data


@api_router.post("/engagements/{eid}/assets/{aid}/api-spec", status_code=201)
async def upload_api_spec(eid: int, aid: int, file: UploadFile = File(...), principal=Depends(_principal)):
    if not has_permission(principal.role, "asset.write"):
        raise HTTPException(403, "permission denied: asset.write")
    try:
        data = await _read_upload(file)
        with db.session() as s:
            return _api_spec_import(s, eid=eid, aid=aid, principal=principal, filename=file.filename or "", data=data)
    except (services.ServiceError, LookupError) as e:
        raise _err(e) from e


@api_router.get("/engagements/{eid}/assets/{aid}/api-spec")
def list_api_specs(eid: int, aid: int, principal=Depends(_principal)):
    if not has_permission(principal.role, "engagement.read"):
        raise HTTPException(403, "permission denied: engagement.read")
    from attestra.automated_vapt.api_inventory import store as inv_store

    try:
        with db.session() as s:
            eng = services.get_engagement(s, eid, principal)
            asset = services.get_asset(s, aid, principal)
            if asset.engagement_id != eid:
                raise LookupError(f"target {aid} not found")
            rows = inv_store.list_versions(tenant_id=eng.tenant_id, engagement_id=eid, asset_id=aid)
            return {"asset_id": aid, "versions": [r.public() for r in rows]}
    except (services.ServiceError, LookupError) as e:
        raise _err(e) from e


@ui_router.post("/engagements/{eid}/targets/{aid}/api-spec")
async def ui_upload_api_spec(request: Request, eid: int, aid: int, file: UploadFile = File(...)):
    principal, redirect = _ui_principal(request)
    if redirect is not None:
        return redirect
    assert principal is not None
    back = f"/engagements/{eid}/targets/{aid}"
    if not has_permission(principal.role, "asset.write"):
        return RedirectResponse(f"{back}?error=not+allowed#api-spec", status_code=303)
    try:
        data = await _read_upload(file)
        with db.session() as s:
            out = _api_spec_import(s, eid=eid, aid=aid, principal=principal, filename=file.filename or "", data=data)
        summ = out.get("summary") or {}
        note = "unchanged (same file)" if out.get("duplicate") else f"version {out.get('version')}"
        msg = f"API spec imported: {summ.get('operations', 0)} operations, {note}"
        from urllib.parse import quote_plus

        return RedirectResponse(f"{back}?msg={quote_plus(msg)}#api-spec", status_code=303)
    except (services.ServiceError, LookupError) as e:
        from urllib.parse import quote_plus

        return RedirectResponse(f"{back}?error={quote_plus(str(e)[:180])}#api-spec", status_code=303)
