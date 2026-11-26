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
    mutation_approval_id: str | None = None


class MutationApprovalRequestIn(BaseModel):
    asset_id: int
    target_origin: str
    endpoint_pattern: str
    http_method: str = "PATCH"
    test_record_id: str
    approved_fields: list[str] = Field(..., min_length=1)
    approved_values: dict | None = None
    cleanup_plan: str
    expected_behavior: str = ""
    ttl_minutes: int = 60
    test_case_id: str = "T22"
    execution_id: int | None = None


class MutationApprovalActionIn(BaseModel):
    reason: str = ""


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
                mutation_approval_id=body.mutation_approval_id,
            )
            return orch.execution_public_dict(ex)
    except services.ServiceError as e:
        raise _err(e) from e


def _mutation_actor(principal) -> tuple[str, int | None, str]:
    actor = getattr(principal, "actor", None) or getattr(principal, "username", "") or "api"
    uid = getattr(principal, "user_id", None)
    role = str(getattr(principal, "role", "") or "").strip().lower()
    return str(actor), uid if uid is None or isinstance(uid, int) else int(uid), role


@api_router.get("/engagements/{eid}/mutation-approvals")
def list_mutation_approvals(eid: int, principal=Depends(_principal)):
    """List production safe-mutation approvals for an engagement (tenant-scoped)."""
    if not has_permission(principal.role, "engagement.read"):
        raise HTTPException(403, "permission denied: engagement.read")
    try:
        from attestra.automated_vapt.core import mutation_approval as ma

        with db.session() as s:
            eng = services.get_engagement(s, eid, principal)
            store = ma.ApprovalStore()
            rows = [r for r in store.list(eid) if int(r.tenant_id) == int(eng.tenant_id)]
            return {
                "enabled": ma.production_safe_mutation_enabled(),
                "approvals": [r.to_public() for r in rows],
            }
    except services.ServiceError as e:
        raise _err(e) from e


@api_router.post("/engagements/{eid}/mutation-approvals", status_code=201)
def request_mutation_approval(eid: int, body: MutationApprovalRequestIn, principal=Depends(_principal)):
    """Request a one-time four-eyes production safe-mutation approval."""
    if not has_permission(principal.role, "engagement.write"):
        raise HTTPException(403, "permission denied: engagement.write")
    from attestra.automated_vapt.core import mutation_approval as ma

    try:
        with db.session() as s:
            eng = services.get_engagement(s, eid, principal)
            asset = services.get_asset(s, body.asset_id, principal)
            if asset.engagement_id != eid:
                raise services.ServiceError("asset not found for this engagement")
            actor, uid, role = _mutation_actor(principal)
            store = ma.ApprovalStore()
            row = ma.request_approval(
                store,
                tenant_id=int(eng.tenant_id),
                engagement_id=int(eid),
                asset_id=int(asset.id),
                requester=actor,
                requester_user_id=uid,
                requester_role=role,
                target_origin=body.target_origin,
                endpoint_pattern=body.endpoint_pattern,
                http_method=body.http_method,
                test_record_id=body.test_record_id,
                approved_fields=list(body.approved_fields),
                approved_values=dict(body.approved_values or {}),
                cleanup_plan=body.cleanup_plan,
                expected_behavior=body.expected_behavior,
                ttl_minutes=body.ttl_minutes,
                test_case_id=body.test_case_id,
                execution_id=body.execution_id,
            )
            ma.audit_lifecycle(s, actor=actor, action="requested", approval=row)
            return row.to_public()
    except ma.MutationApprovalError as e:
        raise HTTPException(400, str(e)) from e
    except services.ServiceError as e:
        raise _err(e) from e


@api_router.post("/engagements/{eid}/mutation-approvals/{approval_id}/approve")
def approve_mutation_approval(eid: int, approval_id: str, principal=Depends(_principal)):
    """Four-eyes approve a pending production safe-mutation (requester cannot self-approve)."""
    if not has_permission(principal.role, "engagement.write"):
        raise HTTPException(403, "permission denied: engagement.write")
    try:
        from attestra.automated_vapt.core import mutation_approval as ma

        with db.session() as s:
            eng = services.get_engagement(s, eid, principal)
            actor, uid, role = _mutation_actor(principal)
            store = ma.ApprovalStore()
            row = ma.approve_approval(
                store,
                engagement_id=eid,
                approval_id=approval_id,
                approver=actor,
                approver_user_id=uid,
                approver_role=role,
                tenant_id=int(eng.tenant_id),
            )
            ma.audit_lifecycle(s, actor=actor, action="approved", approval=row)
            return row.to_public()
    except Exception as e:
        from attestra.automated_vapt.core.mutation_approval import MutationApprovalError

        if isinstance(e, MutationApprovalError):
            raise HTTPException(400, str(e)) from e
        if isinstance(e, services.ServiceError):
            raise _err(e) from e
        raise


@api_router.post("/engagements/{eid}/mutation-approvals/{approval_id}/reject")
def reject_mutation_approval(
    eid: int, approval_id: str, body: MutationApprovalActionIn | None = None, principal=Depends(_principal)
):
    """Reject a pending production safe-mutation request."""
    if not has_permission(principal.role, "engagement.write"):
        raise HTTPException(403, "permission denied: engagement.write")
    try:
        from attestra.automated_vapt.core import mutation_approval as ma

        with db.session() as s:
            eng = services.get_engagement(s, eid, principal)
            actor, uid, role = _mutation_actor(principal)
            store = ma.ApprovalStore()
            row = ma.reject_approval(
                store,
                engagement_id=eid,
                approval_id=approval_id,
                actor=actor,
                actor_user_id=uid,
                actor_role=role,
                reason=(body.reason if body else "") or "",
                tenant_id=int(eng.tenant_id),
            )
            ma.audit_lifecycle(s, actor=actor, action="rejected", approval=row)
            return row.to_public()
    except Exception as e:
        from attestra.automated_vapt.core.mutation_approval import MutationApprovalError

        if isinstance(e, MutationApprovalError):
            raise HTTPException(400, str(e)) from e
        if isinstance(e, services.ServiceError):
            raise _err(e) from e
        raise


@api_router.post("/engagements/{eid}/mutation-approvals/{approval_id}/revoke")
def revoke_mutation_approval(
    eid: int, approval_id: str, body: MutationApprovalActionIn | None = None, principal=Depends(_principal)
):
    """Revoke a pending or approved (unused) production safe-mutation grant."""
    if not has_permission(principal.role, "engagement.write"):
        raise HTTPException(403, "permission denied: engagement.write")
    try:
        from attestra.automated_vapt.core import mutation_approval as ma

        with db.session() as s:
            eng = services.get_engagement(s, eid, principal)
            actor, uid, role = _mutation_actor(principal)
            store = ma.ApprovalStore()
            row = ma.revoke_approval(
                store,
                engagement_id=eid,
                approval_id=approval_id,
                actor=actor,
                actor_user_id=uid,
                actor_role=role,
                reason=(body.reason if body else "") or "",
                tenant_id=int(eng.tenant_id),
            )
            ma.audit_lifecycle(s, actor=actor, action="revoked", approval=row)
            return row.to_public()
    except Exception as e:
        from attestra.automated_vapt.core.mutation_approval import MutationApprovalError

        if isinstance(e, MutationApprovalError):
            raise HTTPException(400, str(e)) from e
        if isinstance(e, services.ServiceError):
            raise _err(e) from e
        raise


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
        mutation_approval_id = str(form.get("mutation_approval_id") or "").strip() or None
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
                mutation_approval_id=mutation_approval_id,
            )
        return RedirectResponse(f"/engagements/{eid}#automated-testing", status_code=303)
    except services.ServiceError as e:
        return RedirectResponse(
            f"/engagements/{eid}?error={str(e)[:180]}#automated-testing",
            status_code=303,
        )


@ui_router.post("/engagements/{eid}/mutation-approvals")
async def ui_request_mutation_approval(request: Request, eid: int):
    """HTML form: request a production safe-mutation approval."""
    principal, redirect = _ui_principal(request)
    if redirect is not None:
        return redirect
    assert principal is not None
    form = await request.form()
    try:
        from attestra.automated_vapt.core import mutation_approval as ma

        fields_raw = str(form.get("approved_fields") or "")
        fields = [f.strip() for f in fields_raw.replace(";", ",").split(",") if f.strip()]
        values_raw = str(form.get("approved_values") or "").strip()
        approved_values: dict = {}
        if values_raw:
            import json as _json

            try:
                parsed = _json.loads(values_raw)
                if isinstance(parsed, dict):
                    approved_values = parsed
            except _json.JSONDecodeError as exc:
                raise services.ServiceError(f"approved_values must be JSON object: {exc}") from None
        with db.session() as s:
            eng = services.get_engagement(s, eid, principal)
            asset_id = int(str(form.get("asset_id") or "0"))
            asset = services.get_asset(s, asset_id, principal)
            if asset.engagement_id != eid:
                raise services.ServiceError("asset not found for this engagement")
            actor, uid, role = _mutation_actor(principal)
            store = ma.ApprovalStore()
            row = ma.request_approval(
                store,
                tenant_id=int(eng.tenant_id),
                engagement_id=int(eid),
                asset_id=int(asset.id),
                requester=actor,
                requester_user_id=uid,
                requester_role=role,
                target_origin=str(form.get("target_origin") or ""),
                endpoint_pattern=str(form.get("endpoint_pattern") or ""),
                http_method=str(form.get("http_method") or "PATCH"),
                test_record_id=str(form.get("test_record_id") or ""),
                approved_fields=fields,
                approved_values=approved_values,
                cleanup_plan=str(form.get("cleanup_plan") or ""),
                expected_behavior=str(form.get("expected_behavior") or ""),
                ttl_minutes=int(str(form.get("ttl_minutes") or "60") or "60"),
            )
            ma.audit_lifecycle(s, actor=actor, action="requested", approval=row)
        return RedirectResponse(
            f"/engagements/{eid}?msg=Mutation+approval+requested#mutation-approvals",
            status_code=303,
        )
    except Exception as e:
        from attestra.automated_vapt.core.mutation_approval import MutationApprovalError

        msg = str(e)[:180]
        if not isinstance(e, (MutationApprovalError, services.ServiceError)):
            msg = f"request failed: {msg}"
        return RedirectResponse(
            f"/engagements/{eid}?error={msg}#mutation-approvals",
            status_code=303,
        )


@ui_router.post("/engagements/{eid}/mutation-approvals/{approval_id}/approve")
def ui_approve_mutation_approval(request: Request, eid: int, approval_id: str):
    principal, redirect = _ui_principal(request)
    if redirect is not None:
        return redirect
    assert principal is not None
    try:
        from attestra.automated_vapt.core import mutation_approval as ma

        with db.session() as s:
            eng = services.get_engagement(s, eid, principal)
            actor, uid, role = _mutation_actor(principal)
            row = ma.approve_approval(
                ma.ApprovalStore(),
                engagement_id=eid,
                approval_id=approval_id,
                approver=actor,
                approver_user_id=uid,
                approver_role=role,
                tenant_id=int(eng.tenant_id),
            )
            ma.audit_lifecycle(s, actor=actor, action="approved", approval=row)
        return RedirectResponse(
            f"/engagements/{eid}?msg=Mutation+approval+granted#mutation-approvals",
            status_code=303,
        )
    except Exception as e:
        return RedirectResponse(
            f"/engagements/{eid}?error={str(e)[:180]}#mutation-approvals",
            status_code=303,
        )


@ui_router.post("/engagements/{eid}/mutation-approvals/{approval_id}/reject")
def ui_reject_mutation_approval(request: Request, eid: int, approval_id: str):
    principal, redirect = _ui_principal(request)
    if redirect is not None:
        return redirect
    assert principal is not None
    try:
        from attestra.automated_vapt.core import mutation_approval as ma

        with db.session() as s:
            eng = services.get_engagement(s, eid, principal)
            actor, uid, role = _mutation_actor(principal)
            row = ma.reject_approval(
                ma.ApprovalStore(),
                engagement_id=eid,
                approval_id=approval_id,
                actor=actor,
                actor_user_id=uid,
                actor_role=role,
                reason="rejected via UI",
                tenant_id=int(eng.tenant_id),
            )
            ma.audit_lifecycle(s, actor=actor, action="rejected", approval=row)
        return RedirectResponse(
            f"/engagements/{eid}?msg=Mutation+approval+rejected#mutation-approvals",
            status_code=303,
        )
    except Exception as e:
        return RedirectResponse(
            f"/engagements/{eid}?error={str(e)[:180]}#mutation-approvals",
            status_code=303,
        )


@ui_router.post("/engagements/{eid}/mutation-approvals/{approval_id}/revoke")
def ui_revoke_mutation_approval(request: Request, eid: int, approval_id: str):
    principal, redirect = _ui_principal(request)
    if redirect is not None:
        return redirect
    assert principal is not None
    try:
        from attestra.automated_vapt.core import mutation_approval as ma

        with db.session() as s:
            eng = services.get_engagement(s, eid, principal)
            actor, uid, role = _mutation_actor(principal)
            row = ma.revoke_approval(
                ma.ApprovalStore(),
                engagement_id=eid,
                approval_id=approval_id,
                actor=actor,
                actor_user_id=uid,
                actor_role=role,
                reason="revoked via UI",
                tenant_id=int(eng.tenant_id),
            )
            ma.audit_lifecycle(s, actor=actor, action="revoked", approval=row)
        return RedirectResponse(
            f"/engagements/{eid}?msg=Mutation+approval+revoked#mutation-approvals",
            status_code=303,
        )
    except Exception as e:
        return RedirectResponse(
            f"/engagements/{eid}?error={str(e)[:180]}#mutation-approvals",
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
