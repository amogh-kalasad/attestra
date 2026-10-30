"""Main Elite automated security-testing execution controller."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit
from attestra.automated_vapt.core import authorization_guard as guard
from attestra.automated_vapt.core import execution_manager as exec_mgr
from attestra.automated_vapt.core import scope_validator
from attestra.automated_vapt.core.test_context import TestContext
from attestra.automated_vapt.core.test_registry import get_test_case, list_test_cases
from attestra.models import AutomatedTestExecution, utcnow
from attestra.services import ServiceError

# @lat: [[architecture#Elite automated security testing]]
# @lat: [[architecture#Elite automated security testing#Orchestrator]]


def create_execution(
    s: Session,
    *,
    engagement_id: int,
    asset_id: int,
    test_case_ids: list[str],
    actor: str,
    principal=None,
    profile: str = "baseline",
    allow_private: bool | None = None,
) -> AutomatedTestExecution:
    """Queue an approved Elite test execution for an engagement asset."""
    guard.require_feature_enabled()
    guard.require_write(principal)
    eng = guard.load_engagement(s, engagement_id, principal)
    guard.assert_engagement_ready(eng)
    asset = guard.load_asset(s, eng, asset_id)

    ids = _normalize_test_ids(test_case_ids)
    target = (asset.identifier or "").strip()
    if not target:
        raise ServiceError("asset has no target identifier")

    private = allow_private if allow_private is not None else scope_validator.is_loopback_target(target)
    seeds = [ln.strip() for ln in (asset.crawl_seed_urls or "").splitlines() if ln.strip()]
    scope = scope_validator.build_scope_from_asset(target, extra_seeds=seeds, allow_private=private)
    # Validate the asset URL itself is in the scope we just built (shape/SSRF).
    scope_validator.validate_target_url(target, scope, check_dns=not private)

    ex = AutomatedTestExecution(
        engagement_id=eng.id,
        tenant_id=eng.tenant_id,
        asset_id=asset.id,
        target_base_url=target,
        profile=(profile or "baseline").strip().lower() or "baseline",
        test_case_ids=ids,
        status="QUEUED",
        requested_by=actor,
        allow_private=private,
        result_json="{}",
        error="",
        created_at=utcnow(),
    )
    s.add(ex)
    s.flush()
    audit.record(
        s,
        actor,
        "automated_vapt.queued",
        "automated_test_execution",
        ex.id,
        tenant_id=eng.tenant_id,
        engagement_id=eng.id,
        asset_id=asset.id,
        tests=ids,
    )
    return ex


def run_execution(
    s: Session,
    execution_id: int,
    *,
    actor: str,
    principal=None,
    extra: dict[str, Any] | None = None,
) -> AutomatedTestExecution:
    """Run a queued execution: scope re-check, then registered case handlers."""
    guard.require_feature_enabled()
    guard.require_write(principal)
    ex = get_execution(s, execution_id, principal=principal)
    if ex.status == "CANCELLED":
        raise ServiceError("execution was cancelled")
    if ex.status not in ("QUEUED",):
        raise ServiceError(f"execution status {ex.status} cannot be started")

    eng = guard.load_engagement(s, ex.engagement_id, principal)
    guard.assert_engagement_ready(eng)
    asset = guard.load_asset(s, eng, ex.asset_id) if ex.asset_id else None
    if asset is None:
        raise ServiceError("execution asset missing")

    exec_mgr.transition(ex, "RUNNING")
    s.flush()

    ctx = TestContext(
        engagement_id=eng.id,
        tenant_id=eng.tenant_id,
        asset_id=asset.id,
        target_base_url=ex.target_base_url,
        test_case_ids=list(ex.test_case_ids or []),
        profile=ex.profile,
        actor=actor,
        allow_private=bool(ex.allow_private),
        extra=dict(extra or {}),
    )

    try:
        seeds = [ln.strip() for ln in (asset.crawl_seed_urls or "").splitlines() if ln.strip()]
        scope = scope_validator.build_scope_from_asset(
            ex.target_base_url,
            extra_seeds=seeds,
            allow_private=ctx.allow_private,
        )
        scope_validator.validate_target_url(
            ex.target_base_url,
            scope,
            check_dns=not ctx.allow_private,
        )

        results: list[dict[str, Any]] = []
        for tid in ctx.test_case_ids:
            results.append(_run_case(tid, ctx))

        ex.result_json = json.dumps({"cases": results}, sort_keys=True)
        exec_mgr.transition(ex, "COMPLETED")
        audit.record(
            s,
            actor,
            "automated_vapt.completed",
            "automated_test_execution",
            ex.id,
            tenant_id=eng.tenant_id,
            engagement_id=eng.id,
            cases=len(results),
        )
    except ServiceError as exc:
        exec_mgr.transition(ex, "FAILED", error=str(exc))
        audit.record(
            s,
            actor,
            "automated_vapt.failed",
            "automated_test_execution",
            ex.id,
            tenant_id=eng.tenant_id,
            engagement_id=eng.id,
            error=str(exc)[:500],
        )
    except Exception as exc:  # noqa: BLE001 — record unexpected failures on the row
        exec_mgr.transition(ex, "FAILED", error=f"internal error: {exc}")
        audit.record(
            s,
            actor,
            "automated_vapt.failed",
            "automated_test_execution",
            ex.id,
            tenant_id=eng.tenant_id,
            engagement_id=eng.id,
            error=type(exc).__name__,
        )
    s.flush()
    return ex


def cancel_execution(s: Session, execution_id: int, *, actor: str, principal=None) -> AutomatedTestExecution:
    guard.require_feature_enabled()
    guard.require_write(principal)
    ex = get_execution(s, execution_id, principal=principal)
    if ex.status in ("COMPLETED", "FAILED", "CANCELLED"):
        raise ServiceError(f"execution already finished ({ex.status})")
    exec_mgr.transition(ex, "CANCELLED")
    audit.record(
        s,
        actor,
        "automated_vapt.cancelled",
        "automated_test_execution",
        ex.id,
        tenant_id=ex.tenant_id,
        engagement_id=ex.engagement_id,
    )
    s.flush()
    return ex


def get_execution(s: Session, execution_id: int, *, principal=None) -> AutomatedTestExecution:
    guard.require_feature_enabled()
    ex = s.get(AutomatedTestExecution, execution_id)
    if ex is None:
        raise ServiceError("execution not found")
    guard.load_engagement(s, ex.engagement_id, principal)
    return ex


def list_executions(
    s: Session,
    engagement_id: int,
    *,
    principal=None,
    limit: int = 50,
) -> list[AutomatedTestExecution]:
    guard.require_feature_enabled()
    guard.load_engagement(s, engagement_id, principal)
    q = (
        select(AutomatedTestExecution)
        .where(AutomatedTestExecution.engagement_id == engagement_id)
        .order_by(AutomatedTestExecution.id.desc())
        .limit(max(1, min(limit, 200)))
    )
    return list(s.scalars(q))


def execution_public_dict(ex: AutomatedTestExecution) -> dict[str, Any]:
    try:
        result = json.loads(ex.result_json or "{}")
    except json.JSONDecodeError:
        result = {}
    return {
        "id": ex.id,
        "engagement_id": ex.engagement_id,
        "tenant_id": ex.tenant_id,
        "asset_id": ex.asset_id,
        "target_base_url": ex.target_base_url,
        "profile": ex.profile,
        "test_case_ids": list(ex.test_case_ids or []),
        "status": ex.status,
        "requested_by": ex.requested_by,
        "allow_private": bool(ex.allow_private),
        "error": ex.error or "",
        "result": result,
        "created_at": ex.created_at.isoformat() if ex.created_at else None,
        "started_at": ex.started_at.isoformat() if ex.started_at else None,
        "ended_at": ex.ended_at.isoformat() if ex.ended_at else None,
    }


def _normalize_test_ids(test_case_ids: list[str]) -> list[str]:
    if not test_case_ids:
        raise ServiceError("at least one test case id is required")
    out: list[str] = []
    for raw in test_case_ids:
        tid = (raw or "").strip().upper()
        if not tid:
            continue
        if get_test_case(tid) is None:
            raise ServiceError(f"unknown test case id: {raw!r}")
        if tid not in out:
            out.append(tid)
    if not out:
        raise ServiceError("at least one test case id is required")
    return out


def _run_case(test_id: str, ctx: TestContext) -> dict[str, Any]:
    """Dispatch a single case. Implemented: SCOPE_SMOKE, T01; others deferred."""
    case = get_test_case(test_id)
    if case is None:
        return {"test_id": test_id, "status": "FAILED", "detail": "unknown test case"}
    if case.id == "SCOPE_SMOKE":
        return {
            "test_id": "SCOPE_SMOKE",
            "status": "PASSED",
            "detail": "engagement authorization and target scope validated",
            "target": ctx.target_base_url,
            "category": case.category,
        }
    if case.id == "T01":
        return _run_t01_http_capture(ctx, case.category)
    if case.id == "T02":
        return _run_t02_browser_capture(ctx, case.category)
    # Later Elite phases register real handlers; record deferred honestly.
    known = {c.id for c in list_test_cases()}
    if test_id in known or case.id in known:
        return {
            "test_id": case.id,
            "status": "DEFERRED",
            "detail": "handler not implemented in this Elite phase yet",
            "category": case.category,
        }
    return {"test_id": test_id, "status": "FAILED", "detail": "unknown test case"}


def _run_t01_http_capture(ctx: TestContext, category: str) -> dict[str, Any]:
    """T01: capture one GET against the approved target base URL."""
    from attestra.automated_vapt.capture.http_capture import capture_request
    from attestra.automated_vapt.capture.request_parser import parse_request
    from attestra.automated_vapt.capture.response_parser import parse_response

    seeds = []
    scope = scope_validator.build_scope_from_asset(
        ctx.target_base_url,
        extra_seeds=seeds,
        allow_private=ctx.allow_private,
    )
    client = ctx.extra.get("httpx_client")
    try:
        tx = capture_request(
            "GET",
            ctx.target_base_url,
            scope=scope,
            profile=ctx.profile,
            client=client,
            check_dns=not ctx.allow_private,
        )
    except Exception as exc:  # noqa: BLE001 — surface capture failures in case result
        return {
            "test_id": "T01",
            "status": "FAILED",
            "detail": f"HTTP capture failed: {exc}",
            "category": category,
        }
    req_n = parse_request(tx.report_pair or tx.pair.redacted())
    resp_n = parse_response(tx.report_pair or tx.pair.redacted())
    return {
        "test_id": "T01",
        "status": "PASSED",
        "detail": "HTTP transaction captured",
        "category": category,
        "capture": tx.to_dict(),
        "request_normalized": {k: v for k, v in req_n.items() if k != "original"},
        "response_normalized": resp_n,
    }


def _run_t02_browser_capture(ctx: TestContext, category: str) -> dict[str, Any]:
    """T02: capture a browser screenshot of the approved target."""
    from attestra.automated_vapt.capture.browser_capture import (
        capture_screenshot,
        stable_screenshot_name,
    )

    scope = scope_validator.build_scope_from_asset(
        ctx.target_base_url,
        allow_private=ctx.allow_private,
    )
    capture_fn = ctx.extra.get("browser_capture_fn")
    try:
        result = capture_screenshot(
            ctx.target_base_url,
            scope=scope,
            allow_private=ctx.allow_private,
            capture_fn=capture_fn,
            check_dns=not ctx.allow_private,
            username=ctx.extra.get("browser_username"),
            password=ctx.extra.get("browser_password"),
            login_url=ctx.extra.get("browser_login_url"),
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "test_id": "T02",
            "status": "FAILED",
            "detail": f"browser capture failed: {exc}",
            "category": category,
        }
    name = stable_screenshot_name(
        engagement_id=ctx.engagement_id,
        execution_id=int(ctx.extra.get("execution_id") or 0),
        test_case_id="T02",
        label="fullpage" if result.full_page else "viewport",
    )
    # Keep PNG out of result_json; record metadata only.
    ctx.extra.setdefault("_screenshots", {})[name] = result.screenshot_png
    return {
        "test_id": "T02",
        "status": "PASSED",
        "detail": "browser screenshot captured",
        "category": category,
        "screenshot": {**result.to_dict(), "filename": name},
    }
