"""Main Elite automated security-testing execution controller."""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from attestra import audit
from attestra.automated_vapt.core import authorization_guard as guard
from attestra.automated_vapt.core import execution_manager as exec_mgr
from attestra.automated_vapt.core import scope_validator
from attestra.automated_vapt.core.test_context import TestContext
from attestra.automated_vapt.core.test_registry import get_test_case, list_test_cases
from attestra.models import AutomatedTestExecution, utcnow
from attestra.services import ServiceError

log = logging.getLogger(__name__)

# Desktop Chrome UA so WAF/CDN bot checks (e.g. Cloudflare) are less likely
# to 403 the shared HTTP client used by T01 and the authz modules.
_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
_DEFAULT_HTTPX_TIMEOUT_S = 15.0
_DEFAULT_HTTPX_HEADERS = {
    "User-Agent": _CHROME_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def _ensure_httpx_client(ctx: TestContext) -> bool:
    """Attach a shared httpx.Client when the caller did not inject one.

    Unit tests pass FastAPI TestClient (or httpx.Client) via extra["httpx_client"];
    those are left untouched and must not be closed here.
    """
    if ctx.extra.get("httpx_client") is not None:
        return False
    import httpx

    client = httpx.Client(
        timeout=_DEFAULT_HTTPX_TIMEOUT_S,
        follow_redirects=True,
        headers=dict(_DEFAULT_HTTPX_HEADERS),
    )
    ctx.extra["httpx_client"] = client
    ctx.extra["_httpx_client_owned"] = True
    return True


def _close_owned_httpx_client(ctx: TestContext) -> None:
    """Close a client created by ``_ensure_httpx_client``; never close a caller-supplied one."""
    owned = bool(ctx.extra.pop("_httpx_client_owned", False))
    if not owned:
        return
    client = ctx.extra.pop("httpx_client", None)
    if client is None:
        return
    close = getattr(client, "close", None)
    if callable(close):
        try:
            close()
        except Exception:  # noqa: BLE001 - never fail the run during cleanup
            log.debug("owned httpx_client close failed", exc_info=True)


# @lat: [[architecture#Elite automated security testing]]
# @lat: [[architecture#Elite automated security testing#Orchestrator]]



def claim_queued_execution(s: Session, worker_id: str = "") -> AutomatedTestExecution | None:
    """Atomically claim the next QUEUED automated execution (worker path).

    Conditional UPDATE on status=QUEUED is the lock (same pattern as claim_job).
    Returns the RUNNING row, or None when the queue is empty.
    """
    from attestra.models import AutomatedTestExecution

    q = (
        select(AutomatedTestExecution)
        .where(AutomatedTestExecution.status == "QUEUED")
        .order_by(AutomatedTestExecution.id)
        .limit(5)
    )
    for ex in s.scalars(q).all():
        result = s.execute(
            update(AutomatedTestExecution)
            .where(
                AutomatedTestExecution.id == ex.id,
                AutomatedTestExecution.status == "QUEUED",
            )
            .values(status="RUNNING", started_at=utcnow(), error="")
            .execution_options(synchronize_session=False)
        )
        if result.rowcount == 1:
            s.refresh(ex)
            audit.record(
                s,
                worker_id or "worker",
                "automated_vapt.claimed",
                "automated_test_execution",
                ex.id,
                tenant_id=ex.tenant_id,
                engagement_id=ex.engagement_id,
                worker_id=worker_id or "",
            )
            return ex
    return None


def recover_stale_executions(s: Session, *, stale_s: int | None = None) -> int:
    """Re-queue RUNNING automated executions whose started_at is older than stale_s.

    Automated runs have no Job heartbeat; a dead worker would leave them RUNNING forever.
    """
    from datetime import timedelta

    from attestra import config
    from attestra.models import AutomatedTestExecution

    seconds = int(
        stale_s
        if stale_s is not None
        else getattr(config, "AUTOMATED_VAPT_STALE_S", 1800)  # 30m; T01?T22 often exceed Job heartbeat (120s)
    )
    cutoff = utcnow() - timedelta(seconds=max(30, seconds))
    rows = list(
        s.scalars(
            select(AutomatedTestExecution).where(
                AutomatedTestExecution.status == "RUNNING",
                AutomatedTestExecution.started_at.is_not(None),
                AutomatedTestExecution.started_at < cutoff,
            )
        ).all()
    )
    n = 0
    for ex in rows:
        result = s.execute(
            update(AutomatedTestExecution)
            .where(
                AutomatedTestExecution.id == ex.id,
                AutomatedTestExecution.status == "RUNNING",
            )
            .values(
                status="QUEUED",
                started_at=None,
                ended_at=None,
                error="re-queued after stale worker heartbeat",
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount == 1:
            n += 1
            audit.record(
                s,
                "system",
                "automated_vapt.requeued_stale",
                "automated_test_execution",
                ex.id,
                tenant_id=ex.tenant_id,
                engagement_id=ex.engagement_id,
            )
    return n


def _parse_optional_profile_id(value: Any, *, field: str) -> int | None:
    """Accept an int, numeric string, or blank; reject other values."""
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
    try:
        pid = int(value)
    except (TypeError, ValueError):
        raise ServiceError(f"{field} must be a profile id") from None
    if pid <= 0:
        raise ServiceError(f"{field} must be a profile id")
    return pid


def _load_engagement_auth_profile(
    s: Session,
    *,
    engagement_id: int,
    tenant_id: int,
    asset_id: int,
    profile_id: int,
    field: str,
):
    """Ensure the profile belongs to this engagement and (if bound) this target."""
    from attestra.models import AuthCredentialProfile

    row = s.get(AuthCredentialProfile, profile_id)
    if row is None or row.engagement_id != engagement_id or row.tenant_id != tenant_id:
        raise ServiceError(f"{field} not found for this engagement")
    if (row.status or "") == "revoked":
        raise ServiceError(f"{field} is revoked; choose another or re-validate it")
    if row.asset_id is not None and int(row.asset_id) != int(asset_id):
        raise ServiceError(f"{field} is not for this target")
    return row


def _auth_ids_from_execution(ex: AutomatedTestExecution) -> dict[str, int]:
    """Queued primary/secondary profile ids stored in result_json until the run starts."""
    try:
        stored = json.loads(ex.result_json or "{}")
    except json.JSONDecodeError:
        return {}
    if not isinstance(stored, dict):
        return {}
    out: dict[str, int] = {}
    for key in ("auth_profile_id", "secondary_auth_profile_id", "auth_profile_id_secondary"):
        raw = stored.get(key)
        if raw in (None, "", 0):
            continue
        try:
            out[key] = int(raw)
        except (TypeError, ValueError):
            continue
    return out


def _hydrate_auth_profile_ids(ctx: TestContext, ex: AutomatedTestExecution) -> dict[str, int]:
    """Copy stored profile ids into ctx.extra without overriding an explicit extra value."""
    stored = _auth_ids_from_execution(ex)
    for key, val in stored.items():
        ctx.extra.setdefault(key, val)
    return stored


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
    auth_profile_id: int | str | None = None,
    secondary_auth_profile_id: int | str | None = None,
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

    primary_pid = _parse_optional_profile_id(auth_profile_id, field="auth profile")
    secondary_pid = _parse_optional_profile_id(
        secondary_auth_profile_id, field="secondary auth profile"
    )
    if primary_pid is not None:
        _load_engagement_auth_profile(
            s,
            engagement_id=eng.id,
            tenant_id=eng.tenant_id,
            asset_id=asset.id,
            profile_id=primary_pid,
            field="auth profile",
        )
    if secondary_pid is not None:
        _load_engagement_auth_profile(
            s,
            engagement_id=eng.id,
            tenant_id=eng.tenant_id,
            asset_id=asset.id,
            profile_id=secondary_pid,
            field="secondary auth profile",
        )
    if primary_pid is not None and secondary_pid is not None and primary_pid == secondary_pid:
        raise ServiceError("secondary auth profile must be different from the primary profile")
    request_auth: dict[str, int] = {}
    if primary_pid is not None:
        request_auth["auth_profile_id"] = primary_pid
    if secondary_pid is not None:
        request_auth["secondary_auth_profile_id"] = secondary_pid

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
        result_json=json.dumps(request_auth, sort_keys=True) if request_auth else "{}",
        error="",
        created_at=utcnow(),
    )
    s.add(ex)
    s.flush()
    # E13: one credit per authorized Elite test run (not per HTTP/screenshot).
    from attestra.automated_vapt.integrations.subscription_adapter import ensure_credit_for_execution

    ensure_credit_for_execution(
        s,
        tenant_id=eng.tenant_id,
        engagement_id=eng.id,
        execution_id=ex.id,
        actor=actor,
        user_id=getattr(principal, "user_id", None) if principal is not None else None,
    )
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
    already_running: bool = False,
) -> AutomatedTestExecution:
    """Run a queued execution: scope re-check, then registered case handlers.

    When ``already_running`` is True the row was atomically claimed by the worker
    (status already RUNNING); do not transition again.
    """
    guard.require_feature_enabled()
    guard.require_write(principal)
    ex = get_execution(s, execution_id, principal=principal)
    if ex.status == "CANCELLED":
        raise ServiceError("execution was cancelled")
    if already_running:
        if ex.status != "RUNNING":
            raise ServiceError(f"execution status {ex.status} is not RUNNING for claimed run")
    elif ex.status not in ("QUEUED",):
        raise ServiceError(f"execution status {ex.status} cannot be started")

    eng = guard.load_engagement(s, ex.engagement_id, principal)
    guard.assert_engagement_ready(eng)
    asset = guard.load_asset(s, eng, ex.asset_id) if ex.asset_id else None
    if asset is None:
        raise ServiceError("execution asset missing")

    if not already_running:
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

    queued_auth = _hydrate_auth_profile_ids(ctx, ex)
    _ensure_httpx_client(ctx)
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

        # Real run id so screenshot names and the evidence folder match this row.
        ctx.extra.setdefault("execution_id", ex.id)
        # Same page list Nuclei uses: base URL + Extra Start URLs + latest ZAP pages.
        from attestra.automated_vapt.core.capture_urls import build_capture_urls

        capture_info: dict[str, Any] = {}
        capture_urls, capture_source = build_capture_urls(
            session=s,
            asset=asset,
            target_base_url=ex.target_base_url,
            scope=scope,
            info=capture_info,
            check_dns=not ctx.allow_private,
        )
        ctx.extra["_capture_urls"] = capture_urls or [ex.target_base_url]
        ctx.extra["_capture_url_source"] = capture_source
        ctx.extra["_capture_api_urls"] = list(capture_info.get("api_urls") or [])
        ctx.extra["_js_api"] = capture_info.get("js_api")
        # Engagement login profile (header + extra headers + extra cookies):
        # explicit extra["auth_profile_id"], else the profile of the reused ZAP scan.
        # Loaded for capture, replay, and authz modules so they do not use lab accounts.
        if any(t in ctx.test_case_ids for t in _SESSION_AUTH_CASES) and "_session_auth" not in ctx.extra:
            from attestra.automated_vapt.core.session_auth import load_session_auth

            pid = ctx.extra.get("auth_profile_id")
            if not pid and capture_info.get("zap_scan_id"):
                from attestra.models import ScanRun

                zr = s.get(ScanRun, capture_info["zap_scan_id"])
                pid = getattr(zr, "auth_profile_id", None) if zr is not None else None
            ctx.extra["_session_auth"] = load_session_auth(
                s,
                profile_id=pid,
                engagement_id=eng.id,
                target_url=ex.target_base_url,
            )
            # Optional second (non-admin) profile for confident IDOR / body-mutation probes.
            sec_pid = ctx.extra.get("secondary_auth_profile_id") or ctx.extra.get("auth_profile_id_secondary")
            if sec_pid and "_secondary_session_auth" not in ctx.extra:
                ctx.extra["_secondary_session_auth"] = load_session_auth(
                    s,
                    profile_id=int(sec_pid),
                    engagement_id=eng.id,
                    target_url=ex.target_base_url,
                )
        # Relative API paths (JS discovery / T19-T22) go to the asset's API Base URL, else the
        # login profile's same-site refresh URL origin, else the target. Pages stay on the target.
        try:
            from attestra.automated_vapt.core import api_base as _api_base

            _api_base.apply_to_ctx(ctx, asset=asset)
        except Exception as exc:  # noqa: BLE001 - never fail the run on base resolution
            ctx.extra["_api_base"] = {"url": ex.target_base_url, "source": "target", "error": type(exc).__name__}
        results: list[dict[str, Any]] = []
        coverage_ledger: list[dict[str, Any]] = []
        from attestra.automated_vapt.coverage.ledger import (
            entries_from_case_result,
            merge_ledger,
        )

        for tid in ctx.test_case_ids:
            pairs_before = len(ctx.extra.get("_http_pairs") or [])
            shots_before = set((ctx.extra.get("_screenshots") or {}).keys())
            # Mid-scan auth guard: re-verify the login before session-dependent cases; on
            # unrecoverable loss the case is BLOCKED with a reason (never run as "passed").
            blocked = _ensure_session_for_case(tid, ctx)
            case_result = blocked if blocked is not None else _run_case(tid, ctx)
            if ctx.extra.get("_auth_events"):
                case_result.setdefault("auth_events", list(ctx.extra["_auth_events"]))
            # Always keep proof of testing on disk, even when no finding is created.
            _persist_run_evidence(ex.id, case_result, ctx, pairs_before, shots_before)
            # Meta cases T08-T14 read earlier results + captures from ctx.extra.
            ctx.extra.setdefault("_case_results", []).append(case_result)
            # E11: map CONFIRMED/POTENTIAL validation onto findings.
            validation = case_result.get("validation") or {}
            if (validation.get("status") or "").upper() in ("CONFIRMED", "POTENTIAL"):
                from attestra.automated_vapt.integrations.attestra_findings import (
                    create_finding_from_validation,
                    document_finding_evidence,
                )

                ftitle = case_result.get("finding_title") or (
                    f"Automated test {case_result.get('test_id')}: "
                    f"{(validation.get('title_suffix') or 'authorization issue')}"
                )
                finding = create_finding_from_validation(
                    s,
                    engagement_id=eng.id,
                    asset_id=asset.id,
                    title=str(ftitle)[:500],
                    description=str(case_result.get("detail") or "Automated test finding"),
                    validation=validation,
                    cwe=case_result.get("finding_cwe") or validation.get("cwe") or 639,
                    location=str(case_result.get("finding_location") or ex.target_base_url)[:1000],
                    actor=actor,
                    recommendation=str(
                        case_result.get("finding_recommendation")
                        or validation.get("recommendation")
                        or "Enforce object-level authorization and retest."
                    ),
                    false_positive=case_result.get("false_positive") or {},
                )
                if finding is not None:
                    case_result["finding_id"] = finding.id
                    # Document captures as finding evidence so HTML/PDF reports embed them.
                    pairs = _evidence_pairs_for_case(case_result, ctx)
                    shots = _evidence_screenshots_for_case(case_result, ctx)
                    case_result["evidence"] = document_finding_evidence(
                        s,
                        finding.id,
                        actor=actor,
                        http_pairs=pairs,
                        screenshots=shots,
                    )
            # Phase 4 ledger: extract while evidence_pairs still present, then strip.
            auth_ctx = None
            sess = ctx.extra.get("_session_auth")
            if sess is not None and hasattr(sess, "public"):
                auth_ctx = sess.public()
            elif isinstance(case_result.get("auth"), dict):
                auth_ctx = case_result.get("auth")
            coverage_ledger = merge_ledger(
                coverage_ledger,
                entries_from_case_result(
                    case_result,
                    engagement_id=eng.id,
                    execution_id=ex.id,
                    asset_id=asset.id if asset is not None else ex.asset_id,
                    auth_context=auth_ctx,
                    executed_at=utcnow(),
                ),
            )
            # HttpPair objects are not JSON-serializable; strip before persist.
            case_result.pop("evidence_pairs", None)
            case_result.pop("finding_evidence_pairs", None)
            results.append(case_result)
            # Persist cases + ledger after each case so FAILED mid-run still retains rows.
            mid: dict[str, Any] = {"cases": results, "coverage_ledger": coverage_ledger}
            mid.update(queued_auth)
            ex.result_json = json.dumps(mid, sort_keys=True)
            s.flush()

        sess_final = ctx.extra.pop("_session_auth", None)  # in-memory only; never persisted
        ctx.extra.pop("_secondary_session_auth", None)
        summary: dict[str, Any] = {"cases": results, "coverage_ledger": coverage_ledger}
        summary.update(queued_auth)
        if sess_final is not None and hasattr(sess_final, "public"):
            summary["auth"] = sess_final.public()
            if ctx.extra.get("_auth_events"):
                summary["auth"]["events"] = list(ctx.extra["_auth_events"])[-20:]
        ex.result_json = json.dumps(summary, sort_keys=True)
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
        # Automatic WSTG/ASVS checklist status from this run (savepoint; never fails the run).
        from attestra.auth_web import checklist_auto

        checklist_auto.apply_automated_run_safely(s, ex)
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
    finally:
        _close_owned_httpx_client(ctx)
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


# Cases that should load the engagement login profile (if not already injected).
_SESSION_AUTH_CASES = frozenset({
    "T01", "T02", "T03", "T04", "T05", "T06", "T07",
    "T19", "T20", "T21", "T22",
    "SESSION", "INJ", "XSS", "XSSDOM", "XSSSTORE", "FILE",
    "BIZ", "ROLEDIFF", "SSRF", "UPLOAD",
})

# Mid-scan liveness checks before these cases run (no-op when no ready session).
_SESSION_DEPENDENT = frozenset({
    "T03", "T04", "T05", "T06", "T07",
    "T19", "T20", "T21", "T22",
    "SESSION", "INJ", "XSS", "XSSDOM", "XSSSTORE", "FILE",
    "BIZ", "ROLEDIFF", "SSRF", "UPLOAD",
})


def _record_auth_event(ctx: TestContext, kind: str, note: str, *, test_id: str = "") -> None:
    events = ctx.extra.setdefault("_auth_events", [])
    events.append({"at": utcnow().isoformat(), "test_id": test_id, "kind": kind, "note": str(note)[:300]})
    del events[:-30]


def _ensure_session_for_case(test_id: str, ctx: TestContext) -> dict[str, Any] | None:
    """Before a session-dependent case, confirm the login is alive (re-login once dead).

    Returns a BLOCKED case result when the session was lost and could not be recovered,
    else ``None`` (run the case). No-op without a ready session / guard or when
    ``ATTESTRA_AUTH_MIDSCAN_ENABLED=0``.
    """
    if test_id not in _SESSION_DEPENDENT:
        return None
    auth = ctx.extra.get("_session_auth")
    if auth is None or not hasattr(auth, "ensure_alive"):
        return None
    if getattr(auth, "status", "") == "lost":
        reason = getattr(auth, "note", "") or "session lost earlier in this run"
        return _blocked_case(test_id, reason, auth)
    if getattr(auth, "status", "") != "ready":
        return None
    relogins_before = getattr(getattr(auth, "guard", None), "relogins", 0)
    ok, note = auth.ensure_alive()
    if ok:
        if getattr(getattr(auth, "guard", None), "relogins", 0) > relogins_before:
            _record_auth_event(ctx, "relogin_ok", note, test_id=test_id)
        return None
    _record_auth_event(ctx, "lost", note, test_id=test_id)
    return _blocked_case(test_id, note, auth)


def _blocked_case(test_id: str, reason: str, auth: Any) -> dict[str, Any]:
    from attestra.auth_web.session_guard import SKIP_REASON_AUTH_LOST

    case = get_test_case(test_id)
    return {
        "test_id": test_id,
        "status": "BLOCKED",
        "detail": f"blocked: authenticated session lost mid-run and re-login failed ({reason})"[:400],
        "skip_reason": SKIP_REASON_AUTH_LOST,
        "category": getattr(case, "category", "") if case is not None else "",
        "auth": auth.public() if hasattr(auth, "public") else {"status": "lost"},
        "endpoints": [],
        "validation": {},
    }


def _run_case(test_id: str, ctx: TestContext) -> dict[str, Any]:
    """Dispatch a single case. Meta cases T08-T14 live in meta_handlers."""
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
    if case.id in {
        "T03", "T04", "T05", "T06", "T07", "SESSION", "INJ", "XSS", "XSSDOM", "XSSSTORE", "FILE",
        "BIZ", "ROLEDIFF", "SSRF", "UPLOAD",
    }:
        return _run_authz_module(case.id, ctx, case.category)
    if case.id in {"T19", "T20", "T21", "T22"}:
        return _run_replay_check(case.id, ctx, case.category)
    if case.id in {"T08", "T09", "T10", "T11", "T12", "T13", "T14"}:
        from attestra.automated_vapt.core.meta_handlers import run_meta_case

        return run_meta_case(case.id, ctx, case.category)
    # Later Elite phases register real handlers; record deferred honestly.
    known = {c.id for c in list_test_cases()}
    if test_id in known or case.id in known:
        return {
            "test_id": case.id,
            "status": "DEFERRED",
            "detail": "handler not implemented yet",
            "category": case.category,
        }
    return {"test_id": test_id, "status": "FAILED", "detail": "unknown test case"}


def _persist_run_evidence(
    execution_id: int,
    case_result: dict[str, Any],
    ctx: TestContext,
    pairs_before: int,
    shots_before: set[str],
) -> None:
    """Save this case's screenshots and HTTP visuals under DATA_DIR/raw/automated-<id>/.

    All captures stay on disk for the engagement gallery. ``report_evidence_files`` lists
    only the failing-endpoint subset (empty when the case passed) so the technical report
    does not embed every screenshot.
    """
    try:
        from attestra.automated_vapt.evidence.run_evidence import persist_case_evidence

        # Prefer the case's own evidence_pairs. Fall back to the slice of _http_pairs added
        # during this case when the handler did not populate evidence_pairs (T01/T02).
        own = list(case_result.get("evidence_pairs") or [])
        if own:
            pairs = own
        else:
            pairs = list((ctx.extra.get("_http_pairs") or [])[pairs_before:])
        pending: dict[str, bytes] = ctx.extra.get("_screenshots") or {}
        shots = [(name, png) for name, png in pending.items() if name not in shots_before]
        files = persist_case_evidence(
            execution_id,
            str(case_result.get("test_id") or "case"),
            http_pairs=pairs,
            screenshots=shots,
        )
        if files:
            case_result["evidence_files"] = files

        # Report subset: finding pairs only (same object identity when possible).
        find_pairs = list(case_result.get("finding_evidence_pairs") or [])
        status_u = (case_result.get("status") or "").upper()
        if not find_pairs and status_u in {"FINDING", "FAILED", "CONFIRMED", "VULNERABLE"}:
            # Whole-case failure with no per-endpoint split (e.g. T01 FAILED).
            find_pairs = pairs
        if find_pairs:
            # Persist under a distinct stem so filenames are stable and easy to filter;
            # originals in evidence_files remain for the UI gallery.
            report_files = persist_case_evidence(
                execution_id,
                f"{case_result.get('test_id') or 'case'}_fail",
                http_pairs=find_pairs,
                screenshots=[],
            )
            case_result["report_evidence_files"] = report_files
        else:
            case_result["report_evidence_files"] = []
    except Exception:  # noqa: BLE001 - evidence must never fail the run
        log.exception("saving run evidence failed for execution %s", execution_id)


def _evidence_pairs_for_case(case_result: dict[str, Any], ctx: TestContext) -> list[Any]:
    """Collect HttpPair (or dict) documents for finding evidence.

    Only the pairs that prove the finding (``finding_evidence_pairs``, else the case's
    own ``evidence_pairs``). Never dumps the whole run's ``_http_pairs`` — that used to
    attach every T01/T19/T20 capture onto a single T21 finding.
    """
    pairs: list[Any] = []
    for item in case_result.get("finding_evidence_pairs") or case_result.get("evidence_pairs") or []:
        pairs.append(item)
    capture = case_result.get("capture")
    if isinstance(capture, dict) and capture.get("url"):
        # T01-style whole-case capture only when this case itself is the finding source.
        if (case_result.get("status") or "").upper() in {"FINDING", "FAILED", "CONFIRMED", "VULNERABLE"}:
            pairs.append(capture)
    return pairs


def _evidence_screenshots_for_case(
    case_result: dict[str, Any], ctx: TestContext
) -> list[tuple[str, bytes]]:
    """Collect PNG screenshots to embed in HTML/PDF via finding evidence."""
    shots: list[tuple[str, bytes]] = []
    pending: dict[str, bytes] = ctx.extra.get("_screenshots") or {}
    meta = case_result.get("screenshot") or {}
    name = meta.get("filename") if isinstance(meta, dict) else None
    if name and name in pending:
        shots.append((name, pending.pop(name)))
    # Remaining browser captures from T02 in this run also document the finding.
    for fname, png in list(pending.items()):
        shots.append((fname, png))
        pending.pop(fname, None)
    return shots


def _run_t01_http_capture(ctx: TestContext, category: str) -> dict[str, Any]:
    """T01: capture GET against each approved page (base + Extra Start + ZAP URLs)."""
    from attestra.automated_vapt.capture.http_capture import capture_request
    from attestra.automated_vapt.capture.request_parser import parse_request
    from attestra.automated_vapt.capture.response_parser import parse_response

    urls = list(ctx.extra.get("_capture_urls") or [ctx.target_base_url])
    source = str(ctx.extra.get("_capture_url_source") or "root-only")
    seeds = [u for u in urls[1:] if u]
    scope = scope_validator.build_scope_from_asset(
        ctx.target_base_url,
        extra_seeds=seeds,
        allow_private=ctx.allow_private,
    )
    client = ctx.extra.get("httpx_client")
    api_set = {u.rstrip("/") for u in ctx.extra.get("_capture_api_urls") or []}
    auth = ctx.extra.get("_session_auth")
    auth_info = auth.public() if auth is not None else {"profile_id": None, "status": "none", "note": "", "injected": []}
    pages: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    last_tx = None
    last_req: dict[str, Any] = {}
    last_resp: dict[str, Any] = {}
    auth_loss_note = ""
    for idx, url in enumerate(urls):
        if auth_loss_note:
            # Session died earlier in this loop and could not be recovered: the remaining
            # authenticated pages are blocked, not captured as if logged in.
            pages.append({"url": url, "status": "BLOCKED", "detail": auth_loss_note, "skip_reason": "auth_lost"})
            continue
        # GET only; session headers only for the target origin.
        headers = auth.headers_for(url, ctx.target_base_url) if auth is not None else {}
        try:
            tx = capture_request(
                "GET",
                url,
                scope=scope,
                profile=ctx.profile,
                headers=headers or None,
                client=client,
                check_dns=not ctx.allow_private,
            )
        except Exception as exc:  # noqa: BLE001 - surface capture failures in case result
            detail = str(exc)
            if auth is not None:
                detail = auth.scrub(detail)
            pages.append({"url": url, "status": "FAILED", "detail": detail})
            continue
        report = tx.report_pair or tx.pair.redacted()
        if auth is not None and auth.redact_values:
            report.response_body = auth.scrub(report.response_body)
            report.request_body = auth.scrub(report.request_body)
            report.request_headers = {k: auth.scrub(v) for k, v in report.request_headers.items()}
            report.response_headers = {k: auth.scrub(v) for k, v in report.response_headers.items()}
            tx.report_pair = report
        ctx.extra.setdefault("_http_pairs", []).append(report)
        # Shared inventory for T20/T22: harvest object ids from authenticated JSON bodies
        # and promote substantive API URLs onto `_capture_api_urls` when discovery missed them.
        try:
            from attestra.automated_vapt.core.replay_checks import record_harvest_into_ctx

            record_harvest_into_ctx(ctx, report.response_body or "", url=url)
        except Exception:  # noqa: BLE001 — harvest must never fail the capture case
            pass
        req_n = parse_request(report)
        resp_n = parse_response(report)
        last_tx, last_req, last_resp = tx, req_n, resp_n
        code = report.status
        status_counts[str(code)] = status_counts.get(str(code), 0) + 1
        page_row = {
            "url": url,
            "status": "PASSED",
            "detail": "HTTP transaction captured",
            "http_status": code,
            "kind": "api" if url.rstrip("/") in api_set or url.rstrip("/") in {
                u.rstrip("/") for u in (ctx.extra.get("_capture_api_urls") or [])
            } else "page",
            "authenticated": bool(headers),
        }
        pages.append(page_row)
        # Periodic mid-scan check: an authenticated page answering like a dead session
        # triggers verify → re-login; unrecovered loss blocks the rest of the list.
        if headers and auth is not None and hasattr(auth, "ensure_alive") and getattr(auth, "guard", None) is not None:
            from attestra.auth_web.session_guard import looks_expired

            hint, why = looks_expired(code, body=report.response_body or "", headers=dict(report.response_headers or {}), cfg=getattr(auth, "cfg", None))
            if hint:
                relogins_before = getattr(auth.guard, "relogins", 0)
                alive, note = auth.ensure_alive()
                if alive and getattr(auth.guard, "relogins", 0) > relogins_before:
                    page_row["detail"] = f"HTTP transaction captured; session re-established after: {why}"
                    _record_auth_event(ctx, "relogin_ok", note, test_id="T01")
                elif not alive:
                    auth_loss_note = f"blocked: authenticated session lost mid-run ({note})"[:300]
                    page_row["detail"] = f"captured, but session looked expired ({why}); {auth_loss_note}"
                    _record_auth_event(ctx, "lost", note, test_id="T01")
    ok = [p for p in pages if p["status"] == "PASSED"]
    if not ok:
        first = pages[0]["detail"] if pages else "no URLs"
        return {
            "test_id": "T01",
            "status": "FAILED",
            "detail": f"HTTP capture failed on {len(pages)} page(s) ({source}): {first}",
            "category": category,
            "pages": pages,
            "url_source": source,
            "auth": auth_info,
        }
    out: dict[str, Any] = {
        "test_id": "T01",
        "status": "PASSED",
        "detail": (
            f"HTTP captured for {len(ok)}/{len(pages)} page(s) ({source}); "
            f"HTTP {', '.join(f'{k}x{v}' for k, v in sorted(status_counts.items()))}; "
            f"auth: {auth_info['status']}"
            + (f" (profile #{auth_info['profile_id']})" if auth_info.get("profile_id") else "")
        ),
        "category": category,
        "pages": pages,
        "url_source": source,
        "status_counts": status_counts,
        "auth": auth.public() if auth is not None else auth_info,
        "js_api": ctx.extra.get("_js_api"),
        "api_base": ctx.extra.get("_api_base"),
    }
    if auth_loss_note:
        blocked_n = sum(1 for p in pages if p["status"] == "BLOCKED")
        out["auth_loss"] = auth_loss_note
        out["skip_reason"] = "auth_lost"
        out["detail"] += f"; {auth_loss_note}; {blocked_n} page(s) blocked"
    if last_tx is not None:
        out["capture"] = last_tx.to_dict()
        out["request_normalized"] = {k: v for k, v in last_req.items() if k != "original"}
        out["response_normalized"] = last_resp
    return out



def _run_t02_browser_capture(ctx: TestContext, category: str) -> dict[str, Any]:
    """T02: browser screenshot of each approved page (base + Extra Start + ZAP URLs)."""
    from attestra.automated_vapt.capture.browser_capture import (
        capture_screenshot,
        stable_screenshot_name,
    )
    from attestra.automated_vapt.core.capture_urls import page_label

    urls = list(ctx.extra.get("_capture_urls") or [ctx.target_base_url])
    api_set = {u.rstrip("/") for u in ctx.extra.get("_capture_api_urls") or []}
    urls = [u for u in urls if u.rstrip("/") not in api_set] or [ctx.target_base_url]
    source = str(ctx.extra.get("_capture_url_source") or "root-only")
    seeds = [u for u in urls[1:] if u]
    scope = scope_validator.build_scope_from_asset(
        ctx.target_base_url,
        extra_seeds=seeds,
        allow_private=ctx.allow_private,
    )
    capture_fn = ctx.extra.get("browser_capture_fn")
    pages: list[dict[str, Any]] = []
    last_shot: dict[str, Any] | None = None
    # Inject login-profile session headers so SPA XHR/fetch runs authenticated and
    # POST/PUT/PATCH JSON bodies can be observed for T22.
    extra_headers: dict[str, str] = {}
    auth = ctx.extra.get("_session_auth")
    if auth is not None and getattr(auth, "status", "") == "ready":
        try:
            extra_headers = auth.headers_for(ctx.target_base_url, ctx.target_base_url) or {}
        except Exception:  # noqa: BLE001
            extra_headers = {}
    write_bodies_all: list[dict[str, Any]] = list(ctx.extra.get("_write_captures") or [])
    for i, url in enumerate(urls, 1):
        try:
            result = capture_screenshot(
                url,
                scope=scope,
                allow_private=ctx.allow_private,
                capture_fn=capture_fn,
                check_dns=not ctx.allow_private,
                username=ctx.extra.get("browser_username"),
                password=ctx.extra.get("browser_password"),
                login_url=ctx.extra.get("browser_login_url"),
                extra_headers=extra_headers or None,
            )
        except Exception as exc:  # noqa: BLE001
            pages.append({"url": url, "status": "FAILED", "detail": str(exc)})
            continue
        name = stable_screenshot_name(
            engagement_id=ctx.engagement_id,
            execution_id=int(ctx.extra.get("execution_id") or 0),
            test_case_id="T02",
            label=page_label(i, url),
        )
        ctx.extra.setdefault("_screenshots", {})[name] = result.screenshot_png
        meta = {**result.to_dict(), "filename": name, "url": url}
        pages.append({"url": url, "status": "PASSED", "detail": "browser screenshot captured", "screenshot": meta})
        last_shot = meta
        for wb in getattr(result, "write_bodies", None) or []:
            write_bodies_all.append(wb)
    # Persist redacted write bodies for T22 (same run folder as screenshots).
    if write_bodies_all:
        try:
            from attestra.automated_vapt.capture import write_body_capture as wbc

            merged = wbc.merge_write_captures([], write_bodies_all)
            ctx.extra["_write_captures"] = merged
            xid = int(ctx.extra.get("execution_id") or 0)
            if xid:
                wbc.save_write_bodies(xid, merged)
        except Exception:  # noqa: BLE001
            log.exception("saving captured write bodies failed")
    ok = [p for p in pages if p["status"] == "PASSED"]
    if not ok:
        first = pages[0]["detail"] if pages else "no URLs"
        return {
            "test_id": "T02",
            "status": "FAILED",
            "detail": f"browser capture failed on {len(pages)} page(s) ({source}): {first}",
            "category": category,
            "pages": pages,
            "url_source": source,
        }
    captured = list(ctx.extra.get("_write_captures") or [])
    from attestra.automated_vapt.capture import write_body_capture as _wbc

    summary = _wbc.public_summary(captured)
    out: dict[str, Any] = {
        "test_id": "T02",
        "status": "PASSED",
        "detail": (
            f"browser screenshots for {len(ok)}/{len(pages)} page(s) ({source}); "
            f"write bodies captured: {len(captured)}"
        ),
        "category": category,
        "pages": pages,
        "url_source": source,
        "write_bodies_captured": len(captured),
        "write_bodies_summary": summary[:40],
    }
    if last_shot is not None:
        out["screenshot"] = last_shot
    return out



def _run_replay_check(test_id: str, ctx: TestContext, category: str) -> dict[str, Any]:
    """T19 auth bypass / T20 IDOR / T21 input validation / T22 body mutation."""
    from attestra.automated_vapt.core import body_mutation, replay_checks

    runners = {
        "T19": replay_checks.run_auth_bypass,
        "T20": replay_checks.run_idor,
        "T21": replay_checks.run_input_validation,
        "T22": body_mutation.run_object_mutation,
    }
    try:
        result = runners[test_id](ctx)
    except Exception as exc:  # noqa: BLE001
        return {
            "test_id": test_id,
            "status": "FAILED",
            "detail": f"module error: {type(exc).__name__}",
            "category": category,
        }
    result.setdefault("category", category)
    # Push redacted pairs onto the shared list so _persist_run_evidence picks them up too.
    for pair in result.get("evidence_pairs") or []:
        ctx.extra.setdefault("_http_pairs", []).append(pair)
    return result


def _run_authz_module(test_id: str, ctx: TestContext, category: str) -> dict[str, Any]:
    """Dispatch T03-T07 / SESSION / BIZ authz modules against an injected HTTP client."""
    client = ctx.extra.get("httpx_client")
    if client is None:
        return {
            "test_id": test_id,
            "status": "FAILED",
            "detail": "httpx_client required in execution extra for authz modules",
            "category": category,
        }
    from attestra.automated_vapt.testing import (
        api_security_tests,
        authentication_tests,
        authorization_tests,
        business_logic_tests,
        file_security_tests,
        file_upload_tests,
        idor_bola_tests,
        injection_tests,
        role_diff_tests,
        session_security_tests,
        ssrf_tests,
        tenant_isolation_tests,
        xss_tests,
    )

    runners = {
        "T03": authentication_tests.run,
        "T04": idor_bola_tests.run,
        "T05": authorization_tests.run,
        "T06": tenant_isolation_tests.run,
        "T07": api_security_tests.run,
        "SESSION": session_security_tests.run,
        "INJ": injection_tests.run,
        "XSS": xss_tests.run,
        "XSSDOM": lambda c, b, **kw: xss_tests.run(c, b, mode="dom", **kw),
        "XSSSTORE": lambda c, b, **kw: xss_tests.run(c, b, mode="stored", **kw),
        "FILE": file_security_tests.run,
        "BIZ": business_logic_tests.run,
        "ROLEDIFF": role_diff_tests.run,
        "SSRF": ssrf_tests.run,
        "UPLOAD": file_upload_tests.run,
    }
    try:
        result = runners[test_id](client, ctx.target_base_url, ctx=ctx)
    except Exception as exc:  # noqa: BLE001
        return {
            "test_id": test_id,
            "status": "FAILED",
            "detail": f"module error: {exc}",
            "category": category,
        }
    # finding_candidate True means vulnerability indicators were observed.
    from attestra.automated_vapt.validation.false_positive_checker import check_false_positive
    from attestra.automated_vapt.validation.vulnerability_validator import validate_result

    obs = result.get("observations") or {}
    protected = bool(obs.get("exposed_secrets") or obs.get("excessive_data_exposure"))
    bypass = bool(
        result.get("finding_candidate")
        and (
            obs.get("cross_tenant_access")
            or obs.get("settings_open_without_auth")
            or (obs.get("member_admin_status") == 200)
            or (obs.get("account_a_proj_b_status") == 200 and protected)
        )
    )
    evidence_pairs = result.get("evidence_pairs") or []
    vctx = {
        "executed": True,
        "in_scope": True,
        "auth_valid": True,
        "identity_ok": True,
        "expected_control_defined": True,
        "status_code": obs.get("account_a_proj_b_status")
        or obs.get("member_admin_status")
        or obs.get("settings_unauth_status")
        or obs.get("users_status"),
        "protected_data_exposed": protected,
        "authorization_bypass": bypass or bool(result.get("finding_candidate") and protected),
        # Do not hard-code evidence strength: require captured pairs for CONFIRMED path.
        "reproducible": bool(evidence_pairs) or bool(obs),
        "evidence_supports": bool(evidence_pairs) or bool(protected or bypass),
        "finding_candidate": bool(result.get("finding_candidate")),
        "authorized_access": bool(obs.get("authorized_ok") and obs.get("unauthorized_blocked")),
    }
    validation = validate_result(vctx)
    fp = check_false_positive(
        {
            "status_code": vctx.get("status_code"),
            "protected_data_exposed": protected,
            "authorization_bypass": vctx["authorization_bypass"],
            "authorized_access": vctx["authorized_access"],
        }
    )
    if result.get("status_hint") == "SKIPPED" or result.get("skip_reason"):
        status = "SKIPPED"
        detail = (result.get("observations") or {}).get("detail") or f"skipped: {result.get('skip_reason')}"
    else:
        status = "FINDING" if result.get("finding_candidate") else "PASSED"
        detail = "authz module completed"
    out: dict[str, Any] = {
        "test_id": test_id,
        "status": status,
        "detail": detail,
        "category": category,
        "module": {
            k: v
            for k, v in result.items()
            if k != "evidence_pairs"
        },
        "validation": validation if status != "SKIPPED" else {},
        "false_positive": fp if status != "SKIPPED" else {},
    }
    if result.get("skip_reason"):
        out["skip_reason"] = result["skip_reason"]
    if result.get("evidence_pairs"):
        out["evidence_pairs"] = list(result["evidence_pairs"])
    return out
