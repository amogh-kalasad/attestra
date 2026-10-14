"""Dispatch gate: authorization, window, intrusive flag, rate limit, ownership, pin.

Phase 6.3: the allow/refuse decisions are made by the scope policy
(``policy/scope.rego``, see :mod:`attestra.runner.policy`). This module gathers
the facts, asks the policy, audits refusals, then authorizes and pins the
target (network IO stays in Python).
"""
# @lat: [[authorization#Runner scope]]

from __future__ import annotations

from datetime import date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from attestra import audit, config, services
from attestra.models import Asset, ScanRun, utcnow
from attestra.runner import policy
from attestra.runner.authorization import AuthorizationError, authorize_target, scope_for_engagement
from attestra.runner.dns_pin import PinnedTarget, pin_url
from attestra.runner.ownership import is_verified


class GateError(Exception):
    """Scan refused by the dispatch gate."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def policy_input(
    s: Session,
    engagement_id: int,
    asset_id: int,
    *,
    tool: str,
    profile: str,
    now: datetime | None = None,
) -> dict:
    """Collect the facts the scope policy needs (the OPA ``input`` document)."""
    now = now or utcnow()
    today = now.date() if isinstance(now, datetime) else date.today()
    eng = services.get_engagement(s, engagement_id)
    asset = s.get(Asset, asset_id)
    found = bool(asset and asset.engagement_id == engagement_id)

    count = 0
    if found:
        since = now - timedelta(hours=1) if isinstance(now, datetime) else utcnow() - timedelta(hours=1)
        count = s.scalar(
            select(func.count(ScanRun.id)).where(
                ScanRun.asset_id == asset_id,
                ScanRun.started_at.is_not(None),
                ScanRun.started_at >= since,
                ScanRun.status.not_in(["refused"]),
            )
        ) or 0

    return policy.build_input(
        asset_found=found,
        engagement_status=eng.status,
        asset_environment=asset.environment if found else "",
        authorized_environments=services.authorized_environments(eng, today),
        today=today,
        window_start=eng.window_start,
        window_end=eng.window_end,
        tool=tool,
        profile=profile,
        intrusive_allowed=bool(asset.intrusive_allowed) if found else False,
        recent_scan_count=count,
        rate_limit=config.SCAN_RATE_PER_ASSET,
        asset_kind=asset.kind if found else "",
        ownership_verified=is_verified(asset) if found else False,
    )


def check(
    s: Session,
    engagement_id: int,
    asset_id: int,
    *,
    tool: str,
    profile: str,
    actor: str,
    now: datetime | None = None,
) -> PinnedTarget | str:
    """Validate a scan request. Returns a PinnedTarget (URL tools) or path/image string."""
    now = now or utcnow()
    today = now.date() if isinstance(now, datetime) else date.today()

    # 1-5: policy decision (authorization env, window, intrusive, rate, ownership)
    decision = policy.decide(policy_input(s, engagement_id, asset_id, tool=tool, profile=profile, now=now))
    if not decision.allow:
        return _refuse(s, actor, asset_id, decision.reason or "refused by scope policy")

    asset = s.get(Asset, asset_id)

    # 6 authorize target + pin
    try:
        scope = scope_for_engagement(s, engagement_id, today)
    except AuthorizationError as exc:
        return _refuse(s, actor, asset_id, str(exc))

    kind = asset.kind
    target = asset.identifier
    try:
        if kind in ("web_app", "api"):
            authorize_target(scope, target, "url")
            return pin_url(target, scope)
        if kind == "repo":
            authorize_target(scope, target, "path")
            return target
        if kind == "image":
            authorize_target(scope, target, "image")
            return target
        if kind == "host":
            scheme = "https"
            url = f"{scheme}://{target}/"
            authorize_target(scope, url, "url")
            return pin_url(url, scope)
    except AuthorizationError as exc:
        return _refuse(s, actor, asset_id, str(exc))

    return _refuse(s, actor, asset_id, f"unsupported asset kind for scan: {kind}")


def _refuse(s: Session, actor: str, asset_id: int, reason: str):
    audit.record(s, actor, "scan.refused", "asset", asset_id, reason=reason)
    raise GateError(reason)
