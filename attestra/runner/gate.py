"""Dispatch gate: authorization, window, intrusive flag, rate limit, ownership, pin."""
# @lat: [[authorization#Runner scope]]

from __future__ import annotations

from datetime import date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from attestra import audit, config, services
from attestra.models import Asset, ScanRun, utcnow
from attestra.runner.authorization import AuthorizationError, authorize_target, scope_for_engagement
from attestra.runner.dns_pin import PinnedTarget, pin_url
from attestra.runner.ownership import is_verified
from attestra.runner.scanners.nuclei_policy import is_active_profile


class GateError(Exception):
    """Scan refused by the dispatch gate."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


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
    eng = services.get_engagement(s, engagement_id)
    asset = s.get(Asset, asset_id)
    if not asset or asset.engagement_id != engagement_id:
        return _refuse(s, actor, asset_id, "asset not found for engagement")

    if eng.status == "halted":
        return _refuse(s, actor, asset_id, "engagement is halted")

    # 1 valid authorization covering the asset environment
    envs = services.authorized_environments(eng, today)
    if asset.environment not in envs:
        return _refuse(s, actor, asset_id, "no valid authorization for asset environment")

    # 2 test window
    if eng.window_start and today < eng.window_start:
        return _refuse(s, actor, asset_id, "before engagement window")
    if eng.window_end and today > eng.window_end:
        return _refuse(s, actor, asset_id, "after engagement window")

    # 3 intrusive / active profile
    if (profile == "active" or (tool == "nuclei" and is_active_profile(profile))) and not asset.intrusive_allowed:
        return _refuse(s, actor, asset_id, "intrusive/active profile not allowed on asset")

    # 4 rate limit
    since = now - timedelta(hours=1) if isinstance(now, datetime) else utcnow() - timedelta(hours=1)
    count = s.scalar(
        select(func.count(ScanRun.id)).where(
            ScanRun.asset_id == asset_id,
            ScanRun.started_at.is_not(None),
            ScanRun.started_at >= since,
            ScanRun.status.not_in(["refused"]),
        )
    ) or 0
    if count >= config.SCAN_RATE_PER_ASSET:
        return _refuse(s, actor, asset_id, "scan rate limit exceeded for asset")

    # 5 ownership (first scan)
    if not is_verified(asset) and asset.kind in ("web_app", "api", "host"):
        return _refuse(s, actor, asset_id, "asset ownership not verified")

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
