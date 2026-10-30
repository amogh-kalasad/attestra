"""Engagement authorization and feature-flag gates for Elite test runs."""

from __future__ import annotations

from datetime import date

from sqlalchemy.orm import Session

from attestra import config
from attestra.auth.roles import has_permission
from attestra.models import Asset, Engagement
from attestra.services import ServiceError, assert_engagement_access, get_engagement

# @lat: [[architecture#Elite automated security testing#Authorization guard]]


def require_feature_enabled() -> None:
    if not config.AUTOMATED_VAPT_ENABLED:
        raise ServiceError(
            "automated security testing is disabled (ATTESTRA_AUTOMATED_VAPT_ENABLED)"
        )


def require_write(principal) -> None:
    if principal is None:
        return
    role = getattr(principal, "role", None) or ""
    if not has_permission(role, "engagement.write"):
        raise ServiceError("not allowed to run automated security tests")


def load_engagement(s: Session, engagement_id: int, principal=None) -> Engagement:
    if principal is not None:
        return assert_engagement_access(s, engagement_id, principal)
    return get_engagement(s, engagement_id)


def assert_engagement_ready(eng: Engagement) -> None:
    if (eng.status or "").lower() not in ("active", "open", ""):
        # Treat missing/empty as active for older rows; refuse closed/archived.
        if (eng.status or "").lower() in ("closed", "archived", "cancelled"):
            raise ServiceError(f"engagement status {eng.status!r} does not allow testing")
    if not any(a.is_valid(date.today()) for a in eng.authorizations):
        raise ServiceError("record a currently valid signed authorization before running tests")
    if eng.window_start and date.today() < eng.window_start:
        raise ServiceError("testing window has not started")
    if eng.window_end and date.today() > eng.window_end:
        raise ServiceError("testing window has ended")


def load_asset(s: Session, eng: Engagement, asset_id: int) -> Asset:
    asset = s.get(Asset, asset_id)
    if asset is None or asset.engagement_id != eng.id:
        raise ServiceError("asset not found on this engagement")
    return asset
