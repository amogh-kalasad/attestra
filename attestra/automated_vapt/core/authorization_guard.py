"""Engagement authorization and feature-flag gates for Elite test runs."""

from __future__ import annotations

from datetime import date

from sqlalchemy.orm import Session

from attestra import config
from attestra.auth.roles import has_permission
from attestra.models import Asset, Engagement
from attestra.services import ServiceError, assert_engagement_access, get_engagement

# @lat: [[architecture#Elite automated security testing#Authorization guard]]
# @lat: [[run-validity-and-policy#Engagement readiness]]


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


# FND-07: statuses that allow automated testing. Anything else (halted, closed,
# archived, cancelled, unknown) is refused: when unsure, refuse.
_READY_STATUSES = frozenset({"active", "open", ""})

# Value-free reason codes for NOT_TESTED cases (PHASE2 §7).
REASON_HALTED = "halted"
REASON_STATUS = "engagement_not_active"
REASON_AUTH_EXPIRED = "authorization_expired"
REASON_ENV = "env_not_authorized"
REASON_WINDOW = "outside_window"
REASON_OWNERSHIP = "ownership_not_verified"
REASON_POLICY = "policy_denied"


class ReadinessError(ServiceError):
    """Engagement is not ready for (further) automated testing. ``code`` is value-free."""

    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


def readiness_problems(eng: Engagement, asset: Asset | None = None, *, today: date | None = None) -> list[tuple[str, str]]:
    """Pure readiness check mirroring ``runner/policy.py`` (no DB). Returns ``[(code, message)]``."""
    on = today or date.today()
    out: list[tuple[str, str]] = []
    status = (eng.status or "").strip().lower()
    if status == "halted":
        out.append((REASON_HALTED, "engagement is halted"))
    elif status not in _READY_STATUSES:
        out.append((REASON_STATUS, f"engagement status {eng.status!r} does not allow testing"))
    if config.signed_authorization_required():
        valid = [a for a in (eng.authorizations or []) if a.is_valid(on)]
        if not valid:
            out.append((REASON_AUTH_EXPIRED, "record a currently valid signed authorization before running tests"))
        elif asset is not None:
            env = (getattr(asset, "environment", "") or "").strip()
            if not any(a.covers(env) for a in valid):
                out.append((REASON_ENV, f"no valid signed authorization covers the asset environment {env!r}"))
    if eng.window_start and on < eng.window_start:
        out.append((REASON_WINDOW, "testing window has not started"))
    if eng.window_end and on > eng.window_end:
        out.append((REASON_WINDOW, "testing window has ended"))
    return out


def assert_engagement_ready(eng: Engagement, asset: Asset | None = None, *, today: date | None = None) -> None:
    """Refuse halted / non-active engagements, missing or non-covering authorization, and windows.

    ``asset`` is optional for backward compatibility; when given, the signed
    authorization must cover ``asset.environment`` (same rule as the scope policy).
    """
    problems = readiness_problems(eng, asset, today=today)
    if problems:
        code, msg = problems[0]
        raise ReadinessError(msg, code)


def assert_engagement_ready_for_case(
    s: Session | None,
    eng: Engagement,
    asset: Asset | None,
    *,
    today: date | None = None,
    policy_check: bool = True,
) -> None:
    """Pre-case re-check (FND-07): call before every automated case.

    Reloads the engagement so a halt or authorization change made mid-run is seen,
    re-runs :func:`readiness_problems`, then (with a session) asks the scope policy the
    same question ``runner/gate.py`` asks, ignoring only the per-hour scan rate limit
    (automated cases are not ScanRuns). Raises :class:`ReadinessError`.
    """
    if s is not None:
        try:
            s.refresh(eng)
        except Exception:  # noqa: BLE001 - stores without refresh keep the loaded row
            pass
    assert_engagement_ready(eng, asset, today=today)
    if not (policy_check and s is not None and asset is not None):
        return
    try:
        from attestra.runner import gate, policy

        inp = gate.policy_input(s, eng.id, asset.id, tool="zap", profile="baseline")
        inp["recent_scan_count"] = 0  # rate limit applies to scanner dispatch, not per case
        decision = policy.decide(inp)
    except Exception as exc:  # noqa: BLE001 - fail closed, value-free
        raise ReadinessError(f"scope policy unavailable ({type(exc).__name__})", REASON_POLICY) from exc
    if not decision.allow:
        reason = decision.reason or "refused by scope policy"
        code = {
            "engagement is halted": REASON_HALTED,
            "no valid authorization for asset environment": REASON_ENV,
            "before engagement window": REASON_WINDOW,
            "after engagement window": REASON_WINDOW,
            "asset ownership not verified": REASON_OWNERSHIP,
        }.get(reason, REASON_POLICY)
        raise ReadinessError(reason, code)


def not_tested_reason(exc: BaseException) -> str:
    """Value-free NOT_TESTED reason for a readiness failure."""
    return getattr(exc, "code", "") or REASON_POLICY


def load_asset(s: Session, eng: Engagement, asset_id: int) -> Asset:
    asset = s.get(Asset, asset_id)
    if asset is None or asset.engagement_id != eng.id:
        raise ServiceError("asset not found on this engagement")
    return asset
