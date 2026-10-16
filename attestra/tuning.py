"""Phase 7.4 tuning: per-tenant risk weights, suppression rules, false-positive rates.

Every change is written to the audit log. Suppression rules must expire; an
expired or revoked rule stops matching on the next import.
"""
# @lat: [[findings#Risk score]]

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from attestra import audit, scoring
from attestra.importers.base import NormalizedFinding
from attestra.models import Engagement, Finding, SuppressionRule, TenantRiskWeights, utcnow

MAX_SUPPRESSION_DAYS = 365
_WEIGHT_MIN, _WEIGHT_MAX = 0.1, 5.0


class TuningError(ValueError):
    pass


def _check_weight(name: str, value: float) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        raise TuningError(f"{name} must be a number") from None
    if not _WEIGHT_MIN <= v <= _WEIGHT_MAX:
        raise TuningError(f"{name} must be between {_WEIGHT_MIN} and {_WEIGHT_MAX}")
    return v


# ---------------------------------------------------------------- risk weights


def get_weights(s: Session, tenant_id: int | None) -> scoring.RiskWeights | None:
    if tenant_id is None:
        return None
    row = s.scalars(select(TenantRiskWeights).where(TenantRiskWeights.tenant_id == tenant_id)).first()
    if row is None:
        return None
    return scoring.RiskWeights(
        criticality={int(k): float(v) for k, v in (row.criticality_weights or {}).items()},
        internet=row.internet_weight,
        cde=row.cde_weight,
    )


def set_weights(
    s: Session,
    tenant_id: int,
    *,
    actor: str,
    criticality: dict | None = None,
    internet: float = 1.3,
    cde: float = 1.3,
) -> TenantRiskWeights:
    """Override scoring.asset_weight / exposure_weight for one tenant, then rescore its findings."""
    crit: dict[str, float] = {}
    for k, v in (criticality or {}).items():
        level = int(k)
        if level not in range(1, 6):
            raise TuningError("criticality levels are 1..5")
        crit[str(level)] = _check_weight(f"criticality {level}", v)
    internet = _check_weight("internet weight", internet)
    cde = _check_weight("cde weight", cde)

    row = s.scalars(select(TenantRiskWeights).where(TenantRiskWeights.tenant_id == tenant_id)).first()
    before = None
    if row is None:
        row = TenantRiskWeights(tenant_id=tenant_id)
        s.add(row)
    else:
        before = {"criticality": row.criticality_weights, "internet": row.internet_weight, "cde": row.cde_weight}
    row.criticality_weights, row.internet_weight, row.cde_weight = crit, internet, cde
    row.updated_by, row.updated_at = actor, utcnow()
    s.flush()
    audit.record(
        s, actor, "tenant.risk_weights", "tenant", tenant_id,
        before=before, after={"criticality": crit, "internet": internet, "cde": cde},
    )
    rescore_tenant(s, tenant_id)
    return row


def clear_weights(s: Session, tenant_id: int, *, actor: str) -> None:
    row = s.scalars(select(TenantRiskWeights).where(TenantRiskWeights.tenant_id == tenant_id)).first()
    if row is None:
        return
    s.delete(row)
    s.flush()
    audit.record(s, actor, "tenant.risk_weights_cleared", "tenant", tenant_id)
    rescore_tenant(s, tenant_id)


def rescore_tenant(s: Session, tenant_id: int) -> int:
    from attestra.services import rescore

    n = 0
    q = select(Finding).join(Engagement, Engagement.id == Finding.engagement_id).where(Engagement.tenant_id == tenant_id)
    for f in s.scalars(q):
        rescore(f)
        n += 1
    s.flush()
    return n


# ---------------------------------------------------------------- suppression rules


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=utcnow().tzinfo)


def create_suppression(
    s: Session,
    tenant_id: int,
    *,
    actor: str,
    reason: str,
    expires_at: datetime,
    engagement_id: int | None = None,
    tool: str = "",
    rule_id: str = "",
    location_contains: str = "",
    title_contains: str = "",
) -> SuppressionRule:
    if not reason.strip():
        raise TuningError("a suppression needs a reason")
    if not any(x.strip() for x in (tool, rule_id, location_contains, title_contains)):
        raise TuningError("a suppression needs at least one of tool, rule_id, location or title")
    now = utcnow()
    expires_at = _aware(expires_at)
    if expires_at <= now:
        raise TuningError("expiry must be in the future")
    if expires_at > now + timedelta(days=MAX_SUPPRESSION_DAYS):
        raise TuningError(f"suppressions may last at most {MAX_SUPPRESSION_DAYS} days")
    if engagement_id is not None:
        eng = s.get(Engagement, engagement_id)
        if eng is None or eng.tenant_id != tenant_id:
            raise TuningError("engagement does not belong to this tenant")
    rule = SuppressionRule(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        tool=tool.strip().lower(),
        rule_id=rule_id.strip(),
        location_contains=location_contains.strip(),
        title_contains=title_contains.strip(),
        reason=reason.strip(),
        created_by=actor,
        created_at=now,
        expires_at=expires_at,
    )
    s.add(rule)
    s.flush()
    audit.record(
        s, actor, "suppression.create", "suppression_rule", rule.id,
        tenant_id=tenant_id, engagement_id=engagement_id, tool=rule.tool, rule_id=rule.rule_id,
        location_contains=rule.location_contains, title_contains=rule.title_contains,
        reason=rule.reason, expires_at=expires_at.isoformat(),
    )
    return rule


def revoke_suppression(s: Session, rule_id: int, *, actor: str) -> SuppressionRule:
    rule = s.get(SuppressionRule, rule_id)
    if rule is None:
        raise TuningError(f"suppression {rule_id} not found")
    if rule.revoked_at is None:
        rule.revoked_at, rule.revoked_by = utcnow(), actor
        s.flush()
        audit.record(s, actor, "suppression.revoke", "suppression_rule", rule.id)
    return rule


def is_active(rule: SuppressionRule, now: datetime | None = None) -> bool:
    now = now or utcnow()
    return rule.revoked_at is None and _aware(rule.expires_at) > now


def active_suppressions(s: Session, tenant_id: int, engagement_id: int | None = None) -> list[SuppressionRule]:
    rules = s.scalars(
        select(SuppressionRule).where(SuppressionRule.tenant_id == tenant_id, SuppressionRule.revoked_at.is_(None))
    )
    now = utcnow()
    return [
        r for r in rules
        if is_active(r, now) and (r.engagement_id is None or r.engagement_id == engagement_id)
    ]


def matches(rule: SuppressionRule, nf: NormalizedFinding) -> bool:
    if rule.tool and rule.tool != nf.tool.lower():
        return False
    if rule.rule_id and rule.rule_id != nf.rule_id:
        return False
    if rule.location_contains and rule.location_contains.lower() not in nf.location.lower():
        return False
    if rule.title_contains and rule.title_contains.lower() not in nf.title.lower():
        return False
    return True


def first_match(rules: list[SuppressionRule], nf: NormalizedFinding) -> SuppressionRule | None:
    return next((r for r in rules if matches(r, nf)), None)


# ---------------------------------------------------------------- false-positive rate


def fp_rate_by_tool(s: Session, tenant_ids=None) -> list[dict]:
    """Per tool: findings it reported, how many were marked false_positive, and the rate.

    ``tenant_ids`` None means all tenants (admin); otherwise restrict to those tenants.
    """
    q = select(Finding.tools, Finding.status)
    if tenant_ids is not None:
        q = q.join(Engagement, Engagement.id == Finding.engagement_id).where(Engagement.tenant_id.in_(list(tenant_ids)))
    totals: dict[str, list[int]] = {}
    for tools, status in s.execute(q):
        for tool in tools or []:
            t = totals.setdefault(tool, [0, 0])
            t[0] += 1
            if status == "false_positive":
                t[1] += 1
    return [
        {"tool": tool, "total": n, "false_positive": fp, "rate": round(fp / n, 3) if n else 0.0}
        for tool, (n, fp) in sorted(totals.items())
    ]


def findings_for_tool(s: Session, tool: str, tenant_ids=None) -> list[Finding]:
    """Findings that list ``tool`` in their tools array (UI audit #87 drill-down)."""
    tool = (tool or "").strip()
    if not tool:
        return []
    q = select(Finding).order_by(Finding.id.desc())
    if tenant_ids is not None:
        q = q.join(Engagement, Engagement.id == Finding.engagement_id).where(
            Engagement.tenant_id.in_(list(tenant_ids))
        )
    out: list[Finding] = []
    for f in s.scalars(q):
        if tool in (f.tools or []):
            out.append(f)
    return out


def suppression_count(s: Session, tenant_id: int) -> int:
    return s.scalar(select(func.count(SuppressionRule.id)).where(SuppressionRule.tenant_id == tenant_id)) or 0
