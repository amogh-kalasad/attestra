"""Human finding assignment: assign/unassign to a tenant username with audit."""
# @lat: [[findings#Assignment]]

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit
from attestra.models import Engagement, Finding, FindingAssignment, TenantMembership, User
from attestra.services import ServiceError


def _user_tenant_ids(s: Session, user: User) -> set[int]:
    ids = {m.tenant_id for m in s.scalars(select(TenantMembership).where(TenantMembership.user_id == user.id))}
    if user.tenant_id is not None:
        ids.add(user.tenant_id)
    return ids


def _finding_and_tenant(s: Session, finding_id: int) -> tuple[Finding, int]:
    f = s.get(Finding, finding_id)
    if not f:
        raise LookupError(f"finding {finding_id} not found")
    eng = s.get(Engagement, f.engagement_id)
    if not eng:
        raise LookupError(f"engagement {f.engagement_id} not found")
    return f, eng.tenant_id


def _resolve_assignee(s: Session, username: str, tenant_id: int) -> User:
    """Resolve username to an active User in the finding tenant (or platform admin)."""
    name = (username or "").strip().lower()
    if not name:
        raise ServiceError("assignee is required; use unassign_finding to clear")
    user = s.scalar(select(User).where(User.username == name))
    if user is None or not user.active:
        raise ServiceError(f"unknown user {username!r}")
    if user.role == "admin":
        return user
    if tenant_id not in _user_tenant_ids(s, user):
        raise ServiceError(f"user {user.username!r} is not in this tenant")
    return user


def assign_finding(
    s: Session,
    finding_id: int,
    *,
    assignee: str,
    actor: str,
    user_id: int | None = None,
) -> FindingAssignment:
    """Assign a finding to a username in the same tenant (or platform admin)."""
    f, tenant_id = _finding_and_tenant(s, finding_id)
    user = _resolve_assignee(s, assignee, tenant_id)
    row = FindingAssignment(
        finding_id=f.id,
        assignee=user.username,
        rule_id=None,
        assigned_by=actor,
    )
    s.add(row)
    s.flush()
    details: dict = {"assignee": user.username}
    if user_id is not None:
        details["user_id"] = user_id
    audit.record(s, actor, "finding.assigned", "finding", f.id, **details)
    return row


def unassign_finding(s: Session, finding_id: int, *, actor: str) -> None:
    """Clear the current assignee; records an empty assignment row and audits."""
    f, _tenant_id = _finding_and_tenant(s, finding_id)
    s.add(
        FindingAssignment(
            finding_id=f.id,
            assignee="",
            rule_id=None,
            assigned_by=actor,
        )
    )
    s.flush()
    audit.record(s, actor, "finding.unassigned", "finding", f.id)


def current_assignee(s: Session, finding_id: int) -> str | None:
    """Latest non-empty assignee, or None if never assigned or last action was unassign."""
    row = s.scalars(
        select(FindingAssignment)
        .where(FindingAssignment.finding_id == finding_id)
        .order_by(FindingAssignment.id.desc())
        .limit(1)
    ).first()
    if row is None:
        return None
    name = (row.assignee or "").strip()
    return name or None


def _latest_assignees(s: Session, finding_ids: list[int]) -> dict[int, str]:
    """Map finding id → current assignee username (empty string if unassigned / never set)."""
    if not finding_ids:
        return {}
    rows = list(
        s.scalars(
            select(FindingAssignment)
            .where(FindingAssignment.finding_id.in_(finding_ids))
            .order_by(FindingAssignment.id.desc())
        )
    )
    latest: dict[int, str] = {}
    for row in rows:
        if row.finding_id in latest:
            continue
        latest[row.finding_id] = (row.assignee or "").strip()
    return latest


def findings_assigned_to(s: Session, engagement_id: int, username: str) -> list[Finding]:
    """Findings in the engagement whose current assignee matches ``username``."""
    name = (username or "").strip().lower()
    if not name:
        return []
    findings = list(
        s.scalars(select(Finding).where(Finding.engagement_id == engagement_id).order_by(Finding.id))
    )
    if not findings:
        return []
    latest = _latest_assignees(s, [f.id for f in findings])
    return [f for f in findings if latest.get(f.id, "").lower() == name]


def assignees_for_engagement(s: Session, engagement_id: int) -> dict[int, str]:
    """Current assignee username per finding id (omit findings with no current assignee)."""
    ids = list(s.scalars(select(Finding.id).where(Finding.engagement_id == engagement_id)))
    latest = _latest_assignees(s, ids)
    return {fid: name for fid, name in latest.items() if name}
