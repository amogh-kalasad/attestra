"""Finding comment threads: list, add, soft-delete with tenant and role checks."""
# @lat: [[findings#Comments]]

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, services
from attestra.auth.roles import has_permission
from attestra.models import Finding, FindingComment, User, utcnow

COMMENT_MAX_LEN = 5000
# Same statuses the client portal hides (untriaged / rejected tester work).
CLIENT_HIDDEN_STATUSES = frozenset({"new", "false_positive"})


def can_add_comment(role: str) -> bool:
    """Writers and client viewers may add; reviewers and auditors may only read."""
    return has_permission(role, "finding.write") or role == "client_viewer"


def can_delete_comment(role: str, *, author_user_id: int, actor_user_id: int) -> bool:
    """Authors may delete their own; lead/admin may delete any in-tenant comment."""
    if author_user_id == actor_user_id:
        return True
    return role in ("lead", "admin")


def finding_fields_for_share(f: Finding) -> dict:
    """Public share-link fields only. Never includes comments, evidence, or notes."""
    return {
        "title": f.title,
        "severity": f.severity,
        "status": f.status,
        "recommendation": f.recommendation or "",
    }


def _visible_finding(s: Session, finding_id: int, principal) -> tuple[Finding, int]:
    f = s.get(Finding, finding_id)
    if not f:
        raise LookupError(f"finding {finding_id} not found")
    eng = services.get_engagement(s, f.engagement_id, principal)
    if principal.role == "client_viewer" and f.status in CLIENT_HIDDEN_STATUSES:
        raise LookupError(f"finding {finding_id} not found")
    return f, eng.tenant_id


def _comment_dict(c: FindingComment, author: User | None) -> dict:
    return {
        "id": c.id,
        "finding_id": c.finding_id,
        "tenant_id": c.tenant_id,
        "author_user_id": c.author_user_id,
        "author_name": (author.display_name or author.username) if author else f"user-{c.author_user_id}",
        "body": c.body,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "edited_at": c.edited_at.isoformat() if c.edited_at else None,
        "deleted": bool(c.deleted),
    }


def list_comments(s: Session, finding_id: int, principal) -> list[dict]:
    if not has_permission(principal.role, "finding.read"):
        raise services.ServiceError("not allowed: cannot read comments")
    _visible_finding(s, finding_id, principal)
    rows = list(
        s.scalars(
            select(FindingComment)
            .where(FindingComment.finding_id == finding_id, FindingComment.deleted.is_(False))
            .order_by(FindingComment.id)
        )
    )
    authors = {}
    for uid in {c.author_user_id for c in rows}:
        authors[uid] = s.get(User, uid)
    return [_comment_dict(c, authors.get(c.author_user_id)) for c in rows]


def add_comment(s: Session, finding_id: int, *, body: str, principal) -> dict:
    if not can_add_comment(principal.role):
        raise services.ServiceError("not allowed: cannot add comments")
    text = (body or "").strip()
    if not text:
        raise services.ServiceError("comment text is required")
    if len(text) > COMMENT_MAX_LEN:
        raise services.ServiceError(f"comment must be at most {COMMENT_MAX_LEN} characters")
    f, tenant_id = _visible_finding(s, finding_id, principal)
    c = FindingComment(
        finding_id=f.id,
        tenant_id=tenant_id,
        author_user_id=principal.user_id,
        body=text,
        created_at=utcnow(),
        deleted=False,
    )
    s.add(c)
    s.flush()
    audit.record(
        s,
        principal.actor,
        "finding.comment.added",
        "finding_comment",
        c.id,
        finding_id=f.id,
        tenant_id=tenant_id,
    )
    from attestra.webhooks.service import safe_emit_finding

    safe_emit_finding(
        s,
        f,
        "finding.commented",
        actor=principal.actor,
        comment_id=c.id,
        author_user_id=principal.user_id,
    )
    author = s.get(User, principal.user_id)
    return _comment_dict(c, author)


def delete_comment(s: Session, finding_id: int, comment_id: int, principal) -> dict:
    f, tenant_id = _visible_finding(s, finding_id, principal)
    c = s.get(FindingComment, comment_id)
    if not c or c.finding_id != f.id or c.tenant_id != tenant_id or c.deleted:
        raise LookupError(f"comment {comment_id} not found")
    if not can_delete_comment(principal.role, author_user_id=c.author_user_id, actor_user_id=principal.user_id):
        raise services.ServiceError("not allowed: cannot delete this comment")
    c.deleted = True
    s.flush()
    audit.record(
        s,
        principal.actor,
        "finding.comment.deleted",
        "finding_comment",
        c.id,
        finding_id=f.id,
        tenant_id=tenant_id,
    )
    author = s.get(User, c.author_user_id)
    return _comment_dict(c, author)


def comments_for_findings(s: Session, finding_ids: list[int]) -> dict[int, list[FindingComment]]:
    """Active comments keyed by finding id (for optional report inclusion)."""
    if not finding_ids:
        return {}
    rows = list(
        s.scalars(
            select(FindingComment)
            .where(FindingComment.finding_id.in_(finding_ids), FindingComment.deleted.is_(False))
            .order_by(FindingComment.id)
        )
    )
    out: dict[int, list[FindingComment]] = {fid: [] for fid in finding_ids}
    for c in rows:
        out.setdefault(c.finding_id, []).append(c)
    return out
