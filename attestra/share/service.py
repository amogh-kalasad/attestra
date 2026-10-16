"""Share-link create, revoke, public view and SVG badge."""
# @lat: [[interfaces#Share links]]

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from xml.sax.saxutils import escape as xml_escape

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, services
from attestra.grade import score_from_findings
from attestra.models import Asset, Engagement, Finding, ScanRun, utcnow
from attestra.share.models import SHARE_KINDS, ShareLink

CREATE_ROLES = frozenset({"admin", "lead", "tester"})
DEFAULT_TTL_DAYS = 7
MAX_TTL_DAYS = 90
TOKEN_BYTES = 32
VIEW_AUDIT_COOLDOWN = timedelta(minutes=15)

# Public HTML / badge must never leak these (seeded in tests and asserted absent).
FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "evidence",
        "tenant_id",
        "email",
        "api_key",
        "notes",
        "internal_note",
        "comments",
        "comment",
        "raw_path",
        "path",
        "username",
        "created_by",
    }
)


class ShareError(services.ServiceError):
    pass


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _check_create_role(principal) -> None:
    if principal is None or principal.role not in CREATE_ROLES:
        raise ShareError(f"share create not allowed for role {getattr(principal, 'role', None)}")


def _aware(dt):
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=utcnow().tzinfo)


def _check_tenant(s: Session, principal, tenant_id: int) -> None:
    allowed = services.tenant_ids_for(s, principal)
    if allowed is not None and tenant_id not in allowed:
        raise LookupError(f"tenant {tenant_id} not found")


def _resolve_targets(
    s: Session, principal, *, kind: str, asset_id: int | None, scan_run_id: int | None
) -> tuple[Engagement, Asset | None, ScanRun | None]:
    if kind not in SHARE_KINDS:
        raise ShareError(f"kind must be one of {SHARE_KINDS}")
    scan = None
    asset = None
    if kind == "scan":
        if not scan_run_id:
            raise ShareError("scan_run_id required for kind=scan")
        scan = s.get(ScanRun, scan_run_id)
        if not scan:
            raise LookupError(f"scan {scan_run_id} not found")
        eng = services.get_engagement(s, scan.engagement_id, principal)
        asset = s.get(Asset, scan.asset_id)
        if not asset or asset.engagement_id != eng.id:
            raise LookupError(f"scan {scan_run_id} not found")
        return eng, asset, scan
    if not asset_id:
        raise ShareError("asset_id required for kind=grade")
    asset = s.get(Asset, asset_id)
    if not asset:
        raise LookupError(f"asset {asset_id} not found")
    eng = services.get_engagement(s, asset.engagement_id, principal)
    return eng, asset, None


def create_share(
    s: Session,
    principal,
    *,
    kind: str,
    asset_id: int | None = None,
    scan_run_id: int | None = None,
    ttl_days: int = DEFAULT_TTL_DAYS,
    label: str = "",
) -> tuple[ShareLink, str]:
    """Create a share link. Returns (row, raw_token). Raw token is never stored."""
    _check_create_role(principal)
    try:
        days = int(ttl_days)
    except (TypeError, ValueError) as e:
        raise ShareError("ttl_days must be an integer") from e
    if days < 1 or days > MAX_TTL_DAYS:
        raise ShareError(f"ttl_days must be between 1 and {MAX_TTL_DAYS}")

    eng, asset, scan = _resolve_targets(s, principal, kind=kind, asset_id=asset_id, scan_run_id=scan_run_id)
    raw = secrets.token_urlsafe(TOKEN_BYTES)
    # secrets.token_urlsafe(32) yields >32 bytes of entropy from the secrets module
    row = ShareLink(
        tenant_id=eng.tenant_id,
        engagement_id=eng.id,
        kind=kind,
        asset_id=asset.id if asset else None,
        scan_run_id=scan.id if scan else None,
        token_hash=hash_token(raw),
        label=(label or "").strip()[:200],
        created_by=principal.actor,
        expires_at=utcnow() + timedelta(days=days),
    )
    s.add(row)
    s.flush()
    audit.record(
        s,
        principal.actor,
        "share.created",
        "share_link",
        row.id,
        kind=kind,
        asset_id=row.asset_id,
        scan_run_id=row.scan_run_id,
        expires_at=row.expires_at.isoformat(),
        ttl_days=days,
    )
    return row, raw


def list_shares(s: Session, principal, tenant_id: int, *, include_revoked: bool = True) -> list[ShareLink]:
    _check_create_role(principal)
    _check_tenant(s, principal, tenant_id)
    q = select(ShareLink).where(ShareLink.tenant_id == tenant_id)
    if not include_revoked:
        q = q.where(ShareLink.revoked_at.is_(None))
    return list(s.scalars(q.order_by(ShareLink.id.desc())))


def revoke_share(s: Session, principal, share_id: int) -> ShareLink:
    _check_create_role(principal)
    row = s.get(ShareLink, share_id)
    if not row:
        raise LookupError(f"share {share_id} not found")
    _check_tenant(s, principal, row.tenant_id)
    if row.revoked_at is not None:
        return row
    row.revoked_at = utcnow()
    row.revoked_by = principal.actor
    audit.record(
        s,
        principal.actor,
        "share.revoked",
        "share_link",
        row.id,
        kind=row.kind,
        asset_id=row.asset_id,
        scan_run_id=row.scan_run_id,
    )
    return row


def _find_by_token(s: Session, raw: str) -> ShareLink | None:
    if not raw or len(raw) < 16:
        return None
    return s.scalars(select(ShareLink).where(ShareLink.token_hash == hash_token(raw))).first()


def _is_valid(row: ShareLink) -> bool:
    if row is None:
        return False
    if row.revoked_at is not None:
        return False
    if _aware(row.expires_at) <= utcnow():
        return False
    return True


def get_valid_share(s: Session, raw: str) -> ShareLink | None:
    """Return the share when the token is good; otherwise None (same for bad/expired/revoked)."""
    row = _find_by_token(s, raw)
    if row is None or not _is_valid(row):
        return None
    return row


def _public_findings(s: Session, asset: Asset) -> list[dict]:
    from attestra.comments import finding_fields_for_share

    rows = list(
        s.scalars(
            select(Finding).where(
                Finding.asset_id == asset.id,
                Finding.engagement_id == asset.engagement_id,
            )
        )
    )
    out = []
    for f in rows:
        fields = finding_fields_for_share(f)
        out.append(
            {
                "title": fields["title"] or "",
                "severity": fields["severity"] or "",
                "status": fields["status"] or "",
                "fix": fields["recommendation"] or "",
            }
        )
    return out


def public_view(s: Session, raw: str, *, ip: str = "") -> dict | None:
    """Safe public payload for a valid share token, or None.

    Audits ``share.viewed`` at most once per IP per cooldown window.
    """
    row = get_valid_share(s, raw)
    if row is None:
        return None

    asset = s.get(Asset, row.asset_id) if row.asset_id else None
    if asset is None:
        return None

    findings_orm = list(
        s.scalars(
            select(Finding).where(
                Finding.asset_id == asset.id,
                Finding.engagement_id == asset.engagement_id,
            )
        )
    )
    grade_info = score_from_findings(findings_orm)
    target_name = (asset.name or "").strip() or (asset.identifier or "target")

    payload = {
        "target_name": target_name,
        "grade": grade_info["grade"],
        "score": grade_info["score"],
        "breakdown": [
            {
                "check": r["check"],
                "result": r["result"],
                "points": r["points"],
                "reason": r["reason"],
            }
            for r in grade_info["breakdown"]
        ],
        "findings": _public_findings(s, asset),
        "kind": row.kind,
    }
    if row.kind == "scan" and row.scan_run_id:
        scan = s.get(ScanRun, row.scan_run_id)
        if scan:
            payload["scan_tool"] = scan.tool or ""
            payload["scan_status"] = scan.status or ""

    # Rate-limited view audit
    now = utcnow()
    ip = (ip or "")[:64]
    should_audit = False
    last_audit = _aware(row.last_view_audit_at)
    if last_audit is None:
        should_audit = True
    elif ip and ip != (row.last_viewed_ip or ""):
        should_audit = True
    elif now - last_audit >= VIEW_AUDIT_COOLDOWN:
        should_audit = True

    row.last_viewed_at = now
    row.last_viewed_ip = ip
    if should_audit:
        row.last_view_audit_at = now
        audit.record(
            s,
            "share-public",
            "share.viewed",
            "share_link",
            row.id,
            ip=ip,
            kind=row.kind,
        )

    return payload


def badge_svg(s: Session, raw: str, *, ip: str = "") -> str | None:
    """Return a self-contained SVG badge, or None when the token is not valid."""
    view = public_view(s, raw, ip=ip)
    if view is None:
        return None
    grade = xml_escape(str(view["grade"]))
    score = xml_escape(str(view["score"]))
    label = xml_escape(f"Grade {view['grade']} · {view['score']}")
    # Fixed template: no external fonts or scripts; grade/score escaped.
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="160" height="20" role="img" '
        f'aria-label="{label}">'
        '<title>' + label + '</title>'
        '<linearGradient id="s" x2="0" y2="100%">'
        '<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        '<stop offset="1" stop-opacity=".1"/>'
        "</linearGradient>"
        '<mask id="m"><rect width="160" height="20" rx="3" fill="#fff"/></mask>'
        '<g mask="url(#m)">'
        '<rect width="70" height="20" fill="#555"/>'
        '<rect x="70" width="90" height="20" fill="#4338CA"/>'
        '<rect width="160" height="20" fill="url(#s)"/>'
        "</g>"
        '<g fill="#fff" text-anchor="middle" '
        'font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">'
        '<text x="35" y="14">Attestra</text>'
        f'<text x="114" y="14">{grade} · {score}</text>'
        "</g>"
        "</svg>"
    )


def link_status(row: ShareLink) -> str:
    if row.revoked_at is not None:
        return "revoked"
    if _aware(row.expires_at) <= utcnow():
        return "expired"
    return "active"


def to_list_item(row: ShareLink) -> dict:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "engagement_id": row.engagement_id,
        "kind": row.kind,
        "asset_id": row.asset_id,
        "scan_run_id": row.scan_run_id,
        "label": row.label,
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        "status": link_status(row),
    }
