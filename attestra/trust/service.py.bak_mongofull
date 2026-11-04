"""Trust center business rules."""

from __future__ import annotations

import hashlib
import re
import secrets
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, config, services
from attestra.models import Engagement, Evidence, Finding, Report, Tenant, utcnow
from attestra.trust.models import ACCESS_LEVELS, ITEM_KINDS, TrustAccessRequest, TrustCenter, TrustItem

# Role rules live here so the shared RBAC map stays untouched.
ENABLE_ROLES = frozenset({"admin"})
PUBLISH_ROLES = frozenset({"admin", "lead", "tester"})
APPROVE_ROLES = frozenset({"admin", "lead"})
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$")
MAX_DOC_BYTES = 20 * 1024 * 1024


class TrustError(services.ServiceError):
    pass


def _check_role(principal, roles: frozenset[str], what: str) -> None:
    if principal.role not in roles:
        raise TrustError(f"{what} not allowed for role {principal.role}")


def _check_tenant(s: Session, principal, tenant_id: int) -> Tenant:
    t = s.get(Tenant, tenant_id)
    allowed = services.tenant_ids_for(s, principal)
    if not t or (allowed is not None and tenant_id not in allowed):
        raise LookupError(f"tenant {tenant_id} not found")
    return t


def get_center(s: Session, tenant_id: int) -> TrustCenter | None:
    return s.scalars(select(TrustCenter).where(TrustCenter.tenant_id == tenant_id)).first()


def configure(s: Session, principal, tenant_id: int, *, enabled: bool, slug: str | None = None,
              title: str | None = None, description: str | None = None) -> TrustCenter:
    """Admin only: create or update the tenant's trust center. Off by default."""
    _check_role(principal, ENABLE_ROLES, "trust center configuration")
    t = _check_tenant(s, principal, tenant_id)
    c = get_center(s, tenant_id)
    if c is None:
        slug = slug or re.sub(r"[^a-z0-9]+", "-", t.name.lower()).strip("-")[:80] or f"tenant-{t.id}"
        c = TrustCenter(tenant_id=tenant_id, slug=slug, enabled=False, title=title or t.name)
        s.add(c)
    if slug is not None:
        if not _SLUG.match(slug):
            raise TrustError("slug must be 3-80 lowercase letters, digits or dashes")
        clash = s.scalars(select(TrustCenter).where(TrustCenter.slug == slug)).first()
        if clash is not None and clash is not c:
            raise TrustError("slug already in use")
        c.slug = slug
    if title is not None:
        c.title = title
    if description is not None:
        c.description = description
    c.enabled = bool(enabled)
    c.updated_by, c.updated_at = principal.actor, utcnow()
    s.flush()
    audit.record(s, principal.actor, "trust.configured", "tenant", tenant_id, enabled=c.enabled, slug=c.slug)
    return c


def _engagement_in_tenant(s: Session, engagement_id: int, tenant_id: int) -> None:
    e = s.get(Engagement, engagement_id)
    if not e or e.tenant_id != tenant_id:
        raise TrustError("referenced item does not belong to this tenant")


def publish(s: Session, principal, tenant_id: int, *, kind: str, title: str, summary: str = "",
            access: str = "public", ref_id: int | None = None, ref_key: str = "",
            filename: str = "", data: bytes | None = None) -> TrustItem:
    """Tester/lead/admin explicitly publishes one item. Nothing else ever creates items."""
    _check_role(principal, PUBLISH_ROLES, "trust publishing")
    _check_tenant(s, principal, tenant_id)
    if kind not in ITEM_KINDS:
        raise TrustError(f"unknown kind {kind}")
    if access not in ACCESS_LEVELS:
        raise TrustError(f"unknown access {access}")
    if not title.strip():
        raise TrustError("title required")
    item = TrustItem(tenant_id=tenant_id, kind=kind, title=title.strip()[:300], summary=summary,
                     access=access, ref_id=ref_id, ref_key=ref_key[:100], published_by=principal.actor)
    if kind == "report":
        r = s.get(Report, ref_id or 0)
        if not r:
            raise TrustError("report not found")
        _engagement_in_tenant(s, r.engagement_id, tenant_id)
        if r.status != "signed":
            raise TrustError("only signed reports can be published")
        item.sha256 = r.sha256
    elif kind == "finding":
        f = s.get(Finding, ref_id or 0)
        if not f:
            raise TrustError("finding not found")
        _engagement_in_tenant(s, f.engagement_id, tenant_id)
    elif kind == "evidence":
        ev = s.get(Evidence, ref_id or 0)
        if not ev:
            raise TrustError("evidence not found")
        _engagement_in_tenant(s, ev.finding.engagement_id, tenant_id)
        item.sha256 = ev.sha256
    elif kind == "framework":
        if not ref_key:
            raise TrustError("framework key required")
    elif kind == "document":
        if not data:
            raise TrustError("document file required")
        if len(data) > MAX_DOC_BYTES:
            raise TrustError("document too large")
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(filename or "document").name)[:120] or "document"
        folder = Path(config.DATA_DIR) / "trust" / str(tenant_id)
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{secrets.token_hex(8)}_{safe}"
        path.write_bytes(data)
        item.path, item.sha256 = str(path), hashlib.sha256(data).hexdigest()
    s.add(item)
    s.flush()
    audit.record(s, principal.actor, "trust.published", "trust_item", item.id,
                 tenant_id=tenant_id, kind=kind, access=access, ref_id=ref_id)
    return item


def unpublish(s: Session, principal, item_id: int) -> TrustItem:
    _check_role(principal, PUBLISH_ROLES, "trust publishing")
    item = s.get(TrustItem, item_id)
    if not item:
        raise LookupError(f"trust item {item_id} not found")
    _check_tenant(s, principal, item.tenant_id)
    item.published = False
    audit.record(s, principal.actor, "trust.unpublished", "trust_item", item.id, tenant_id=item.tenant_id)
    return item


def list_items(s: Session, tenant_id: int, *, published_only: bool = True) -> list[TrustItem]:
    q = select(TrustItem).where(TrustItem.tenant_id == tenant_id)
    if published_only:
        q = q.where(TrustItem.published.is_(True))
    return list(s.scalars(q.order_by(TrustItem.kind, TrustItem.id)))


def report_status(s: Session, item: TrustItem) -> dict:
    """Live signature check for a published report (summary only, never contents)."""
    from attestra.reports.render import verify_report

    r = s.get(Report, item.ref_id or 0)
    if not r:
        return {"verified": False, "reason": "report missing"}
    try:
        v = verify_report(s, r.id)
    except (OSError, LookupError, services.ServiceError):
        return {"verified": False, "reason": "report file unavailable", "sha256": r.sha256}
    ok = bool(v["hash_matches"] and v["signature_valid"] and r.status == "signed")
    return {
        "verified": ok, "reason": "" if ok else "hash or signature mismatch", "sha256": r.sha256,
        "algorithm": v.get("algorithm", ""), "framework": r.framework, "kind": r.kind,
        "version": r.version, "signed_at": r.signed_at,
    }


def public_view(s: Session, slug: str) -> dict | None:
    c = s.scalars(select(TrustCenter).where(TrustCenter.slug == slug)).first()
    if c is None or not c.enabled:
        return None
    items = list_items(s, c.tenant_id)
    view: dict = {"center": c, "frameworks": [], "reports": [], "badges": [], "documents": [],
                  "findings": [], "evidence": []}
    for it in items:
        if it.kind == "report":
            view["reports"].append({"item": it, "status": report_status(s, it)})
        elif it.kind == "finding":
            f = s.get(Finding, it.ref_id or 0)
            # Only the headline is shown; never description, location or evidence.
            view["findings"].append({"item": it, "severity": f.severity if f else "",
                                     "status": f.status if f else ""})
        elif it.kind == "evidence":
            view["evidence"].append({"item": it})
        else:
            view[{"framework": "frameworks", "badge": "badges", "document": "documents"}[it.kind]].append(
                {"item": it})
    return view


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def request_access(s: Session, slug: str, item_id: int, *, name: str, email: str, company: str = "",
                   reason: str = "", nda_accepted: bool = False) -> TrustAccessRequest:
    c = s.scalars(select(TrustCenter).where(TrustCenter.slug == slug)).first()
    item = s.get(TrustItem, item_id)
    if c is None or not c.enabled or not item or item.tenant_id != c.tenant_id or not item.published:
        raise LookupError("item not found")
    if item.access != "nda":
        raise TrustError("item is public; no request needed")
    if not nda_accepted:
        raise TrustError("the NDA must be accepted")
    if not name.strip() or "@" not in email:
        raise TrustError("name and a valid email are required")
    req = TrustAccessRequest(tenant_id=c.tenant_id, item_id=item.id, requester_name=name.strip()[:200],
                             requester_email=email.strip()[:200], company=company.strip()[:200],
                             reason=reason[:2000], nda_accepted=True)
    s.add(req)
    s.flush()
    audit.record(s, f"public:{req.requester_email}", "trust.access_requested", "trust_access_request", req.id,
                 tenant_id=c.tenant_id, item_id=item.id, company=req.company, nda_accepted=True)
    return req


def decide(s: Session, principal, request_id: int, *, approve: bool) -> tuple[TrustAccessRequest, str | None]:
    """Lead/admin approves or denies. Approval returns a one-time download token (stored hashed)."""
    _check_role(principal, APPROVE_ROLES, "access approval")
    req = s.get(TrustAccessRequest, request_id)
    if not req:
        raise LookupError(f"request {request_id} not found")
    _check_tenant(s, principal, req.tenant_id)
    if req.status != "pending":
        raise TrustError(f"request already {req.status}")
    token = secrets.token_urlsafe(24) if approve else None
    req.status = "approved" if approve else "denied"
    req.token_hash = _hash(token) if token else ""
    req.decided_by, req.decided_at = principal.actor, utcnow()
    audit.record(s, principal.actor, f"trust.access_{req.status}", "trust_access_request", req.id,
                 tenant_id=req.tenant_id, item_id=req.item_id)
    return req, token


def list_requests(s: Session, principal, tenant_id: int) -> list[TrustAccessRequest]:
    _check_role(principal, APPROVE_ROLES | PUBLISH_ROLES, "trust requests")
    _check_tenant(s, principal, tenant_id)
    return list(s.scalars(select(TrustAccessRequest).where(TrustAccessRequest.tenant_id == tenant_id)
                          .order_by(TrustAccessRequest.id.desc())))


def download(s: Session, slug: str, item_id: int, token: str | None) -> tuple[Path, str]:
    """Return (path, filename) when the caller may download. Logs every NDA download."""
    c = s.scalars(select(TrustCenter).where(TrustCenter.slug == slug)).first()
    item = s.get(TrustItem, item_id)
    if c is None or not c.enabled or not item or item.tenant_id != c.tenant_id or not item.published:
        raise LookupError("item not found")
    if item.kind == "document":
        path = Path(item.path)
    elif item.kind == "report":
        r = s.get(Report, item.ref_id or 0)
        if not r or r.status != "signed":
            raise LookupError("item not found")
        path = Path(r.pdf_path or r.path)
    else:
        raise LookupError("item has no download")
    if item.access == "nda":
        if not token:
            raise TrustError("access request required")
        req = s.scalars(select(TrustAccessRequest).where(
            TrustAccessRequest.item_id == item.id, TrustAccessRequest.status == "approved",
            TrustAccessRequest.token_hash == _hash(token))).first()
        if req is None:
            raise TrustError("access not approved")
        audit.record(s, f"public:{req.requester_email}", "trust.downloaded", "trust_item", item.id,
                     tenant_id=item.tenant_id, request_id=req.id)
    if not path.is_file():
        raise LookupError("file unavailable")
    return path, path.name.split("_", 1)[-1] if item.kind == "document" else path.name
