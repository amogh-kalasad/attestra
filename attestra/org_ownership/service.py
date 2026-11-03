"""Organization domain ownership: durable per-hostname tokens, verify, download, renew."""
# @lat: [[authorization#Target ownership#Organization domain ownership]]

from __future__ import annotations

import ipaddress
import re
import secrets
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, services
from attestra.auth.roles import has_permission
from attestra.models import Asset, Engagement, Tenant, TenantOwnershipHost, utcnow
from attestra.runner import ownership
from attestra.runner.authorization import AuthorizationError, authorize_target, owner_confirm_host, scope_for_engagement
from attestra.runner.policy import OWNERSHIP_KINDS

WELL_KNOWN_DOWNLOAD_NAME = ownership.WELL_KNOWN_FILENAME
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


class OrgOwnershipError(ValueError):
    pass


def _require_manage(principal) -> None:
    if principal is None or not has_permission(getattr(principal, "role", ""), "asset.verify_ownership"):
        raise PermissionError("only a lead or admin can manage organization domain ownership")


def _require_tenant(s: Session, principal, tenant_id: int) -> Tenant:
    allowed = services.tenant_ids_for(s, principal)
    if allowed is not None and tenant_id not in allowed:
        raise LookupError(f"tenant {tenant_id} not found")
    t = s.get(Tenant, tenant_id)
    if t is None:
        raise LookupError(f"tenant {tenant_id} not found")
    return t


def normalize_hostname(raw: str) -> str:
    """Normalize a hostname or URL host for org ownership (lowercase, no port/path)."""
    text = (raw or "").strip().lower()
    if not text:
        raise OrgOwnershipError("Hostname is required.")
    if "://" not in text and "/" in text:
        text = text.split("/", 1)[0]
    if "://" in text:
        host = urlsplit(text).hostname
    else:
        # Strip brackets for IPv6 literals; drop :port for hostnames (not IPv6).
        host = text.strip("[]")
        if host.count(":") == 1 and not host.replace(".", "").isdigit():
            # hostname:port
            host = host.rsplit(":", 1)[0]
        elif host.count(":") > 1:
            host = text.strip("[]").split("%", 1)[0]
        else:
            host = host
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        raise OrgOwnershipError("Hostname is required.")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _HOSTNAME.fullmatch(host):
        raise OrgOwnershipError(f"Invalid hostname: {raw!r}")
    return host


def get_ownership_host(s: Session, host_id: int, principal=None) -> TenantOwnershipHost:
    row = s.get(TenantOwnershipHost, host_id)
    if row is None:
        raise LookupError(f"ownership host {host_id} not found")
    if principal is not None:
        _require_tenant(s, principal, row.tenant_id)
    return row


def list_ownership_hosts(s: Session, tenant_id: int) -> list[TenantOwnershipHost]:
    return list(
        s.scalars(
            select(TenantOwnershipHost)
            .where(TenantOwnershipHost.tenant_id == tenant_id)
            .order_by(TenantOwnershipHost.hostname)
        )
    )


def ensure_org_ownership_host(
    s: Session, tenant_id: int, hostname: str, *, actor: str = "", renew_if_expired: bool = True
) -> TenantOwnershipHost:
    """Get or create the durable org ownership row for a hostname; rotate token only after expiry."""
    host = normalize_hostname(hostname)
    row = s.scalar(
        select(TenantOwnershipHost).where(
            TenantOwnershipHost.tenant_id == tenant_id, TenantOwnershipHost.hostname == host
        )
    )
    if row is None:
        # Prefer an existing asset token for this host so DNS stays one-time for the org.
        seed_token = ""
        seed_verified = None
        days = services.ownership_validity_days_for_tenant(s, tenant_id)
        siblings = services._tenant_assets_for_ownership_host(s, tenant_id, host)
        verified = [
            a for a in siblings if a.ownership_token and ownership.is_verified(a, validity_days=days)
        ]
        if verified:
            src = max(verified, key=lambda a: ownership._as_utc(a.ownership_verified_at))
            seed_token = src.ownership_token
            seed_verified = src.ownership_verified_at
        else:
            with_token = [a for a in siblings if a.ownership_token]
            if with_token:
                seed_token = with_token[0].ownership_token
        token = seed_token or secrets.token_urlsafe(24)
        row = TenantOwnershipHost(
            tenant_id=tenant_id,
            hostname=host,
            ownership_token=token,
            ownership_verified_at=seed_verified,
            last_method="",
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        s.add(row)
        s.flush()
        sync_assets_from_org_host(s, row)
        if actor:
            audit.record(
                s,
                actor,
                "tenant.ownership_host_added",
                "tenant_ownership_host",
                row.id,
                tenant_id=tenant_id,
                hostname=host,
                token_suffix=ownership.token_fingerprint(token),
            )
        return row
    if renew_if_expired:
        renew_org_ownership_host_if_expired(s, row, actor=actor)
    return row


def renew_org_ownership_host_if_expired(s: Session, row: TenantOwnershipHost, *, actor: str = "") -> bool:
    """If the org proof expired, issue a new token (one-time DNS/file update required)."""
    days = services.ownership_validity_days_for_tenant(s, row.tenant_id)
    probe = ownership.synthetic_asset_for_host(row.hostname, row.ownership_token or "x")
    probe.ownership_verified_at = row.ownership_verified_at
    if row.ownership_verified_at is None:
        return False
    if not ownership.is_expired(probe, validity_days=days):
        return False
    old_suffix = ownership.token_fingerprint(row.ownership_token)
    row.ownership_token = secrets.token_urlsafe(24)
    row.ownership_verified_at = None
    row.last_method = ""
    row.updated_at = utcnow()
    sync_assets_from_org_host(s, row)
    if actor:
        audit.record(
            s,
            actor,
            "tenant.ownership_host_renewed",
            "tenant_ownership_host",
            row.id,
            tenant_id=row.tenant_id,
            hostname=row.hostname,
            previous_token_suffix=old_suffix,
            token_suffix=ownership.token_fingerprint(row.ownership_token),
        )
    return True


def add_ownership_host(s: Session, principal, tenant_id: int, hostname: str) -> TenantOwnershipHost:
    _require_manage(principal)
    _require_tenant(s, principal, tenant_id)
    host = normalize_hostname(hostname)
    existing = s.scalar(
        select(TenantOwnershipHost).where(
            TenantOwnershipHost.tenant_id == tenant_id, TenantOwnershipHost.hostname == host
        )
    )
    if existing is not None:
        renew_org_ownership_host_if_expired(s, existing, actor=principal.actor)
        return existing
    return ensure_org_ownership_host(s, tenant_id, host, actor=principal.actor, renew_if_expired=False)


def sync_assets_from_org_host(s: Session, row: TenantOwnershipHost) -> int:
    """Copy org host token + verification onto all same-host assets in the organization."""
    n = 0
    for asset in services._tenant_assets_for_ownership_host(s, row.tenant_id, row.hostname):
        if asset.kind not in OWNERSHIP_KINDS:
            continue
        changed = (
            asset.ownership_token != row.ownership_token
            or asset.ownership_verified_at != row.ownership_verified_at
        )
        asset.ownership_token = row.ownership_token
        asset.ownership_verified_at = row.ownership_verified_at
        if changed:
            n += 1
    return n


def host_card(s: Session, row: TenantOwnershipHost) -> dict:
    """UI dict for one org ownership host."""
    days = services.ownership_validity_days_for_tenant(s, row.tenant_id)
    renew_org_ownership_host_if_expired(s, row)
    probe = ownership.synthetic_asset_for_host(row.hostname, row.ownership_token)
    probe.ownership_verified_at = row.ownership_verified_at
    verified = ownership.is_verified(probe, validity_days=days)
    expired = ownership.is_expired(probe, validity_days=days)
    until = ownership.verified_until(probe, validity_days=days)
    private = bool(owner_confirm_host("web_app", f"https://{row.hostname}"))
    return {
        "id": row.id,
        "hostname": row.hostname,
        "token": row.ownership_token,
        "txt_value": f"{ownership.TXT_PREFIX}{row.ownership_token}",
        "file_name": WELL_KNOWN_DOWNLOAD_NAME,
        "file_url": f"https://{row.hostname}{ownership.WELL_KNOWN_PATH}",
        "file_path_hint": ownership.WELL_KNOWN_PATH,
        "verified": verified,
        "expired": expired,
        "verified_at": row.ownership_verified_at,
        "verified_until": until,
        "last_method": row.last_method or "",
        "private_confirm": private,
        "validity_days": days,
    }


def _scope_for_org_host(s: Session, tenant_id: int, hostname: str):
    """Pick any engagement in the tenant that can authorize a file check for this host."""
    engs = list(s.scalars(select(Engagement).where(Engagement.tenant_id == tenant_id).order_by(Engagement.id)))
    last_err = "no engagement in this organization"
    for eng in engs:
        try:
            scope = scope_for_engagement(s, eng.id)
            url = f"https://{hostname}{ownership.WELL_KNOWN_PATH}"
            authorize_target(scope, url, "url")
            return scope, ""
        except AuthorizationError as exc:
            last_err = str(exc)
            continue
        except Exception as exc:  # noqa: BLE001
            last_err = str(exc)
            continue
    return None, last_err


def verify_ownership_host(s: Session, principal, host_id: int):
    """DNS/file Check now for an organization ownership host."""
    _require_manage(principal)
    row = get_ownership_host(s, host_id, principal)
    renew_org_ownership_host_if_expired(s, row, actor=principal.actor)
    probe = ownership.synthetic_asset_for_host(row.hostname, row.ownership_token)
    probe.ownership_token = row.ownership_token
    days = services.ownership_validity_days_for_tenant(s, row.tenant_id)
    probe.ownership_verified_at = row.ownership_verified_at
    if ownership.is_verified(probe, validity_days=days):
        result = ownership.OwnershipCheck(ok=True, method=row.last_method or "dns")
        until = ownership.verified_until(probe, validity_days=days)
        note = f" It stays valid until {until.isoformat()}." if until else ""
        result.notes.append(f"This hostname is already verified for the organization.{note}")
        return result

    scope, scope_error = _scope_for_org_host(s, row.tenant_id, row.hostname)
    result = ownership.check(probe, scope=scope, scope_error=scope_error)
    if result.ok:
        row.ownership_verified_at = probe.ownership_verified_at or utcnow()
        row.last_method = result.method
        row.updated_at = utcnow()
        sync_assets_from_org_host(s, row)
        audit.record(
            s,
            principal.actor,
            "tenant.ownership_host_verified",
            "tenant_ownership_host",
            row.id,
            tenant_id=row.tenant_id,
            hostname=row.hostname,
            method=result.method,
            verified_at=row.ownership_verified_at.isoformat(),
        )
    else:
        audit.record(
            s,
            principal.actor,
            "tenant.ownership_host_check_failed",
            "tenant_ownership_host",
            row.id,
            tenant_id=row.tenant_id,
            hostname=row.hostname,
            reason=result.message[:500],
        )
    return result


def confirm_ownership_host(s: Session, principal, host_id: int, *, confirmed: bool, confirmed_by: str):
    """Option C for private-IP org hosts."""
    _require_manage(principal)
    row = get_ownership_host(s, host_id, principal)
    renew_org_ownership_host_if_expired(s, row, actor=principal.actor)
    days = services.ownership_validity_days_for_tenant(s, row.tenant_id)
    probe = ownership.synthetic_asset_for_host(row.hostname, row.ownership_token)
    probe.ownership_verified_at = row.ownership_verified_at
    if ownership.is_verified(probe, validity_days=days):
        raise OrgOwnershipError("This hostname is already verified for the organization.")
    host = owner_confirm_host("web_app", f"https://{row.hostname}")
    if not host:
        raise OrgOwnershipError(
            "Owner confirmation is only for private network addresses. For public hostnames use DNS or the file."
        )
    if not confirmed:
        raise OrgOwnershipError("Tick the box to confirm you own or control this private address.")
    who = " ".join((confirmed_by or "").split())
    if not who:
        raise OrgOwnershipError("Type who is confirming, as name and role.")
    if len(who) > 200:
        raise OrgOwnershipError("Confirmed by is too long (200 characters at most).")
    row.ownership_verified_at = utcnow()
    row.last_method = "owner_confirmed"
    row.updated_at = utcnow()
    sync_assets_from_org_host(s, row)
    audit.record(
        s,
        principal.actor,
        "tenant.ownership_host_confirmed",
        "tenant_ownership_host",
        row.id,
        tenant_id=row.tenant_id,
        hostname=row.hostname,
        method="owner_confirmed",
        confirmed_by=who,
        verified_at=row.ownership_verified_at.isoformat(),
    )
    return row


def backfill_ownership_hosts(s: Session, tenant_id: int, *, actor: str = "") -> int:
    """Create org host rows from existing assets (best token / verification per hostname)."""
    created = 0
    by_host: dict[str, list[Asset]] = {}
    assets = list(
        s.scalars(
            select(Asset)
            .join(Engagement, Asset.engagement_id == Engagement.id)
            .where(Engagement.tenant_id == tenant_id, Asset.kind.in_(tuple(OWNERSHIP_KINDS)))
        )
    )
    for asset in assets:
        host = ownership.host_for(asset)
        if not host:
            continue
        by_host.setdefault(host, []).append(asset)
    days = services.ownership_validity_days_for_tenant(s, tenant_id)
    for host, group in by_host.items():
        existing = s.scalar(
            select(TenantOwnershipHost).where(
                TenantOwnershipHost.tenant_id == tenant_id, TenantOwnershipHost.hostname == host
            )
        )
        if existing is not None:
            continue
        verified = [a for a in group if a.ownership_token and ownership.is_verified(a, validity_days=days)]
        if verified:
            src = max(verified, key=lambda a: ownership._as_utc(a.ownership_verified_at))
        else:
            with_token = [a for a in group if a.ownership_token]
            src = with_token[0] if with_token else group[0]
        token = src.ownership_token or secrets.token_urlsafe(24)
        row = TenantOwnershipHost(
            tenant_id=tenant_id,
            hostname=host,
            ownership_token=token,
            ownership_verified_at=(src.ownership_verified_at if src.ownership_token else None),
            last_method="",
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        if not src.ownership_token:
            row.ownership_verified_at = None
        s.add(row)
        s.flush()
        sync_assets_from_org_host(s, row)
        created += 1
        if actor:
            audit.record(
                s,
                actor,
                "tenant.ownership_host_backfilled",
                "tenant_ownership_host",
                row.id,
                tenant_id=tenant_id,
                hostname=host,
                token_suffix=ownership.token_fingerprint(token),
            )
    return created
