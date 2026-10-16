"""User management service: invites, password resets, role and status changes.

Tokens are random, single-use and time-limited; only their SHA-256 hash is stored.
Every change is written to the hash-chained audit log.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from attestra import audit, services
from attestra.auth.keys import hash_password
from attestra.auth.roles import ROLES
from attestra.models import Engagement, Tenant, TenantMembership, User, UserInvite, utcnow

INVITE_TTL_HOURS = int(os.environ.get("ATTESTRA_INVITE_TTL_HOURS", "72"))
RESET_TTL_HOURS = int(os.environ.get("ATTESTRA_RESET_TTL_HOURS", "24"))
MIN_PASSWORD_LENGTH = 12
MANAGER_ROLES = frozenset({"admin", "lead"})
LEAD_INVITABLE = frozenset({"tester", "reviewer", "client_viewer"})
ENGAGEMENT_ROLES = frozenset({"client_viewer", "auditor"})
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USERNAME = re.compile(r"^[a-z0-9][a-z0-9._@-]{2,99}$")


class UserAdminError(services.ServiceError):
    """A user-management request that breaks a rule."""


# ---------------------------------------------------------------- helpers


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def validate_password(password: str, username: str = "") -> None:
    """Password policy: at least 12 characters, not the username, not one repeated character."""
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise UserAdminError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if username and password.strip().lower() == username.strip().lower():
        raise UserAdminError("password must not equal the username")
    if len(set(password)) < 4:
        raise UserAdminError("password is too simple")


def assignable_roles(principal) -> tuple[str, ...]:
    if principal.role == "admin":
        return ROLES
    if principal.role == "lead":
        return tuple(r for r in ROLES if r in LEAD_INVITABLE)
    return ()


def _require_manager(principal) -> None:
    if principal is None or principal.role not in MANAGER_ROLES:
        raise UserAdminError("user management not allowed for this role")


def _require_admin(principal) -> None:
    if principal is None or principal.role != "admin":
        raise UserAdminError("only an admin may do this (not allowed)")


def _user_tenants(s: Session, user: User) -> set[int]:
    ids = {m.tenant_id for m in s.scalars(select(TenantMembership).where(TenantMembership.user_id == user.id))}
    if user.tenant_id is not None:
        ids.add(user.tenant_id)
    return ids


def _in_scope(s: Session, principal, user: User) -> bool:
    allowed = services.tenant_ids_for(s, principal)
    return allowed is None or bool(_user_tenants(s, user) & allowed)


def _active_admins(s: Session) -> int:
    return s.scalar(select(func.count(User.id)).where(User.role == "admin", User.active.is_(True))) or 0


def _get_user(s: Session, principal, user_id: int) -> User:
    user = s.get(User, user_id)
    if user is None or not _in_scope(s, principal, user):
        raise LookupError(f"user {user_id} not found")
    return user


# ---------------------------------------------------------------- listing


def list_users(s: Session, principal, tenant_id: int | None = None) -> list[dict]:
    _require_manager(principal)
    allowed = services.tenant_ids_for(s, principal)
    q = select(User).order_by(User.username)
    if tenant_id is not None:
        if allowed is not None and tenant_id not in allowed:
            return []
        member = select(TenantMembership.user_id).where(TenantMembership.tenant_id == tenant_id)
        q = q.where(or_(User.tenant_id == tenant_id, User.id.in_(member)))
    elif allowed is not None:
        member = select(TenantMembership.user_id).where(TenantMembership.tenant_id.in_(allowed))
        q = q.where(or_(User.tenant_id.in_(allowed), User.id.in_(member)))
    names = {t.id: t.name for t in s.scalars(select(Tenant))}
    out = []
    for u in s.scalars(q):
        out.append({
            "id": u.id,
            "username": u.username,
            "display_name": u.display_name,
            "role": u.role,
            "status": "active" if u.active else "disabled",
            "tenant_id": u.tenant_id,
            "tenant": names.get(u.tenant_id, "") if u.tenant_id else "",
            "source": "sso" if u.password_hash == "oidc" else "local",
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        })
    return out


def list_invites(s: Session, principal) -> list[dict]:
    _require_manager(principal)
    allowed = services.tenant_ids_for(s, principal)
    q = select(UserInvite).where(UserInvite.used_at.is_(None), UserInvite.revoked_at.is_(None))
    if allowed is not None:
        q = q.where(UserInvite.tenant_id.in_(allowed))
    now = utcnow()
    return [
        {
            "id": i.id,
            "purpose": i.purpose,
            "email": i.email,
            "role": i.role,
            "tenant_id": i.tenant_id,
            "engagement_id": i.engagement_id,
            "user_id": i.user_id,
            "created_by": i.created_by,
            "expires_at": _aware(i.expires_at).isoformat(),
            "expired": _aware(i.expires_at) <= now,
        }
        for i in s.scalars(q.order_by(UserInvite.id.desc()))
    ]


# ---------------------------------------------------------------- invites and resets


def create_invite(
    s: Session,
    principal,
    *,
    email: str,
    role: str,
    tenant_id: int | None = None,
    engagement_id: int | None = None,
    ttl_hours: int | None = None,
) -> tuple[UserInvite, str]:
    _require_manager(principal)
    email = (email or "").strip().lower()
    if not _EMAIL.match(email):
        raise UserAdminError("a valid email is required")
    if role not in ROLES:
        raise UserAdminError(f"role must be one of {ROLES}")
    if role not in assignable_roles(principal):
        raise UserAdminError(f"role {role!r} not allowed for {principal.role}")
    if engagement_id is not None:
        if role not in ENGAGEMENT_ROLES:
            raise UserAdminError("an engagement applies only to client_viewer or auditor invites")
        eng = s.get(Engagement, engagement_id)
        if eng is None:
            raise LookupError(f"engagement {engagement_id} not found")
        if tenant_id is not None and tenant_id != eng.tenant_id:
            raise UserAdminError("engagement belongs to a different tenant")
        tenant_id = eng.tenant_id
    if tenant_id is not None and s.get(Tenant, tenant_id) is None:
        raise LookupError(f"tenant {tenant_id} not found")
    allowed = services.tenant_ids_for(s, principal)
    if allowed is not None and tenant_id not in allowed:
        raise UserAdminError("tenant not allowed for this user")
    if role == "client_viewer" and tenant_id is None:
        raise UserAdminError("client_viewer invites need a tenant or engagement")
    ttl = INVITE_TTL_HOURS if ttl_hours is None else int(ttl_hours)
    if ttl < 1 or ttl > 24 * 30:
        raise UserAdminError("ttl_hours must be between 1 and 720")
    raw = secrets.token_urlsafe(32)
    inv = UserInvite(
        purpose="invite", email=email, role=role, tenant_id=tenant_id, engagement_id=engagement_id,
        token_hash=hash_token(raw), created_by=principal.actor, expires_at=utcnow() + timedelta(hours=ttl),
    )
    s.add(inv)
    s.flush()
    audit.record(s, principal.actor, "user.invite", "user_invite", inv.id, email=email, role=role,
                 tenant_id=tenant_id, engagement_id=engagement_id, ttl_hours=ttl)
    return inv, raw


def create_reset(s: Session, principal, user_id: int) -> tuple[UserInvite, str]:
    _require_admin(principal)
    user = _get_user(s, principal, user_id)
    if user.password_hash == "oidc":
        raise UserAdminError("SSO users reset their password in the identity provider")
    if not user.active:
        raise UserAdminError("enable the user before resetting the password")
    now = utcnow()
    for old in s.scalars(select(UserInvite).where(UserInvite.user_id == user.id, UserInvite.purpose == "reset",
                                                  UserInvite.used_at.is_(None), UserInvite.revoked_at.is_(None))):
        old.revoked_at = now
    raw = secrets.token_urlsafe(32)
    inv = UserInvite(
        purpose="reset", email="", role=user.role, tenant_id=user.tenant_id, user_id=user.id,
        token_hash=hash_token(raw), created_by=principal.actor, expires_at=now + timedelta(hours=RESET_TTL_HOURS),
    )
    s.add(inv)
    s.flush()
    audit.record(s, principal.actor, "user.password_reset_issued", "user", user.id, invite_id=inv.id)
    return inv, raw


def revoke_invite(s: Session, principal, invite_id: int) -> None:
    _require_manager(principal)
    inv = s.get(UserInvite, invite_id)
    allowed = services.tenant_ids_for(s, principal)
    if inv is None or (allowed is not None and inv.tenant_id not in allowed):
        raise LookupError(f"invite {invite_id} not found")
    if principal.role != "admin" and inv.role not in LEAD_INVITABLE:
        raise UserAdminError("not allowed")
    if inv.used_at is None and inv.revoked_at is None:
        inv.revoked_at = utcnow()
        audit.record(s, principal.actor, "user.invite_revoke", "user_invite", inv.id)


def _valid(s: Session, raw: str, purpose: str) -> UserInvite:
    inv = s.scalar(select(UserInvite).where(UserInvite.token_hash == hash_token(raw or "")))
    if inv is None or inv.purpose != purpose:
        raise UserAdminError("link is invalid")
    if inv.used_at is not None:
        raise UserAdminError("link has already been used")
    if inv.revoked_at is not None:
        raise UserAdminError("link has been revoked")
    if _aware(inv.expires_at) <= utcnow():
        raise UserAdminError("link has expired")
    return inv


def peek(s: Session, raw: str, purpose: str) -> dict:
    inv = _valid(s, raw, purpose)
    user = s.get(User, inv.user_id) if inv.user_id else None
    return {"email": inv.email, "role": inv.role, "username": user.username if user else ""}


def accept_invite(s: Session, raw: str, *, username: str, password: str, display_name: str = "") -> User:
    inv = _valid(s, raw, "invite")
    username = (username or "").strip().lower()
    if not _USERNAME.match(username):
        raise UserAdminError("username must be 3-100 characters: letters, digits, . _ @ -")
    if s.scalar(select(User).where(User.username == username)):
        raise UserAdminError("username is taken")
    validate_password(password, username)
    user = User(username=username, display_name=(display_name or "").strip()[:200] or username,
                password_hash=hash_password(password), role=inv.role, tenant_id=inv.tenant_id, active=True)
    s.add(user)
    s.flush()
    if inv.tenant_id is not None and inv.role not in ("client_viewer", "auditor"):
        s.add(TenantMembership(user_id=user.id, tenant_id=inv.tenant_id, role=inv.role))
    inv.used_at = utcnow()
    inv.user_id = user.id
    audit.record(s, username, "user.invite_accept", "user", user.id, invite_id=inv.id, role=inv.role,
                 tenant_id=inv.tenant_id, engagement_id=inv.engagement_id)
    return user


def complete_reset(s: Session, raw: str, *, password: str) -> User:
    inv = _valid(s, raw, "reset")
    user = s.get(User, inv.user_id) if inv.user_id else None
    if user is None or not user.active:
        raise UserAdminError("link is invalid")
    validate_password(password, user.username)
    user.password_hash = hash_password(password)
    inv.used_at = utcnow()
    audit.record(s, user.username, "user.password_reset", "user", user.id, invite_id=inv.id)
    return user


def set_password(s: Session, username: str, password: str, *, actor: str) -> User:
    """Operator path (CLI): set a local user's password directly. Same policy as resets; audited."""
    name = (username or "").strip()
    user = s.scalar(select(User).where(User.username == name)) or s.scalar(
        select(User).where(func.lower(User.username) == name.lower())
    )
    if user is None:
        raise LookupError(f"user {name!r} not found")
    if user.password_hash == "oidc":
        raise UserAdminError("SSO users reset their password in the identity provider")
    validate_password(password, user.username)
    user.password_hash = hash_password(password)
    now = utcnow()
    for old in s.scalars(select(UserInvite).where(UserInvite.user_id == user.id, UserInvite.purpose == "reset",
                                                  UserInvite.used_at.is_(None), UserInvite.revoked_at.is_(None))):
        old.revoked_at = now
    audit.record(s, actor, "user.password_set", "user", user.id, via="cli")
    return user


# ---------------------------------------------------------------- role and status


def set_role(s: Session, principal, user_id: int, role: str) -> User:
    _require_admin(principal)
    if role not in ROLES:
        raise UserAdminError(f"role must be one of {ROLES}")
    user = _get_user(s, principal, user_id)
    if user.role == role:
        return user
    if user.role == "admin" and user.active and _active_admins(s) <= 1:
        raise UserAdminError("cannot demote the last admin")
    old = user.role
    user.role = role
    audit.record(s, principal.actor, "user.role_change", "user", user.id, old=old, new=role)
    return user


def set_active(s: Session, principal, user_id: int, active: bool) -> User:
    _require_admin(principal)
    user = _get_user(s, principal, user_id)
    if user.active == active:
        return user
    if not active and user.role == "admin" and _active_admins(s) <= 1:
        raise UserAdminError("cannot disable the last admin")
    user.active = active
    if not active:
        for inv in s.scalars(select(UserInvite).where(UserInvite.user_id == user.id, UserInvite.used_at.is_(None),
                                                      UserInvite.revoked_at.is_(None))):
            inv.revoked_at = utcnow()
    audit.record(s, principal.actor, "user.enable" if active else "user.disable", "user", user.id)
    return user


def tenants_for_form(s: Session, principal) -> list[Tenant]:
    allowed = services.tenant_ids_for(s, principal)
    q = select(Tenant).order_by(Tenant.name)
    if allowed is not None:
        q = q.where(Tenant.id.in_(allowed))
    return list(s.scalars(q))


def engagements_for_form(s: Session, principal) -> list[Engagement]:
    allowed = services.tenant_ids_for(s, principal)
    q = select(Engagement).order_by(Engagement.id.desc())
    if allowed is not None:
        q = q.where(Engagement.tenant_id.in_(allowed))
    return list(s.scalars(q))
