"""MongoDB-native user management (same rules/messages as ``users.service``).

Documents are dicts (``id`` == ``_id``). Tokens: only SHA-256 hashes are stored; links
are consumed atomically. Audit goes to the Mongo hash-chained audit log.
Also provides Mongo versions of ``auth.keys`` user/API-key helpers used by the CLI.
"""

from __future__ import annotations

import secrets
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

from attestra.auth.keys import Principal, generate_api_key, hash_api_key, hash_password, verify_password
from attestra.auth.roles import ROLES
from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo.repositories.core import MembershipRepository
from attestra.persistence.mongo.repositories.identity import (
    ApiKeyAdminRepository,
    InviteRepository,
    UserAdminRepository,
)
from attestra.persistence.mongo.repositories.ops import AuditRepository
from attestra.persistence.mongo.serialization import ensure_utc, utcnow
from attestra.persistence.mongo.tenant import TenantIds
from attestra.users.service import (
    _EMAIL,
    _USERNAME,
    ENGAGEMENT_ROLES,
    INVITE_TTL_HOURS,
    LEAD_INVITABLE,
    RESET_TTL_HOURS,
    UserAdminError,
    _require_admin,
    _require_manager,
    assignable_roles,
    hash_token,
    validate_password,
)


def _audit(db, actor, action, entity, entity_id, **details) -> None:
    AuditRepository(db).record(actor, action, entity, entity_id, **details)


def allowed_tenants(db, principal) -> TenantIds:
    from attestra.persistence.mongo.service_bridge import tenant_ids_for_principal

    return tenant_ids_for_principal(SimpleNamespace(db=db), principal)


def _users(db, principal=None) -> UserAdminRepository:
    return UserAdminRepository(db, tenant_ids=allowed_tenants(db, principal) if principal is not None else None)


def _get_user(db, principal, user_id: int) -> dict:
    user = _users(db, principal).get_visible(user_id)
    if user is None:
        raise LookupError(f"user {user_id} not found")
    return user


def _iso(v):
    return ensure_utc(v).isoformat() if v else None


# ---------------------------------------------------------------- listing


def list_users(db, principal, tenant_id: int | None = None) -> list[dict]:
    _require_manager(principal)
    names = {int(t["_id"]): t.get("name", "") for t in db[C.TENANTS].find({}, {"name": 1})}
    out = []
    for u in _users(db, principal).list_visible(tenant_id):
        tid = u.get("tenant_id")
        out.append({
            "id": u["id"], "username": u["username"], "display_name": u.get("display_name", ""), "role": u["role"],
            "status": "active" if u.get("active") else "disabled", "tenant_id": tid,
            "tenant": names.get(int(tid), "") if tid else "",
            "source": "sso" if u.get("password_hash") == "oidc" else "local",
            "last_login_at": _iso(u.get("last_login_at")), "created_at": _iso(u.get("created_at")),
        })
    return out


def list_invites(db, principal) -> list[dict]:
    _require_manager(principal)
    now = utcnow()
    return [
        {
            "id": i["id"], "purpose": i["purpose"], "email": i.get("email", ""), "role": i["role"],
            "tenant_id": i.get("tenant_id"), "engagement_id": i.get("engagement_id"), "user_id": i.get("user_id"),
            "created_by": i.get("created_by", ""), "expires_at": ensure_utc(i["expires_at"]).isoformat(),
            "expired": ensure_utc(i["expires_at"]) <= now,
        }
        for i in InviteRepository(db, tenant_ids=allowed_tenants(db, principal)).list_open()
    ]


# ---------------------------------------------------------------- invites and resets


def create_invite(db, principal, *, email: str, role: str, tenant_id: int | None = None,
                  engagement_id: int | None = None, ttl_hours: int | None = None) -> tuple[dict, str]:
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
        eng = db[C.ENGAGEMENTS].find_one({"_id": int(engagement_id)}, {"tenant_id": 1})
        if eng is None:
            raise LookupError(f"engagement {engagement_id} not found")
        if tenant_id is not None and int(tenant_id) != int(eng["tenant_id"]):
            raise UserAdminError("engagement belongs to a different tenant")
        tenant_id = int(eng["tenant_id"])
    if tenant_id is not None and db[C.TENANTS].find_one({"_id": int(tenant_id)}, {"_id": 1}) is None:
        raise LookupError(f"tenant {tenant_id} not found")
    allowed = allowed_tenants(db, principal)
    if allowed is not None and tenant_id not in allowed:
        raise UserAdminError("tenant not allowed for this user")
    if role == "client_viewer" and tenant_id is None:
        raise UserAdminError("client_viewer invites need a tenant or engagement")
    ttl = INVITE_TTL_HOURS if ttl_hours is None else int(ttl_hours)
    if ttl < 1 or ttl > 24 * 30:
        raise UserAdminError("ttl_hours must be between 1 and 720")
    raw = secrets.token_urlsafe(32)
    inv = InviteRepository(db, tenant_ids=allowed).create(
        purpose="invite", email=email, role=role, tenant_id=tenant_id, engagement_id=engagement_id,
        token_hash=hash_token(raw), created_by=principal.actor, expires_at=utcnow() + timedelta(hours=ttl))
    _audit(db, principal.actor, "user.invite", "user_invite", inv["id"], email=email, role=role,
           tenant_id=tenant_id, engagement_id=engagement_id, ttl_hours=ttl)
    return inv, raw


def create_reset(db, principal, user_id: int) -> tuple[dict, str]:
    _require_admin(principal)
    user = _get_user(db, principal, user_id)
    if user.get("password_hash") == "oidc":
        raise UserAdminError("SSO users reset their password in the identity provider")
    if not user.get("active"):
        raise UserAdminError("enable the user before resetting the password")
    invites = InviteRepository(db)
    invites.revoke_open_for_user(user["id"], purpose="reset")
    raw = secrets.token_urlsafe(32)
    inv = invites.create(purpose="reset", email="", role=user["role"], tenant_id=user.get("tenant_id"),
                         user_id=user["id"], token_hash=hash_token(raw), created_by=principal.actor,
                         expires_at=utcnow() + timedelta(hours=RESET_TTL_HOURS))
    _audit(db, principal.actor, "user.password_reset_issued", "user", user["id"], invite_id=inv["id"])
    return inv, raw


def revoke_invite(db, principal, invite_id: int) -> None:
    _require_manager(principal)
    repo = InviteRepository(db, tenant_ids=allowed_tenants(db, principal))
    inv = repo.get_scoped(invite_id)
    if inv is None:
        raise LookupError(f"invite {invite_id} not found")
    if principal.role != "admin" and inv["role"] not in LEAD_INVITABLE:
        raise UserAdminError("not allowed")
    if repo.revoke(invite_id):
        _audit(db, principal.actor, "user.invite_revoke", "user_invite", inv["id"])


def _valid(db, raw: str, purpose: str) -> dict:
    inv = InviteRepository(db).get_by_token_hash(hash_token(raw or ""))
    if inv is None or inv["purpose"] != purpose:
        raise UserAdminError("link is invalid")
    if inv.get("used_at") is not None:
        raise UserAdminError("link has already been used")
    if inv.get("revoked_at") is not None:
        raise UserAdminError("link has been revoked")
    if ensure_utc(inv["expires_at"]) <= utcnow():
        raise UserAdminError("link has expired")
    return inv


def peek(db, raw: str, purpose: str) -> dict:
    inv = _valid(db, raw, purpose)
    user = db[C.USERS].find_one({"_id": int(inv["user_id"])}) if inv.get("user_id") else None
    return {"email": inv.get("email", ""), "role": inv["role"], "username": user["username"] if user else ""}


def accept_invite(db, raw: str, *, username: str, password: str, display_name: str = "") -> dict:
    inv = _valid(db, raw, "invite")
    username = (username or "").strip().lower()
    if not _USERNAME.match(username):
        raise UserAdminError("username must be 3-100 characters: letters, digits, . _ @ -")
    users = UserAdminRepository(db)
    if users.find_by_username(username):
        raise UserAdminError("username is taken")
    validate_password(password, username)
    invites = InviteRepository(db)
    if not invites.consume(inv["id"]):  # claim first: single use under concurrency
        raise UserAdminError("link has already been used")
    from pymongo.errors import DuplicateKeyError

    try:
        user = users.create(username, password_hash=hash_password(password), role=inv["role"],
                            display_name=(display_name or "").strip()[:200] or username,
                            tenant_id=inv.get("tenant_id"), active=True)
    except DuplicateKeyError:
        db[C.USER_INVITES].update_one({"_id": inv["id"]}, {"$set": {"used_at": None}})
        raise UserAdminError("username is taken") from None
    db[C.USER_INVITES].update_one({"_id": inv["id"]}, {"$set": {"user_id": user["id"]}})
    if inv.get("tenant_id") is not None and inv["role"] not in ("client_viewer", "auditor"):
        MembershipRepository(db).ensure(user["id"], int(inv["tenant_id"]), inv["role"])
    _audit(db, username, "user.invite_accept", "user", user["id"], invite_id=inv["id"], role=inv["role"],
           tenant_id=inv.get("tenant_id"), engagement_id=inv.get("engagement_id"))
    return user


def complete_reset(db, raw: str, *, password: str) -> dict:
    inv = _valid(db, raw, "reset")
    users = UserAdminRepository(db)
    user = users.get_visible(int(inv["user_id"])) if inv.get("user_id") else None
    if user is None or not user.get("active"):
        raise UserAdminError("link is invalid")
    validate_password(password, user["username"])
    if not InviteRepository(db).consume(inv["id"]):
        raise UserAdminError("link has already been used")
    user = users.update_fields(user["id"], password_hash=hash_password(password))
    _audit(db, user["username"], "user.password_reset", "user", user["id"], invite_id=inv["id"])
    return user


def set_password(db, username: str, password: str, *, actor: str) -> dict:
    """Operator path (CLI)."""
    users = UserAdminRepository(db)
    user = users.find_by_username(username)
    if user is None:
        raise LookupError(f"user {(username or '').strip()!r} not found")
    if user.get("password_hash") == "oidc":
        raise UserAdminError("SSO users reset their password in the identity provider")
    validate_password(password, user["username"])
    user = users.update_fields(user["id"], password_hash=hash_password(password))
    InviteRepository(db).revoke_open_for_user(user["id"], purpose="reset")
    _audit(db, actor, "user.password_set", "user", user["id"], via="cli")
    return user


# ---------------------------------------------------------------- role and status


def set_role(db, principal, user_id: int, role: str) -> dict:
    _require_admin(principal)
    if role not in ROLES:
        raise UserAdminError(f"role must be one of {ROLES}")
    users = _users(db, principal)
    user = _get_user(db, principal, user_id)
    if user["role"] == role:
        return user
    if user["role"] == "admin" and user.get("active") and users.count_active_admins() <= 1:
        raise UserAdminError("cannot demote the last admin")
    old = user["role"]
    user = users.update_fields(user["id"], role=role)
    _audit(db, principal.actor, "user.role_change", "user", user["id"], old=old, new=role)
    return user


def set_active(db, principal, user_id: int, active: bool) -> dict:
    _require_manager(principal)
    users = _users(db, principal)
    user = _get_user(db, principal, user_id)
    if bool(user.get("active")) == bool(active):
        return user
    if principal.role == "lead" and user["role"] not in LEAD_INVITABLE:
        raise UserAdminError("not allowed: leads may only enable or disable tester, reviewer, or client_viewer")
    if not active and user["role"] == "admin" and users.count_active_admins() <= 1:
        raise UserAdminError("cannot disable the last admin")
    user = users.update_fields(user["id"], active=bool(active))
    if not active:
        InviteRepository(db).revoke_open_for_user(user["id"])
    _audit(db, principal.actor, "user.enable" if active else "user.disable", "user", user["id"])
    return user


def disable_by_username(db, principal, username: str) -> dict:
    user = UserAdminRepository(db).find_by_username(username)
    if user is None:
        raise LookupError(f"user {(username or '').strip()!r} not found")
    return set_active(db, principal, user["id"], False)


def tenants_for_form(db, principal) -> list[dict]:
    from attestra.persistence.mongo.tenant import tenant_filter

    q = tenant_filter("_id", allowed_tenants(db, principal))
    return [{**t, "id": t["_id"]} for t in db[C.TENANTS].find(q).sort("name", 1)]


def engagements_for_form(db, principal) -> list[dict]:
    from attestra.persistence.mongo.tenant import tenant_filter

    q = tenant_filter("tenant_id", allowed_tenants(db, principal))
    return [{**e, "id": e["_id"]} for e in db[C.ENGAGEMENTS].find(q).sort("_id", -1)]


# ---------------------------------------------------------------- auth.keys equivalents


def _principal(user: dict) -> Principal:
    return Principal(user_id=int(user["id"]), username=user["username"], display_name=user.get("display_name", ""),
                     role=user["role"], tenant_id=user.get("tenant_id"))


def create_user(db, *, username: str, role: str, password: str, display_name: str = "",
                tenant_id: int | None = None) -> dict:
    username = (username or "").strip().lower()
    if not username:
        raise ValueError("username required")
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    users = UserAdminRepository(db)
    if users.find_by_username(username):
        raise ValueError(f"user {username!r} already exists")
    return users.create(username, password_hash=hash_password(password), role=role,
                        display_name=display_name or username, tenant_id=tenant_id, active=True)


def create_api_key(db, user: dict) -> tuple[dict, str]:
    raw = generate_api_key()
    row = ApiKeyAdminRepository(db).create(int(user["id"]), hash_api_key(raw), raw[:8])
    row.pop("key_hash", None)
    return row, raw


def list_api_keys(db, *, username: str | None = None) -> list[dict[str, Any]]:
    return ApiKeyAdminRepository(db).list_public(username=username)


def revoke_api_key(db, key_id: int, *, actor: str = "cli") -> dict:
    repo = ApiKeyAdminRepository(db)
    existing = db[C.API_KEYS].find_one({"_id": int(key_id)})
    if not existing:
        raise LookupError(f"api key {key_id} not found")
    if existing.get("revoked_at") is not None:
        return {**existing, "id": existing["_id"]}
    row = repo.revoke(key_id) or {**existing, "id": existing["_id"]}
    _audit(db, actor, "api_key.revoke", "api_key", row["id"], user_id=row["user_id"], prefix=row.get("prefix", ""))
    return row


def authenticate_api_key(db, raw_key: str) -> Principal | None:
    if not raw_key or not raw_key.strip():
        return None
    repo = ApiKeyAdminRepository(db)
    row = repo.get_by_hash(hash_api_key(raw_key.strip()))
    if row is None or row.get("revoked_at") is not None:
        return None
    user = db[C.USERS].find_one({"_id": int(row["user_id"])})
    if user is None or not user.get("active"):
        return None
    repo.touch_last_used(row["id"])
    return _principal({**user, "id": user["_id"]})


def authenticate_password(db, username: str, password: str) -> Principal | None:
    users = UserAdminRepository(db)
    user = db[C.USERS].find_one({"username": (username or "").strip().lower()})
    if user is None or not user.get("active"):
        return None
    if not verify_password(password, user.get("password_hash", "")):
        return None
    users.touch_login(user["_id"])
    return _principal({**user, "id": user["_id"]})
