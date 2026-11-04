"""API keys and password hashing (scrypt)."""
# @lat: [[authorization#Identity]]

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import config
from attestra.models import ApiKey, User, utcnow


@dataclass(frozen=True)
class Principal:
    user_id: int
    username: str
    display_name: str
    role: str
    tenant_id: int | None
    """Home tenant for client users; staff may be None and use memberships."""

    @property
    def actor(self) -> str:
        return self.username


def _pepper() -> bytes:
    from attestra.secret_store import get_secret

    return get_secret("api_key_pepper", config.API_KEY_PEPPER).encode("utf-8")


def hash_api_key(raw_key: str) -> str:
    return hmac.new(_pepper(), raw_key.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_hex, hash_hex = stored.split("$", 2)
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return hmac.compare_digest(dk.hex(), hash_hex)


def create_user(
    s: Session,
    *,
    username: str,
    role: str,
    password: str,
    display_name: str = "",
    tenant_id: int | None = None,
) -> User:
    from attestra.auth.roles import ROLES

    username = username.strip().lower()
    if not username:
        raise ValueError("username required")
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if s.scalar(select(User).where(User.username == username)):
        raise ValueError(f"user {username!r} already exists")
    user = User(
        username=username,
        display_name=display_name or username,
        password_hash=hash_password(password),
        role=role,
        tenant_id=tenant_id,
        active=True,
    )
    s.add(user)
    s.flush()
    return user


def create_api_key(s: Session, user: User) -> tuple[ApiKey, str]:
    raw = generate_api_key()
    prefix = raw[:8]
    row = ApiKey(user_id=user.id, key_hash=hash_api_key(raw), prefix=prefix)
    s.add(row)
    s.flush()
    return row, raw


def list_api_keys(s: Session, *, username: str | None = None) -> list[dict]:
    """Return API key rows (id, user, prefix, timestamps). Never includes the secret."""
    q = select(ApiKey, User).join(User, ApiKey.user_id == User.id).order_by(ApiKey.id)
    if username:
        q = q.where(User.username == username.strip().lower())
    out = []
    for key, user in s.execute(q):
        out.append({
            "id": key.id,
            "user_id": user.id,
            "username": user.username,
            "prefix": key.prefix,
            "created_at": key.created_at.isoformat() if key.created_at else None,
            "revoked_at": key.revoked_at.isoformat() if key.revoked_at else None,
            "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
            "status": "revoked" if key.revoked_at is not None else "active",
        })
    return out


def revoke_api_key(s: Session, key_id: int, *, actor: str = "cli") -> ApiKey:
    """Revoke an API key and write an ``api_key.revoke`` audit row."""
    from attestra import audit

    row = s.get(ApiKey, key_id)
    if not row:
        raise LookupError(f"api key {key_id} not found")
    if row.revoked_at is not None:
        return row
    row.revoked_at = utcnow()
    audit.record(s, actor, "api_key.revoke", "api_key", row.id, user_id=row.user_id, prefix=row.prefix)
    return row


def authenticate_api_key(s: Session, raw_key: str) -> Principal | None:
    if not raw_key or not raw_key.strip():
        return None
    digest = hash_api_key(raw_key.strip())
    row = s.scalar(select(ApiKey).where(ApiKey.key_hash == digest))
    if row is None or row.revoked_at is not None:
        return None
    user = s.get(User, row.user_id)
    if user is None or not user.active:
        return None
    row.last_used_at = utcnow()
    return Principal(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
        role=user.role,
        tenant_id=user.tenant_id,
    )


def authenticate_password(s: Session, username: str, password: str) -> Principal | None:
    user = s.scalar(select(User).where(User.username == username.strip().lower()))
    if user is None or not user.active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    user.last_login_at = utcnow()
    return Principal(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
        role=user.role,
        tenant_id=user.tenant_id,
    )
