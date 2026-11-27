"""Customer self-service registration (public signup).

Creates a new organization (tenant) and a tenant-scoped ``lead`` user. Never
creates platform ``admin``. Reuses password policy, tenant uniqueness, credit
account bootstrap, and the existing SMTP mailer.
"""
# @lat: [[interfaces#Customer self-service registration]]

from __future__ import annotations

import logging
import os
import re
from typing import Any

from attestra.auth.keys import hash_password
from attestra.auth.roles import ROLES
from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo.repositories.core import MembershipRepository, TenantRepository
from attestra.persistence.mongo.repositories.identity import UserAdminRepository
from attestra.users.service import MIN_PASSWORD_LENGTH, UserAdminError, validate_password

log = logging.getLogger(__name__)

# Public signup always assigns this role — never admin / reviewer / tester via this path.
SELF_SERVICE_ROLE = "lead"
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USERNAME = re.compile(r"^[a-z0-9][a-z0-9._@-]{2,99}$")
_ORG_NAME = re.compile(r"^[\w .,'&()/+-]{2,200}$", re.UNICODE)


def self_service_registration_enabled() -> bool:
    """True when ``ATTESTRA_CUSTOMER_SELF_SERVICE_REGISTRATION`` allows public signup.

    Default **on** (``1``). Set to ``0`` / ``false`` / ``off`` to hide routes and reject posts.
    """
    raw = (os.environ.get("ATTESTRA_CUSTOMER_SELF_SERVICE_REGISTRATION") or "1").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _require_enabled() -> None:
    if not self_service_registration_enabled():
        raise UserAdminError("customer self-service registration is disabled")


def _norm_username(username: str) -> str:
    name = (username or "").strip().lower()
    if not _USERNAME.match(name):
        raise UserAdminError("username must be 3-100 characters: letters, digits, . _ @ -")
    return name


def _norm_email(email: str) -> str:
    value = (email or "").strip().lower()
    if not value or not _EMAIL.match(value):
        raise UserAdminError("a valid email address is required")
    if len(value) > 254:
        raise UserAdminError("email is too long")
    return value


def _norm_org(name: str) -> str:
    value = (name or "").strip()
    if len(value) < 2:
        raise UserAdminError("organization name is required")
    if len(value) > 200:
        raise UserAdminError("organization name is too long")
    if not _ORG_NAME.match(value):
        raise UserAdminError("organization name has invalid characters")
    return value


def register_customer(
    db,
    *,
    username: str,
    password: str,
    email: str,
    organization_name: str,
    display_name: str = "",
    contact_name: str = "",
) -> dict[str, Any]:
    """Create a new tenant + lead user for public customer signup.

    Returns ``{user, tenant, emailed}``. Raises [[UserAdminError]] on validation
    or duplicate conflicts. Welcome email is best-effort (failures are logged, not raised).
    """
    _require_enabled()
    if SELF_SERVICE_ROLE not in ROLES or SELF_SERVICE_ROLE == "admin":
        raise UserAdminError("self-service role is misconfigured")

    username = _norm_username(username)
    email = _norm_email(email)
    org_name = _norm_org(organization_name)
    display = (display_name or "").strip()[:200] or username
    contact = (contact_name or "").strip()[:200] or display
    validate_password(password, username)

    from attestra.persistence.mongo.tenant import SYSTEM_SCOPE

    users = UserAdminRepository(db, tenant_ids=SYSTEM_SCOPE)
    if users.find_by_username(username):
        raise UserAdminError("username is taken")

    tenants = TenantRepository(db, tenant_ids=SYSTEM_SCOPE)  # unscoped operator path
    if db[C.TENANTS].find_one({"name": org_name}):
        raise UserAdminError("organization name is already registered")

    # Soft duplicate email guard across tenant contacts (email is not a User column).
    if db[C.TENANTS].find_one({"contact_email": email}):
        raise UserAdminError("an organization with this email is already registered")

    from pymongo.errors import DuplicateKeyError

    try:
        tenant = tenants.create(
            org_name,
            contact_name=contact,
            contact_email=email,
            plan="standard",
        )
    except DuplicateKeyError as exc:
        raise UserAdminError("organization name is already registered") from exc

    # Bootstrap organization test-run credits (existing subscription infrastructure).
    try:
        from attestra.persistence.mongo.adapters import mongo_credit_account

        mongo_credit_account(int(tenant["id"]))
    except Exception:  # noqa: BLE001 — account can be created lazily on first use
        log.warning("credit account bootstrap deferred for tenant %s", tenant.get("id"))

    try:
        user = users.create(
            username,
            password_hash=hash_password(password),
            role=SELF_SERVICE_ROLE,
            display_name=display,
            tenant_id=int(tenant["id"]),
            active=True,
        )
    except DuplicateKeyError as exc:
        # Roll back the empty tenant if user create races.
        db[C.TENANTS].delete_one({"_id": int(tenant["id"])})
        raise UserAdminError("username is taken") from exc

    MembershipRepository(db, tenant_ids=SYSTEM_SCOPE).ensure(
        int(user["id"]), int(tenant["id"]), SELF_SERVICE_ROLE
    )

    from attestra.users.mongo_service import _audit

    _audit(
        db,
        username,
        "user.self_register",
        "user",
        user["id"],
        tenant_id=int(tenant["id"]),
        role=SELF_SERVICE_ROLE,
        organization=org_name,
    )
    _audit(
        db,
        username,
        "tenant.create",
        "tenant",
        int(tenant["id"]),
        name=org_name,
        via="self_service",
    )

    emailed = False
    try:
        from attestra.users import mailer

        emailed = bool(
            mailer.send_welcome(
                email,
                username=username,
                organization_name=org_name,
                display_name=display,
            )
        )
    except Exception:  # noqa: BLE001 — never fail registration on mail
        log.exception("welcome email failed for user %s", username)
        emailed = False

    return {"user": user, "tenant": tenant, "emailed": emailed, "email": email}
