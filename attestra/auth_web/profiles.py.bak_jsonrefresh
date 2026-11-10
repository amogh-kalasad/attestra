"""Auth credential profile service: metadata + opaque secret_ref only."""
# @lat: [[interfaces#Auth-web credential profiles]]
# @lat: [[architecture#Authenticated website testing]]

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, credentials, services
from attestra.auth.roles import has_permission
from attestra.models import (
    AUTH_METHODS,
    AUTH_PROFILE_STATUSES,
    AuthCredentialProfile,
    utcnow,
)

_SSO_NOTE = (
    "SSO/MFA bootstrap is blocked: complete interactive SSO outside Attestra, "
    "then use a session cookie or header profile. Never bypass MFA or SSO."
)
_PENDING_NOTE = "Low-impact validation only; live login target not exercised."
_NONE_NOTE = "method=none: no secret required; marked valid."


def _actor_name(actor: str | None, principal) -> str:
    if actor and str(actor).strip():
        return str(actor).strip()
    if principal is not None:
        return getattr(principal, "actor", None) or getattr(principal, "username", "") or "unknown"
    return "unknown"


def _check_read(principal) -> None:
    role = getattr(principal, "role", None) if principal is not None else None
    if not has_permission(role or "", "engagement.read"):
        raise services.ServiceError("not allowed to read auth credential profiles")


def _check_write(principal) -> None:
    role = getattr(principal, "role", None) if principal is not None else None
    if not has_permission(role or "", "engagement.write"):
        raise services.ServiceError("not allowed to manage auth credential profiles")


def _eng(s: Session, engagement_id: int, principal) -> Any:
    return services.get_engagement(s, engagement_id, principal)


def _get_profile(s: Session, engagement_id: int, profile_id: int, principal) -> AuthCredentialProfile:
    eng = _eng(s, engagement_id, principal)
    row = s.get(AuthCredentialProfile, profile_id)
    if row is None or row.engagement_id != eng.id or row.tenant_id != eng.tenant_id:
        raise LookupError(f"auth profile {profile_id} not found")
    return row


def _truncate_ref(secret_ref: str) -> str:
    ref = (secret_ref or "").strip()
    if not ref:
        return ""
    if len(ref) <= 16:
        return ref[:4] + "…" if len(ref) > 4 else "…"
    return f"{ref[:8]}…{ref[-6:]}"


def profile_dict(row: AuthCredentialProfile) -> dict:
    """Public serializer: metadata only — never plaintext secrets."""
    ref = (row.secret_ref or "").strip()
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "engagement_id": row.engagement_id,
        "asset_id": row.asset_id,
        "label": row.label or "",
        "role_name": row.role_name or "",
        "purpose": row.purpose or "",
        "method": row.method or "",
        "login_url": row.login_url or "",
        "username_selector": row.username_selector or "",
        "password_selector": row.password_selector or "",
        "submit_selector": row.submit_selector or "",
        "success_url_contains": row.success_url_contains or "",
        "has_secret": bool(ref),
        "secret_ref": _truncate_ref(ref),
        "config": dict(row.config_json or {}),
        "extra_headers": getattr(row, "extra_headers", "") or "",
        # Extra cookies are secret: only whether they exist + their NAMES, never values.
        "has_extra_cookies": bool((getattr(row, "extra_cookies_ref", "") or "").strip()),
        "extra_cookie_names": [
            n.strip() for n in (getattr(row, "extra_cookie_names", "") or "").split(",") if n.strip()
        ],
        "status": row.status or "",
        "last_validated_at": row.last_validated_at.isoformat() if row.last_validated_at else None,
        "last_validation_note": row.last_validation_note or "",
        "created_by": row.created_by or "",
        "updated_by": row.updated_by or "",
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def list_profiles(s: Session, engagement_id: int, principal) -> list[AuthCredentialProfile]:
    """Tenant-scoped list of auth credential profiles for an engagement."""
    _check_read(principal)
    eng = _eng(s, engagement_id, principal)
    return list(
        s.scalars(
            select(AuthCredentialProfile)
            .where(
                AuthCredentialProfile.engagement_id == eng.id,
                AuthCredentialProfile.tenant_id == eng.tenant_id,
            )
            .order_by(AuthCredentialProfile.id)
        )
    )


def create_profile(
    s: Session,
    engagement_id: int,
    *,
    label: str,
    role_name: str = "",
    purpose: str = "",
    method: str = "form",
    login_url: str = "",
    username_selector: str = "",
    password_selector: str = "",
    submit_selector: str = "",
    success_url_contains: str = "",
    secret_value: str | None = None,
    secret_ref: str | None = None,
    asset_id: int | None = None,
    config_json: dict | None = None,
    extra_headers: str | None = None,
    extra_cookies: str | None = None,
    actor: str | None = None,
    principal=None,
) -> AuthCredentialProfile:
    """Create a profile. Persist only ``secret_ref``; store plaintext via credentials.put_secret."""
    _check_write(principal)
    eng = _eng(s, engagement_id, principal)
    method = (method or "form").strip().lower()
    if method not in AUTH_METHODS:
        raise services.ServiceError(f"method must be one of {', '.join(AUTH_METHODS)}")
    label = (label or "").strip()
    if not label:
        raise services.ServiceError("label is required")
    if len(label) > 200:
        raise services.ServiceError("label must be at most 200 characters")

    if secret_value is not None and secret_ref is not None and str(secret_ref).strip():
        raise services.ServiceError("provide secret_value or secret_ref, not both")
    extra_text = _clean_extra_headers(extra_headers, method, config_json)
    cookie_pairs = _clean_extra_cookies(extra_cookies, method, config_json)

    stored_ref = ""
    if secret_value is not None:
        value = str(secret_value)
        if not value:
            raise services.ServiceError("secret_value must be a non-empty string when provided")
        if method == "none":
            raise services.ServiceError("method=none does not accept a secret")
        stored_ref = credentials.put_secret(eng.tenant_id, eng.id, label, value)
    elif secret_ref is not None and str(secret_ref).strip():
        stored_ref = str(secret_ref).strip()
        from attestra.credentials.store import parse_secret_ref
        from attestra.secret_store import SecretsError

        try:
            tid, eid, _ = parse_secret_ref(stored_ref)
        except SecretsError as exc:
            raise services.ServiceError("invalid secret_ref") from exc
        if tid != eng.tenant_id or eid != eng.id:
            raise services.ServiceError("secret_ref does not belong to this engagement")
    elif method != "none":
        raise services.ServiceError("secret_value or secret_ref is required for this method")

    if asset_id is not None:
        from attestra.models import Asset

        asset = s.get(Asset, asset_id)
        if asset is None or asset.engagement_id != eng.id:
            raise LookupError(f"asset {asset_id} not found on engagement")

    xc_ref = ""
    if cookie_pairs:
        xc_ref = credentials.put_secret(
            eng.tenant_id, eng.id, f"{label} (extra cookies)", _cookie_secret_text(cookie_pairs)
        )

    who = _actor_name(actor, principal)
    now = utcnow()
    row = AuthCredentialProfile(
        tenant_id=eng.tenant_id,
        engagement_id=eng.id,
        asset_id=asset_id,
        label=label,
        role_name=(role_name or "").strip()[:100],
        purpose=(purpose or "").strip(),
        method=method,
        login_url=(login_url or "").strip()[:1000],
        username_selector=(username_selector or "").strip()[:300],
        password_selector=(password_selector or "").strip()[:300],
        submit_selector=(submit_selector or "").strip()[:300],
        success_url_contains=(success_url_contains or "").strip()[:500],
        secret_ref=stored_ref,
        config_json=dict(config_json or {}),
        extra_headers=extra_text,
        extra_cookies_ref=xc_ref,
        extra_cookie_names=_cookie_names_text(cookie_pairs),
        status="pending",
        last_validation_note="",
        created_by=who,
        updated_by=who,
        created_at=now,
        updated_at=now,
    )
    s.add(row)
    s.flush()
    audit.record(
        s,
        who,
        "auth_profile.create",
        "auth_credential_profile",
        row.id,
        engagement_id=eng.id,
        label=row.label,
        method=row.method,
        has_secret=bool(stored_ref),
        extra_header_names=_extra_names(extra_text),
        extra_cookie_names=[k for k, _ in cookie_pairs],
    )
    return row


def _clean_extra_headers(text: str | None, method: str | None, cfg: dict | None) -> str:
    """Validate + normalize the extra headers text (ServiceError on bad input)."""
    from attestra.auth_web import extra_headers as xh

    try:
        return xh.normalize_extra_headers(text, own_header_name=xh.own_header_name(method, cfg))
    except xh.ExtraHeadersError as exc:
        raise services.ServiceError(str(exc)) from exc


def _extra_names(text: str) -> list[str]:
    """Header NAMES only (for audit detail); values are never recorded."""
    from attestra.auth_web import extra_headers as xh

    try:
        return [k for k, _ in xh.parse_extra_headers(text)]
    except xh.ExtraHeadersError:
        return []


def update_extra_headers(
    s: Session,
    engagement_id: int,
    profile_id: int,
    *,
    extra_headers: str | None,
    principal,
    actor: str | None = None,
) -> AuthCredentialProfile:
    """Replace a profile's non-secret extra headers (empty text clears them)."""
    _check_write(principal)
    row = _get_profile(s, engagement_id, profile_id, principal)
    if row.status == "revoked":
        raise services.ServiceError("not allowed: profile is revoked")
    text = _clean_extra_headers(extra_headers, row.method, row.config_json)
    who = _actor_name(actor, principal)
    row.extra_headers = text
    row.updated_by = who
    row.updated_at = utcnow()
    s.flush()
    audit.record(
        s,
        who,
        "auth_profile.extra_headers",
        "auth_credential_profile",
        row.id,
        engagement_id=engagement_id,
        extra_header_names=_extra_names(text),
    )
    return row



def _clean_extra_cookies(text: str | None, method: str | None, cfg: dict | None) -> list[tuple[str, str]]:
    """Validate the extra cookies text (ServiceError with a value-free message)."""
    from attestra.auth_web import extra_cookies as xc

    try:
        pairs = xc.parse_extra_cookies(text)
    except xc.ExtraCookiesError as exc:
        raise services.ServiceError(str(exc)) from exc
    m = (method or "").strip().lower()
    if pairs and m in ("none", "sso_bootstrap"):
        raise services.ServiceError(f"extra cookies are not used by method={m}")
    own = xc.own_cookie_name(m, cfg)
    if own and own in {k for k, _ in pairs}:
        raise services.ServiceError(f"extra cookie '{own}' duplicates the profile's session cookie")
    return pairs


def _cookie_secret_text(pairs: list[tuple[str, str]]) -> str:
    return "; ".join(f"{k}={v}" for k, v in pairs)


def _cookie_names_text(pairs: list[tuple[str, str]]) -> str:
    return ", ".join(k for k, _ in pairs)[:1200]


def update_extra_cookies(
    s: Session,
    engagement_id: int,
    profile_id: int,
    *,
    extra_cookies: str | None,
    principal,
    actor: str | None = None,
) -> AuthCredentialProfile:
    """Replace a profile's ENCRYPTED extra cookies (empty text clears them).

    Values go only to the credential store; the row keeps the opaque ref + names.
    """
    _check_write(principal)
    row = _get_profile(s, engagement_id, profile_id, principal)
    if row.status == "revoked":
        raise services.ServiceError("not allowed: profile is revoked")
    pairs = _clean_extra_cookies(extra_cookies, row.method, row.config_json)
    old = (getattr(row, "extra_cookies_ref", "") or "").strip()
    who = _actor_name(actor, principal)
    if pairs:
        value = _cookie_secret_text(pairs)
        new_ref = ""
        if old:
            try:
                new_ref = credentials.rotate_secret(old, value)
            except credentials.SecretsError:
                new_ref = ""
        if not new_ref:
            new_ref = credentials.put_secret(
                row.tenant_id, row.engagement_id, f"{row.label} (extra cookies)", value
            )
        row.extra_cookies_ref = new_ref
        row.extra_cookie_names = _cookie_names_text(pairs)
    else:
        if old:
            try:
                credentials.delete_secret(old)
            except credentials.SecretsError:
                pass
        row.extra_cookies_ref = ""
        row.extra_cookie_names = ""
    row.updated_by = who
    row.updated_at = utcnow()
    s.flush()
    audit.record(
        s,
        who,
        "auth_profile.extra_cookies",
        "auth_credential_profile",
        row.id,
        engagement_id=engagement_id,
        extra_cookie_names=[k for k, _ in pairs],
        cleared=not pairs,
    )
    return row


def validate_profile(
    s: Session,
    engagement_id: int,
    profile_id: int,
    *,
    principal,
    actor: str | None = None,
    live_check: Callable[[AuthCredentialProfile], tuple[str, str]] | None = None,
) -> AuthCredentialProfile:
    """Low-impact validation. Never bypasses MFA/SSO; no live login unless ``live_check`` given."""
    _check_write(principal)
    row = _get_profile(s, engagement_id, profile_id, principal)
    if row.status == "revoked":
        raise services.ServiceError("not allowed: profile is revoked")

    who = _actor_name(actor, principal)
    now = utcnow()
    method = (row.method or "").strip().lower()

    if live_check is not None and method not in ("sso_bootstrap",):
        status, note = live_check(row)
        if status not in AUTH_PROFILE_STATUSES:
            raise services.ServiceError(f"live_check returned invalid status {status!r}")
        row.status = status
        row.last_validation_note = (note or "")[:500]
    elif method == "none":
        row.status = "valid"
        row.last_validation_note = _NONE_NOTE
    elif method == "sso_bootstrap":
        row.status = "blocked_sso"
        row.last_validation_note = _SSO_NOTE[:500]
    elif method in ("form", "header", "cookie"):
        row.status = "pending"
        row.last_validation_note = _PENDING_NOTE
    else:
        row.status = "pending"
        row.last_validation_note = _PENDING_NOTE

    row.last_validated_at = now
    row.updated_by = who
    row.updated_at = now
    s.flush()
    audit.record(
        s,
        who,
        "auth_profile.validate",
        "auth_credential_profile",
        row.id,
        engagement_id=engagement_id,
        status=row.status,
        note=row.last_validation_note[:200],
    )
    return row


def rotate_secret(
    s: Session,
    engagement_id: int,
    profile_id: int,
    *,
    secret_value: str,
    principal,
    actor: str | None = None,
) -> AuthCredentialProfile:
    """Replace the stored secret; response never includes plaintext."""
    _check_write(principal)
    row = _get_profile(s, engagement_id, profile_id, principal)
    if row.status == "revoked":
        raise services.ServiceError("not allowed: profile is revoked")
    if (row.method or "").strip().lower() == "none":
        raise services.ServiceError("method=none has no secret to rotate")
    value = str(secret_value or "")
    if not value:
        raise services.ServiceError("secret_value is required")

    who = _actor_name(actor, principal)
    if (row.secret_ref or "").strip():
        credentials.rotate_secret(row.secret_ref, value)
    else:
        row.secret_ref = credentials.put_secret(row.tenant_id, row.engagement_id, row.label, value)

    row.status = "pending"
    row.last_validation_note = "Secret rotated; re-validate before use."
    row.last_validated_at = None
    row.updated_by = who
    row.updated_at = utcnow()
    s.flush()
    audit.record(
        s,
        who,
        "auth_profile.rotate",
        "auth_credential_profile",
        row.id,
        engagement_id=engagement_id,
        has_secret=True,
    )
    return row


def revoke_profile(
    s: Session,
    engagement_id: int,
    profile_id: int,
    *,
    principal,
    actor: str | None = None,
) -> AuthCredentialProfile:
    """Mark profile revoked (secret retained until delete)."""
    _check_write(principal)
    row = _get_profile(s, engagement_id, profile_id, principal)
    who = _actor_name(actor, principal)
    if row.status == "revoked":
        return row
    row.status = "revoked"
    row.last_validation_note = "Revoked; secret retained until delete."
    row.updated_by = who
    row.updated_at = utcnow()
    s.flush()
    audit.record(
        s,
        who,
        "auth_profile.revoke",
        "auth_credential_profile",
        row.id,
        engagement_id=engagement_id,
    )
    return row


def delete_profile(
    s: Session,
    engagement_id: int,
    profile_id: int,
    *,
    principal,
    actor: str | None = None,
) -> None:
    """Delete profile row and ciphertext via credentials.delete_secret."""
    _check_write(principal)
    row = _get_profile(s, engagement_id, profile_id, principal)
    who = _actor_name(actor, principal)
    ref = (row.secret_ref or "").strip()
    pid = row.id
    label = row.label
    if ref:
        credentials.delete_secret(ref)
    xc_ref = (getattr(row, "extra_cookies_ref", "") or "").strip()
    if xc_ref:
        try:
            credentials.delete_secret(xc_ref)
        except credentials.SecretsError:
            pass
    s.delete(row)
    s.flush()
    audit.record(
        s,
        who,
        "auth_profile.delete",
        "auth_credential_profile",
        pid,
        engagement_id=engagement_id,
        label=label,
        had_secret=bool(ref),
    )
