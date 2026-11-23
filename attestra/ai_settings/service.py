"""Per-tenant AI provider settings stored in Mongo with Fernet-encrypted API keys.

Compose ``api`` and ``worker`` share the same Mongo URI and
``ATTESTRA_CREDENTIAL_FERNET_KEY``, so a UI save is visible to both without
rewriting container env or restarting Docker.
"""

from __future__ import annotations

from typing import Any

from attestra import audit, services
from attestra.ai_providers import PROVIDERS, catalog_public, resolve_spec
from attestra.auth.roles import has_permission
from attestra.persistence.mongo.repositories.settings import (
    AI_SETTINGS_DEFAULTS,
    AiSettingsRepository,
    as_row,
)
from attestra.persistence.mongo.secrets_codec import SecretCodecError, decrypt_secret, encrypt_secret
from attestra.persistence.mongo.tenant import SYSTEM_SCOPE


class AiSettingsError(Exception):
    pass


def _mdb():
    from attestra.web.data_access import mongo_db

    return mongo_db()


def _repo() -> AiSettingsRepository:
    return AiSettingsRepository(_mdb(), tenant_ids=SYSTEM_SCOPE)


def get_raw(tenant_id: int) -> dict[str, Any] | None:
    """Return the Mongo document (may include ``api_key_enc``) or ``None``."""
    return _repo().get(int(tenant_id))


def decrypt_api_key(row: dict[str, Any] | Any) -> str:
    enc = getattr(row, "api_key_enc", None) if not isinstance(row, dict) else row.get("api_key_enc")
    if not enc:
        return ""
    try:
        return decrypt_secret(str(enc))
    except SecretCodecError as exc:
        raise AiSettingsError(f"AI API key cannot be decrypted ({exc})") from None


def _check_tenant(s, principal, tenant_id: int) -> None:
    allowed = services.tenant_ids_for(s, principal)
    if allowed is not None and tenant_id not in allowed:
        raise LookupError(f"tenant {tenant_id} not found")
    if not has_permission(principal.role, "ai.configure"):
        raise AiSettingsError("not allowed to manage AI provider settings")


def settings_dict(row: Any | None, tenant_id: int) -> dict[str, Any]:
    """Public settings payload — never includes plaintext or ciphertext keys."""
    if row is None:
        base = {
            "tenant_id": tenant_id,
            **{k: v for k, v in AI_SETTINGS_DEFAULTS.items() if k != "api_key_enc"},
            "has_api_key": False,
        }
    else:
        enc = getattr(row, "api_key_enc", None)
        base = {
            "tenant_id": int(getattr(row, "tenant_id", tenant_id)),
            "enabled": bool(getattr(row, "enabled", False)),
            "provider": str(getattr(row, "provider", "ollama") or "ollama"),
            "base_url": str(getattr(row, "base_url", "") or ""),
            "model": str(getattr(row, "model", "") or ""),
            "has_api_key": bool(enc),
            "updated_by": str(getattr(row, "updated_by", "") or ""),
            "updated_at": row.updated_at.isoformat() if getattr(row, "updated_at", None) else None,
        }
    base["providers"] = catalog_public()
    return base


def get_settings(s, tenant_id: int):
    return as_row(get_raw(tenant_id), AI_SETTINGS_DEFAULTS)


def update_settings(
    s,
    principal,
    tenant_id: int,
    *,
    enabled: bool | None = None,
    provider: str | None = None,
    base_url: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    clear_api_key: bool = False,
):
    _check_tenant(s, principal, tenant_id)
    from attestra.persistence.mongo import collections as C

    if _mdb()[C.TENANTS].count_documents({"_id": int(tenant_id)}, limit=1) == 0:
        raise LookupError(f"tenant {tenant_id} not found")

    fields: dict[str, Any] = {}
    if enabled is not None:
        fields["enabled"] = bool(enabled)
    if provider is not None:
        kind = str(provider).strip().lower()
        try:
            resolve_spec(kind)
        except Exception as exc:
            raise AiSettingsError(str(exc)) from None
        fields["provider"] = kind
        # When switching provider and base_url not supplied, clear custom URL so catalog default applies.
        if base_url is None:
            existing = get_raw(tenant_id) or {}
            old = str(existing.get("provider") or "")
            old_base = str(existing.get("base_url") or "").rstrip("/")
            old_default = (PROVIDERS.get(old).default_base_url if old in PROVIDERS else "").rstrip("/")
            if not old_base or old_base == old_default:
                fields["base_url"] = ""
    if base_url is not None:
        url = str(base_url).strip()
        if url and not url.lower().startswith(("http://", "https://")):
            raise AiSettingsError("base URL must be an http(s) URL")
        fields["base_url"] = url
    if model is not None:
        fields["model"] = str(model).strip()

    if clear_api_key:
        fields["api_key_enc"] = None
    elif api_key is not None:
        pasted = str(api_key).strip()
        if pasted:
            try:
                fields["api_key_enc"] = encrypt_secret(pasted)
            except SecretCodecError as exc:
                raise AiSettingsError(
                    f"AI API key encryption needs ATTESTRA_CREDENTIAL_FERNET_KEY ({exc})"
                ) from None
        # empty paste → leave existing key unchanged (omit api_key_enc)

    if not fields:
        row = get_settings(s, tenant_id) or as_row(
            _repo().ensure(tenant_id), AI_SETTINGS_DEFAULTS
        )
        return row

    doc = _repo().update(tenant_id, actor=principal.actor, **fields)
    row = as_row(doc, AI_SETTINGS_DEFAULTS)
    audit.record(
        s,
        principal.actor,
        "ai.settings.update",
        "ai_settings",
        getattr(row, "id", tenant_id),
        tenant_id=tenant_id,
        enabled=bool(getattr(row, "enabled", False)),
        provider=str(getattr(row, "provider", "")),
        model=str(getattr(row, "model", "")),
        has_api_key=bool(getattr(row, "api_key_enc", None)),
        base_url_set=bool(str(getattr(row, "base_url", "") or "").strip()),
    )
    return row
