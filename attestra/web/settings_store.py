"""Thin route helpers for tenant email-alert, AI provider, and Certification Authority settings.

``attestra.alerts.service`` / ``attestra.certification.service`` / ``attestra.ai_settings.service``
own Mongo persistence; this module adds the tenant pickers the routes need and returns
``settings_dict`` payloads. ``s`` is always ``None`` (``identity_session``).
"""

from __future__ import annotations

from attestra import services
from attestra.ai_settings import service as ai_cfg
from attestra.alerts import service as alerts
from attestra.certification import service as ca


def _mdb():
    from attestra.web.data_access import mongo_db

    return mongo_db()


# ---------------------------------------------------------------- email alerts


def alert_tenant_ids(s, principal):
    return services.tenant_ids_for(s, principal)


def alert_default_tenant(s, principal) -> int:
    """Tenant for settings when the caller did not pass tenant_id (first by name when unrestricted)."""
    if principal.tenant_id:
        return int(principal.tenant_id)
    allowed = services.tenant_ids_for(s, principal)
    if allowed is not None:
        if not allowed:
            raise alerts.AlertError("no tenant in scope for email alert settings")
        return sorted(allowed)[0]
    tenants = alert_tenants(s, principal)
    if not tenants:
        raise alerts.AlertError("no tenant in scope for email alert settings")
    return int(tenants[0]["id"])


def alert_tenants(s, principal) -> list[dict]:
    """Tenants in scope as ``{"id", "name"}`` ordered by name, then id."""
    allowed = services.tenant_ids_for(s, principal)
    from attestra.persistence.mongo import collections as C

    q: dict = {} if allowed is None else {"_id": {"$in": sorted(int(t) for t in allowed)}}
    docs = _mdb()[C.TENANTS].find(q, {"name": 1}).sort([("name", 1), ("_id", 1)])
    return [{"id": int(d["_id"]), "name": d.get("name", "")} for d in docs]


def alert_check_tenant(s, principal, tenant_id: int) -> None:
    alerts._check_tenant(s, principal, tenant_id)


def alert_settings(s, tenant_id: int) -> dict:
    return alerts.settings_dict(alerts.get_settings(s, tenant_id), tenant_id)


def alert_known_emails(s, tenant_id: int) -> list[str]:
    return alerts.known_tenant_emails(s, tenant_id)


def alert_update(s, principal, tenant_id: int, **fields) -> dict:
    """Validated partial update; returns ``settings_dict``. Raises LookupError / AlertError."""
    return alerts.settings_dict(alerts.update_settings(s, principal, tenant_id, **fields), tenant_id)


# ---------------------------------------------------------------- certification authority


def ca_settings(s) -> dict:
    return ca.settings_dict(ca.get_settings(s))


def ca_update(s, principal, **fields) -> dict:
    """Validated partial update (Super Admin only); returns ``settings_dict``. Raises CertificationError."""
    return ca.settings_dict(ca.update_settings(s, principal, **fields))


# ---------------------------------------------------------------- AI provider settings


def ai_default_tenant(s, principal) -> int:
    """Tenant for AI settings when the caller did not pass tenant_id."""
    try:
        return alert_default_tenant(s, principal)
    except alerts.AlertError as e:
        raise ai_cfg.AiSettingsError(
            "no tenant in scope for AI provider settings — create a tenant first"
        ) from e


def ai_tenants(s, principal) -> list[dict]:
    return alert_tenants(s, principal)


def ai_check_tenant(s, principal, tenant_id: int) -> None:
    ai_cfg._check_tenant(s, principal, tenant_id)


def ai_settings(s, tenant_id: int) -> dict:
    return ai_cfg.settings_dict(ai_cfg.get_settings(s, tenant_id), tenant_id)


def ai_update(s, principal, tenant_id: int, **fields) -> dict:
    """Validated partial update; returns ``settings_dict``. Raises LookupError / AiSettingsError."""
    return ai_cfg.settings_dict(ai_cfg.update_settings(s, principal, tenant_id, **fields), tenant_id)


__all__ = [
    "ai_check_tenant", "ai_default_tenant", "ai_settings", "ai_tenants", "ai_update",
    "alert_check_tenant", "alert_default_tenant", "alert_known_emails", "alert_settings", "alert_tenant_ids",
    "alert_tenants", "alert_update", "ca_settings", "ca_update",
]
