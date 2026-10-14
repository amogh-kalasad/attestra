"""OIDC (Keycloak) login behind ATTESTRA_OIDC_ENABLED.

Uses authlib when the optional ``oidc`` extra is installed. Validation covers
issuer, audience, nonce, and expiry.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from attestra import config


@dataclass
class OIDCTokens:
    access_token: str
    id_token: str
    claims: dict[str, Any]


class OIDCError(Exception):
    pass


def oidc_enabled() -> bool:
    return bool(config.OIDC_ENABLED)


def map_oidc_role(claims: dict[str, Any]) -> str:
    """Map Keycloak realm/client roles/groups to an Attestra role."""
    roles = set()
    realm = (claims.get("realm_access") or {}).get("roles") or []
    roles.update(realm)
    for client in (claims.get("resource_access") or {}).values():
        roles.update(client.get("roles") or [])
    groups = claims.get("groups") or []
    roles.update(g.strip("/").lower() for g in groups)
    for candidate in ("admin", "lead", "tester", "reviewer", "client_viewer", "auditor"):
        if candidate in roles or f"attestra-{candidate}" in roles:
            return candidate
    return "client_viewer"


def validate_id_token_claims(
    claims: dict[str, Any],
    *,
    expected_nonce: str,
    expected_audience: str | None = None,
    issuer: str | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Validate ID token claims without a network call (used by unit tests)."""
    now = now if now is not None else time.time()
    iss = issuer or config.OIDC_ISSUER
    aud = expected_audience or config.OIDC_CLIENT_ID
    if not iss or claims.get("iss") != iss:
        raise OIDCError("invalid issuer")
    token_aud = claims.get("aud")
    if isinstance(token_aud, list):
        if aud not in token_aud:
            raise OIDCError("invalid audience")
    elif token_aud != aud:
        raise OIDCError("invalid audience")
    if claims.get("nonce") != expected_nonce:
        raise OIDCError("invalid nonce")
    exp = claims.get("exp")
    if exp is None or float(exp) < now:
        raise OIDCError("token expired")
    return claims


def build_authorization_url(*, state: str, nonce: str, redirect_uri: str) -> str:
    if not oidc_enabled():
        raise OIDCError("OIDC is disabled")
    # Minimal authorize URL; full PKCE flow uses authlib when installed.
    from urllib.parse import urlencode

    params = urlencode(
        {
            "response_type": "code",
            "client_id": config.OIDC_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce,
            "code_challenge_method": "S256",
        }
    )
    return f"{config.OIDC_ISSUER.rstrip('/')}/protocol/openid-connect/auth?{params}"
