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


# --- Step 6.4: bearer JWT (access token) validation against the IdP JWKS ---------

_jwks_cache = None


def _jwks():
    """Process-wide JWKS cache for ``config.OIDC_JWKS_URL`` (Keycloak default path if unset)."""
    global _jwks_cache
    from attestra.auth.jwt_verify import JWKSCache

    url = config.OIDC_JWKS_URL or f"{config.OIDC_ISSUER.rstrip('/')}/protocol/openid-connect/certs"
    if _jwks_cache is None or _jwks_cache.url != url:
        _jwks_cache = JWKSCache(url)
    return _jwks_cache


def looks_like_jwt(token: str) -> bool:
    return token.count(".") == 2 and token.startswith("eyJ")


def validate_access_token(
    token: str,
    *,
    jwks=None,
    issuer: str | None = None,
    audience: str | None = None,
    leeway_s: float = 60.0,
    now: float | None = None,
) -> dict[str, Any]:
    """Verify signature (JWKS) and issuer/audience/exp/nbf. Returns claims or raises OIDCError."""
    from attestra.auth.jwt_verify import JWTError, verify_jws

    if not oidc_enabled():
        raise OIDCError("OIDC is disabled")
    algs = tuple(a.strip() for a in config.OIDC_ALGORITHMS.split(",") if a.strip())
    try:
        claims = verify_jws(token, jwks or _jwks(), allowed_algs=algs)
    except JWTError as exc:
        raise OIDCError(f"invalid token: {exc}") from None
    now = now if now is not None else time.time()
    iss = issuer or config.OIDC_ISSUER
    if not iss or claims.get("iss") != iss:
        raise OIDCError("invalid issuer")
    aud = audience or config.OIDC_AUDIENCE or config.OIDC_CLIENT_ID
    token_aud = claims.get("aud")
    auds = token_aud if isinstance(token_aud, list) else ([token_aud] if token_aud else [])
    # Keycloak access tokens often carry aud=["account"] and azp=<client>; accept azp as a fallback.
    if not aud or (aud not in auds and claims.get("azp") != aud):
        raise OIDCError("invalid audience")
    exp = claims.get("exp")
    if exp is None or float(exp) + leeway_s < now:
        raise OIDCError("token expired")
    nbf = claims.get("nbf")
    if nbf is not None and float(nbf) - leeway_s > now:
        raise OIDCError("token not yet valid")
    return claims


def map_oidc_tenant(claims: dict[str, Any]) -> int | None:
    """Tenant from ``config.OIDC_TENANT_CLAIM`` (an int id); None for staff."""
    value = claims.get(config.OIDC_TENANT_CLAIM)
    if isinstance(value, list):
        value = value[0] if len(value) == 1 else None
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise OIDCError("tenant claim must be an integer tenant id") from None


def principal_from_claims(s, claims: dict[str, Any]):
    """Map validated claims to a Principal, linking/provisioning a local User row.

    The IdP is the source of truth for role and tenant: they are refreshed on each login.
    Client roles (client_viewer) require a tenant claim.
    """
    from sqlalchemy import select

    from attestra.auth.keys import Principal
    from attestra.models import Tenant, User

    username = str(claims.get(config.OIDC_USERNAME_CLAIM) or claims.get("sub") or "").strip().lower()
    if not username:
        raise OIDCError("token has no username claim")
    role = map_oidc_role(claims)
    tenant_id = map_oidc_tenant(claims)
    if tenant_id is not None and s.get(Tenant, tenant_id) is None:
        raise OIDCError("unknown tenant in token")
    if role == "client_viewer" and tenant_id is None:
        raise OIDCError("client users need a tenant claim")
    user = s.scalar(select(User).where(User.username == username))
    if user is None:
        if not config.OIDC_AUTO_PROVISION:
            raise OIDCError("user not provisioned")
        # password_hash "oidc" never verifies (not scrypt), so local password login stays impossible.
        user = User(username=username, display_name=str(claims.get("name") or username)[:200],
                    password_hash="oidc", role=role, tenant_id=tenant_id, active=True)
        s.add(user)
        s.flush()
    elif not user.active:
        raise OIDCError("user disabled")
    else:
        user.role = role
        user.tenant_id = tenant_id
    return Principal(user_id=user.id, username=user.username, display_name=user.display_name,
                     role=role, tenant_id=tenant_id)


def authenticate_bearer_jwt(s, token: str, *, jwks=None):
    """Return a Principal for a valid IdP access token, else None (never raises)."""
    if not oidc_enabled() or not looks_like_jwt(token):
        return None
    try:
        return principal_from_claims(s, validate_access_token(token, jwks=jwks))
    except OIDCError:
        return None
