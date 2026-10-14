"""Prove control of a target before the first scan (DNS TXT or well-known file)."""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

from attestra.models import Asset, utcnow
from attestra.runner.authorization import AuthorizedScope


def issue_token(asset: Asset) -> str:
    token = secrets.token_urlsafe(24)
    asset.ownership_token = token
    return token


def is_verified(asset: Asset) -> bool:
    if asset.ownership_verified_at is not None:
        return True
    # Loopback / explicitly private fixtures skip ownership in development.
    ident = (asset.identifier or "").lower()
    notes = (asset.notes or "").lower()
    if "allow_private" in notes or "127.0.0.1" in ident or "localhost" in ident:
        return True
    return False


def verify(
    asset: Asset,
    *,
    scope: AuthorizedScope | None = None,
    dns_lookup=None,
    http_get=None,
) -> bool:
    """Return True and set ownership_verified_at when DNS TXT or well-known file matches."""
    token = asset.ownership_token
    if not token:
        token = issue_token(asset)
    expected = f"attestra-verify={token}"
    host = _host_for(asset)
    if not host:
        return False

    # DNS TXT
    lookup = dns_lookup or _default_dns_txt
    try:
        txts = lookup(host)
        if any(expected in t or token in t for t in txts):
            asset.ownership_verified_at = utcnow()
            return True
    except Exception:
        pass

    # Well-known HTTP file
    if asset.kind in ("web_app", "api") and scope is not None:
        url = asset.identifier.rstrip("/") + "/.well-known/attestra-verify.txt"
        getter = http_get or _default_http_get
        try:
            body = getter(url, scope=scope)
            if token in body.decode("utf-8", errors="replace"):
                asset.ownership_verified_at = utcnow()
                return True
        except Exception:
            return False
    return False


def _host_for(asset: Asset) -> str:
    if asset.kind in ("web_app", "api"):
        return (urlsplit(asset.identifier).hostname or "").lower()
    if asset.kind == "host":
        return asset.identifier.split("/")[0].lower()
    return ""


def _default_dns_txt(host: str) -> list[str]:
    """Best-effort TXT lookup; tests inject ``dns_lookup``. No hard dependency on dnspython."""
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return []
    try:
        answers = dns.resolver.resolve(host, "TXT")
    except Exception:
        return []
    out: list[str] = []
    for r in answers:
        out.extend(s.decode() if isinstance(s, bytes) else str(s) for s in r.strings)
    return out


def _default_http_get(url: str, *, scope: AuthorizedScope) -> bytes:
    from attestra.runner.http_safe import safe_get

    return safe_get(url, scope=scope).body
