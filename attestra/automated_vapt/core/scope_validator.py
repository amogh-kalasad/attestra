"""Ensure Elite automated tests stay within authorized engagement scope.

Reuses [[attestra/auth_web/scope.py]] crawl allowlist and SSRF guards.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from attestra.auth_web.scope import (
    CrawlScope,
    ScopeError,
    assert_redirect_in_scope,
    assert_url_in_scope,
    origin_of,
    scope_from_seeds,
)
from attestra.services import ServiceError

# @lat: [[architecture#Elite automated security testing#Scope validation]]


def build_scope_from_asset(
    asset_identifier: str,
    *,
    extra_seeds: list[str] | None = None,
    allow_private: bool = False,
) -> CrawlScope:
    """Build crawl scope from the asset URL plus optional seed URLs."""
    seeds = [asset_identifier.strip()]
    for s in extra_seeds or []:
        if (s or "").strip():
            seeds.append(s.strip())
    try:
        return scope_from_seeds(seeds, allow_private=allow_private)
    except ScopeError as exc:
        raise ServiceError(str(exc)) from exc


def validate_target_url(
    url: str,
    scope: CrawlScope,
    *,
    check_dns: bool = True,
) -> None:
    """Raise ServiceError when the URL is outside scope or fails SSRF checks."""
    try:
        assert_url_in_scope(url, scope, check_dns=check_dns)
    except ScopeError as exc:
        raise ServiceError(f"target out of scope: {exc}") from exc


def validate_redirect(
    from_url: str,
    to_url: str,
    scope: CrawlScope,
) -> None:
    """Refuse redirects that leave the approved scope."""
    try:
        assert_redirect_in_scope(from_url, to_url, scope)
    except ScopeError as exc:
        raise ServiceError(f"redirect out of scope: {exc}") from exc


def allowed_methods_for_profile(profile: str) -> frozenset[str]:
    """Baseline stays read-oriented; intrusive may use more methods later."""
    prof = (profile or "baseline").strip().lower()
    if prof in ("active", "intrusive"):
        return frozenset({"GET", "HEAD", "OPTIONS", "POST"})
    return frozenset({"GET", "HEAD", "OPTIONS"})


def validate_method(method: str, profile: str) -> None:
    m = (method or "GET").upper()
    allowed = allowed_methods_for_profile(profile)
    if m not in allowed:
        raise ServiceError(f"HTTP method {m} not allowed for profile {profile!r}")


def target_origin(url: str) -> str:
    try:
        return origin_of(url)
    except ScopeError as exc:
        raise ServiceError(str(exc)) from exc


def is_loopback_target(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host in ("127.0.0.1", "localhost", "::1") or host.endswith(".localhost")
