"""Passive CT log subdomain suggestions for an in-scope apex domain.

One crt.sh JSON request per run. Results are suggestions only — never added to
scope and never scanned or resolved.
"""
# @lat: [[authorization#CT subdomain suggestions]]

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

from sqlalchemy.orm import Session

from attestra import audit, services
from attestra.runner.authorization import AuthorizationError, AuthorizedScope, scope_for_engagement
from attestra.runner.http_safe import SafeResponse, passive_get

CT_TIMEOUT_S = 30
CT_MAX_BODY = 2_000_000
CRT_SH_URL = "https://crt.sh/?q={query}&output=json"

HttpGet = Callable[..., SafeResponse]


@dataclass(frozen=True)
class CtSuggestion:
    name: str
    first_seen: str
    issuer: str


def apex_domain(host: str) -> str:
    """Simple registrable apex (last two labels), matching webcheck DNS."""
    labels = [p for p in host.strip(".").lower().split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def host_from_identifier(identifier: str) -> str:
    """Host from a URL or bare host asset identifier."""
    ident = (identifier or "").strip()
    if "://" in ident:
        return (urlsplit(ident).hostname or "").lower()
    return ident.split("/")[0].split(":")[0].strip("[]").lower()


def under_apex(name: str, apex: str) -> bool:
    """True when name is the apex or a subdomain of it."""
    n = name.strip(".").lower()
    a = apex.strip(".").lower()
    if not n or not a:
        return False
    return n == a or n.endswith("." + a)


def apex_in_scope(scope: AuthorizedScope, apex: str) -> bool:
    """R14: CT lookup runs only when the apex itself is on the signed allow-list."""
    a = apex.strip(".").lower()
    if not a or "." not in a:
        return False
    return a in {h.strip(".").lower() for h in scope.allowed_hosts}


def in_scope_apexes(scope: AuthorizedScope) -> list[str]:
    """Apex domains that are themselves present in signed scope (button enable list)."""
    found: list[str] = []
    seen: set[str] = set()
    for host in sorted(scope.allowed_hosts):
        apex = apex_domain(host)
        if apex and apex not in seen and apex_in_scope(scope, apex):
            seen.add(apex)
            found.append(apex)
    return found


def normalize_ct_name(raw: str) -> str | None:
    """Strip wildcard prefix; drop empty / invalid names."""
    name = (raw or "").strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not name or "*" in name or " " in name:
        return None
    return name


def parse_ct_entries(payload: object, apex: str) -> list[CtSuggestion]:
    """Filter crt.sh JSON: drop wildcards/dupes and names outside the apex."""
    if not isinstance(payload, list):
        return []
    best: dict[str, CtSuggestion] = {}
    for row in payload:
        if not isinstance(row, dict):
            continue
        issuer = str(row.get("issuer_name") or row.get("issuer") or "").strip()
        first = str(
            row.get("entry_timestamp")
            or row.get("not_before")
            or row.get("min_cert_id")
            or ""
        ).strip()
        raw_names = str(row.get("name_value") or row.get("common_name") or "")
        for part in raw_names.replace(",", "\n").splitlines():
            name = normalize_ct_name(part)
            if not name or not under_apex(name, apex):
                continue
            prev = best.get(name)
            if prev is None or (first and (not prev.first_seen or first < prev.first_seen)):
                best[name] = CtSuggestion(name=name, first_seen=first, issuer=issuer)
    return sorted(best.values(), key=lambda s: s.name)


def crt_sh_query_url(apex: str) -> str:
    """One crt.sh JSON URL for the apex (includes wildcard search)."""
    q = f"%.{apex.strip('.').lower()}"
    return CRT_SH_URL.format(query=quote(q, safe="%."))


def fetch_ct_suggestions(
    apex: str,
    *,
    http_get: HttpGet | None = None,
) -> tuple[list[CtSuggestion], int]:
    """One CT request; returns (suggestions, request_count)."""
    getter = http_get or (lambda url, **kw: passive_get(url, timeout=CT_TIMEOUT_S, max_body=CT_MAX_BODY))
    url = crt_sh_query_url(apex)
    resp = getter(url, timeout=CT_TIMEOUT_S, max_body=CT_MAX_BODY)
    request_count = 1
    if resp.status >= 400:
        raise AuthorizationError(f"CT lookup failed with HTTP {resp.status}")
    try:
        payload = json.loads(resp.body.decode("utf-8", errors="replace") or "[]")
    except json.JSONDecodeError as exc:
        raise AuthorizationError("CT lookup returned invalid JSON") from exc
    return parse_ct_entries(payload, apex), request_count


def suggestions_for_engagement(
    s: Session,
    engagement_id: int,
    apex: str,
    *,
    actor: str,
    http_get: HttpGet | None = None,
) -> dict:
    """Scope-gated CT suggestions. Never mutates assets or creates scans."""
    eng = services.get_engagement(s, engagement_id)
    apex_l = apex.strip(".").lower()
    if not apex_l or apex_l != apex_domain(apex_l):
        raise services.ServiceError("apex must be a registrable domain (for example example.com)")
    try:
        scope = scope_for_engagement(s, engagement_id)
    except AuthorizationError as exc:
        raise services.ServiceError(str(exc)) from exc
    if not apex_in_scope(scope, apex_l):
        raise services.ServiceError(f"apex {apex_l} is not in the signed scope")
    asset_count_before = len(eng.assets)
    suggestions, request_count = fetch_ct_suggestions(apex_l, http_get=http_get)
    audit.record(
        s,
        actor,
        "scope.suggestions.fetched",
        "engagement",
        engagement_id,
        apex=apex_l,
        count=len(suggestions),
        requests=request_count,
    )
    # Re-read so callers can assert scope table unchanged.
    s.refresh(eng)
    return {
        "apex": apex_l,
        "suggestions": [
            {"name": x.name, "first_seen": x.first_seen, "issuer": x.issuer} for x in suggestions
        ],
        "requests": request_count,
        "asset_count": len(eng.assets),
        "asset_count_before": asset_count_before,
    }
