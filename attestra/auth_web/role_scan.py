"""Multi-role access-control comparison for authenticated website testing (Phase 7 P5-3).

Read-only by design: loads credential profiles and route inventory, captures
[[attestra/auth_web/roles.py#RoleSnapshot]] values via a pluggable fetcher (or
prebuilt snapshots), then calls [[attestra/auth_web/roles.py#compare_roles]] with
``intrusive=False``. Meaningful status/redirect/control diffs become Finding rows
with ``tool=auth_web_roles``. Intrusive IDOR probes belong to a later phase.
"""
# @lat: [[architecture#Authenticated website testing]]
# @lat: [[tests#Phase 7 testing depth#Multi-role comparison]]

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, config, credentials, services
from attestra.auth.roles import has_permission
from attestra.auth_web.roles import RoleDiff, RoleSnapshot, compare_roles
from attestra.auth_web.scope import ScopeError, origin_of
from attestra.fingerprint import fingerprint
from attestra.models import (
    Asset,
    AuthCredentialProfile,
    AuthRouteInventory,
    Finding,
    utcnow,
)

logger = logging.getLogger(__name__)

TOOL = "auth_web_roles"
_CWE = 862  # Missing Authorization — access-control signal from role diffs
_FETCH_TIMEOUT_S = 8.0
_USER_AGENT = "attestra-auth-web/0.1 (security testing; role-scan read-only)"

# url, profile (may be None), secret plaintext (may be None / empty)
RoleFetcher = Callable[[str, AuthCredentialProfile | None, str | None], RoleSnapshot]


def _actor_name(actor: str | None, principal) -> str:
    if actor and str(actor).strip():
        return str(actor).strip()
    if principal is not None:
        return getattr(principal, "actor", None) or getattr(principal, "username", "") or "unknown"
    return "unknown"


def _check_write(principal) -> None:
    if principal is None:
        return
    role = getattr(principal, "role", None) or ""
    if not has_permission(role, "engagement.write"):
        raise services.ServiceError("not allowed to run role comparison")


def _require_enabled() -> None:
    if not config.AUTH_WEB_ENABLED:
        raise services.ServiceError("authenticated website testing is disabled (ATTESTRA_AUTH_WEB_ENABLED)")


def _load_profiles(
    s: Session,
    eng,
    asset_id: int,
    role_a: str,
    role_b: str,
) -> tuple[AuthCredentialProfile, AuthCredentialProfile]:
    rows = list(
        s.scalars(
            select(AuthCredentialProfile).where(
                AuthCredentialProfile.engagement_id == eng.id,
                AuthCredentialProfile.tenant_id == eng.tenant_id,
            )
        )
    )

    def _pick(role: str) -> AuthCredentialProfile:
        role_l = (role or "").strip().lower()
        matches = [p for p in rows if (p.role_name or "").strip().lower() == role_l]
        if not matches:
            raise services.ServiceError(f"no auth credential profile for role {role!r}")
        # Prefer asset-scoped profile, then engagement-wide (asset_id NULL).
        for p in matches:
            if p.asset_id == asset_id:
                return p
        for p in matches:
            if p.asset_id is None:
                return p
        return matches[0]

    return _pick(role_a), _pick(role_b)


def _inventory_urls(s: Session, engagement_id: int, asset_id: int) -> list[str]:
    rows = list(
        s.scalars(
            select(AuthRouteInventory)
            .where(
                AuthRouteInventory.engagement_id == engagement_id,
                AuthRouteInventory.asset_id == asset_id,
                AuthRouteInventory.status.in_(("visited", "discovered")),
            )
            .order_by(AuthRouteInventory.id)
        )
    )
    seen: set[str] = set()
    out: list[str] = []
    for r in rows:
        u = (r.url or "").strip()
        if not u or u in seen:
            continue
        seen.add(u)
        out.append(u)
        if len(out) >= config.AUTH_WEB_MAX_ROUTES:
            break
    return out


def _allowed_hosts(asset: Asset, urls: Sequence[str]) -> set[str]:
    hosts: set[str] = set()
    for raw in [asset.identifier or "", *urls]:
        try:
            host = (urlsplit(raw).hostname or "").lower()
        except Exception:
            host = ""
        if host:
            hosts.add(host)
    return hosts


def _host_allowed(url: str, allowed: set[str]) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except Exception:
        return False
    return bool(host) and host in allowed


def _auth_headers(profile: AuthCredentialProfile | None, secret: str | None) -> dict[str, str]:
    """Build request headers from profile method + secret. Never logs the secret."""
    headers = {"User-Agent": _USER_AGENT}
    if profile is None or not secret:
        return headers
    method = (profile.method or "").strip().lower()
    cfg = dict(profile.config_json or {})
    if method == "header":
        name = str(cfg.get("header_name") or cfg.get("name") or "Authorization").strip() or "Authorization"
        prefix = str(cfg.get("header_prefix") or cfg.get("prefix") or "").strip()
        value = f"{prefix} {secret}".strip() if prefix else secret
        headers[name] = value
    elif method == "cookie":
        name = str(cfg.get("cookie_name") or cfg.get("name") or "session").strip() or "session"
        headers["Cookie"] = f"{name}={secret}"
    # form / sso_bootstrap / none: default fetcher cannot complete interactive login;
    # callers should inject a session-aware fetcher or prebuilt snapshots.
    return headers


def default_fetcher(
    url: str,
    profile: AuthCredentialProfile | None,
    secret: str | None,
    *,
    allowed_hosts: set[str] | None = None,
    timeout_s: float = _FETCH_TIMEOUT_S,
) -> RoleSnapshot:
    """Safe read-only GET against allowed hosts only (urllib, short timeout)."""
    role = (profile.role_name if profile else "") or ""
    if allowed_hosts is not None and not _host_allowed(url, allowed_hosts):
        return RoleSnapshot(role_name=role, url=url, status_code=None, final_url=url, body_markers=["blocked_host"])
    try:
        origin_of(url)  # scheme/host sanity
    except ScopeError:
        return RoleSnapshot(role_name=role, url=url, status_code=None, final_url=url, body_markers=["bad_url"])

    headers = _auth_headers(profile, secret)
    req = Request(url, headers=headers, method="GET")
    redirect_chain: list[str] = []
    try:
        with urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - host allowlist enforced above
            final = getattr(resp, "geturl", lambda: url)()
            status = int(getattr(resp, "status", 200) or 200)
            # Discard body — role_scan does not persist response content.
            resp.read(65_536)
            return RoleSnapshot(
                role_name=role,
                url=url,
                status_code=status,
                final_url=final or url,
                redirect_chain=redirect_chain,
            )
    except Exception as exc:
        # HTTPError subclasses URLError and carries a status code.
        code = getattr(exc, "code", None)
        if isinstance(code, int):
            loc = ""
            hdrs = getattr(exc, "headers", None)
            if hdrs is not None:
                loc = hdrs.get("Location") or hdrs.get("location") or ""
            if 300 <= code < 400 and loc:
                redirect_chain = [loc]
            return RoleSnapshot(
                role_name=role,
                url=url,
                status_code=code,
                final_url=loc or url,
                redirect_chain=redirect_chain,
            )
        logger.info("role_scan fetch failed for %s: %s", urlsplit(url).path or "/", type(exc).__name__)
        return RoleSnapshot(role_name=role, url=url, status_code=None, final_url=url, body_markers=["fetch_error"])


def _load_secret(profile: AuthCredentialProfile) -> str | None:
    ref = (profile.secret_ref or "").strip()
    if not ref:
        return None
    try:
        return credentials.get_secret(ref)
    except Exception:
        logger.info("role_scan could not load secret for profile id=%s", profile.id)
        return None


def _diff_is_meaningful(diff: RoleDiff) -> bool:
    """Persist findings only when status, redirect, or visible controls differ."""
    return bool(
        diff.status_differs
        or diff.redirect_differs
        or diff.controls_only_in_a
        or diff.controls_only_in_b
    )


def _severity_for(diff: RoleDiff) -> str:
    # Status mismatches are a stronger access-control signal than UI-only diffs.
    if diff.status_differs:
        return "low"
    return "info"


def _finding_title(diff: RoleDiff) -> str:
    return f"Role access difference ({diff.role_a} vs {diff.role_b})"


def _finding_description(diff: RoleDiff) -> str:
    """Reproducible steps; never include secrets, cookies, or tokens."""
    lines = [
        f"Compare GET {diff.url} authenticated as role '{diff.role_a}' versus role '{diff.role_b}'.",
        "Observed differences:",
    ]
    for note in diff.notes:
        lines.append(f"- {note}")
    if diff.controls_only_in_a:
        lines.append(f"- controls only in {diff.role_a}: {', '.join(diff.controls_only_in_a)}")
    if diff.controls_only_in_b:
        lines.append(f"- controls only in {diff.role_b}: {', '.join(diff.controls_only_in_b)}")
    lines.extend(
        [
            "Steps to reproduce:",
            f"1. Authenticate with the stored credential profile for role '{diff.role_a}'.",
            f"2. Authenticate with the stored credential profile for role '{diff.role_b}'.",
            f"3. Issue a read-only GET to {diff.url} as each role.",
            "4. Compare HTTP status, redirect / final URL, and visible controls.",
            "Do not use intrusive object-tampering probes in this comparison path.",
        ]
    )
    return "\n".join(lines)


def _finding_recommendation(diff: RoleDiff) -> str:
    return (
        "Verify that each role receives only the status codes, redirects, and UI controls "
        f"appropriate for '{diff.role_a}' and '{diff.role_b}'. Tighten authorization if a "
        "lower-privilege role can reach privileged status or controls."
    )


def _existing_finding(
    s: Session,
    engagement_id: int,
    fp: str,
    title: str,
    location: str,
) -> Finding | None:
    row = s.scalar(
        select(Finding).where(Finding.engagement_id == engagement_id, Finding.fingerprint == fp)
    )
    if row is not None:
        return row
    # Fallback dedup by title+location when fingerprint does not match an older row.
    candidates = list(
        s.scalars(
            select(Finding).where(
                Finding.engagement_id == engagement_id,
                Finding.title == title[:500],
                Finding.location == location[:1000],
            )
        )
    )
    for c in candidates:
        if TOOL in (c.tools or []):
            return c
    return None


def _enrich_finding(f: Finding) -> None:
    from attestra.compliance.owasp import map_finding_to_owasp

    refs = map_finding_to_owasp(f)
    f.owasp_top10 = refs["owasp_top10"]
    f.asvs_ref = refs["asvs_ref"]
    f.wstg_ref = refs["wstg_ref"]
    services.rescore(f)


def _persist_diff(
    s: Session,
    *,
    engagement_id: int,
    asset_id: int,
    diff: RoleDiff,
    actor: str,
) -> tuple[Finding, bool] | None:
    """Return ``(finding, created)`` or None when the diff is not persisted."""
    if not _diff_is_meaningful(diff):
        return None
    title = _finding_title(diff)
    location = (diff.url or "")[:1000]
    variant = f"{diff.role_a}|{diff.role_b}|status={int(diff.status_differs)}|redir={int(diff.redirect_differs)}"
    fp = fingerprint(
        location=location,
        cwe=_CWE,
        cves=[],
        title=title,
        asset_id=asset_id,
        variant=variant,
    )
    existing = _existing_finding(s, engagement_id, fp, title, location)
    if existing is not None:
        existing.occurrences = (existing.occurrences or 1) + 1
        existing.last_seen = utcnow()
        if TOOL not in (existing.tools or []):
            existing.tools = [*(existing.tools or []), TOOL]
        return existing, False

    f = Finding(
        engagement_id=engagement_id,
        asset_id=asset_id,
        fingerprint=fp,
        title=title[:500],
        description=_finding_description(diff),
        recommendation=_finding_recommendation(diff),
        tools=[TOOL],
        rule_ids=["auth_web.role_compare"],
        cwe=_CWE,
        cves=[],
        location=location,
        severity=_severity_for(diff),
        status="new",
        first_seen=utcnow(),
        last_seen=utcnow(),
        affected_urls=[diff.url] if diff.url else [],
    )
    s.add(f)
    s.flush()
    _enrich_finding(f)
    audit.record(
        s,
        actor,
        "auth_web.role_diff",
        "finding",
        f.id,
        engagement_id=engagement_id,
        asset_id=asset_id,
        role_a=diff.role_a,
        role_b=diff.role_b,
        url=diff.url,
        severity=f.severity,
    )
    return f, True


def run_role_comparison(
    session: Session,
    engagement_id: int,
    asset_id: int,
    *,
    role_a: str,
    role_b: str,
    urls: list[str] | None = None,
    actor: str,
    principal=None,
    fetcher: RoleFetcher | None = None,
    snapshots_a: Sequence[RoleSnapshot] | None = None,
    snapshots_b: Sequence[RoleSnapshot] | None = None,
) -> dict[str, Any]:
    """Compare two engagement roles across URLs and persist access-control findings.

    Always uses read-only [[attestra/auth_web/roles.py#compare_roles]] (never
    ``intrusive=True``). Secrets are loaded via [[attestra.credentials.store.get_secret]]
    for the default fetcher path and are never written into findings or logs.
    """
    from attestra import config

    _require_enabled()
    _check_write(principal)
    eng = services.get_engagement(session, engagement_id, principal)
    if config.signed_authorization_required() and not any(a.is_valid() for a in eng.authorizations):
        raise services.ServiceError(
            "record a currently valid signed authorization before running role comparison"
        )

    asset = session.get(Asset, asset_id)
    if asset is None or asset.engagement_id != eng.id:
        raise LookupError(f"asset {asset_id} not found")

    role_a = (role_a or "").strip()
    role_b = (role_b or "").strip()
    if not role_a or not role_b:
        raise services.ServiceError("role_a and role_b are required")
    if role_a.lower() == role_b.lower():
        raise services.ServiceError("role_a and role_b must differ")

    profile_a, profile_b = _load_profiles(session, eng, asset_id, role_a, role_b)
    who = _actor_name(actor, principal)

    if urls is None:
        url_list = _inventory_urls(session, eng.id, asset_id)
    else:
        url_list = []
        seen: set[str] = set()
        for u in urls:
            u = (u or "").strip()
            if not u or u in seen:
                continue
            seen.add(u)
            url_list.append(u)
            if len(url_list) >= config.AUTH_WEB_MAX_ROUTES:
                break

    if snapshots_a is not None and snapshots_b is not None:
        snaps_a = list(snapshots_a)
        snaps_b = list(snapshots_b)
    else:
        if not url_list:
            raise services.ServiceError("no URLs to compare (pass urls= or populate AuthRouteInventory)")

        allowed = _allowed_hosts(asset, url_list)
        secret_a = _load_secret(profile_a)
        secret_b = _load_secret(profile_b)

        def _fetch(url: str, profile: AuthCredentialProfile, secret: str | None) -> RoleSnapshot:
            if fetcher is not None:
                return fetcher(url, profile, secret)
            return default_fetcher(url, profile, secret, allowed_hosts=allowed)

        snaps_a = [_fetch(u, profile_a, secret_a) for u in url_list]
        snaps_b = [_fetch(u, profile_b, secret_b) for u in url_list]
        # Drop plaintext as soon as snapshots exist.
        secret_a = None
        secret_b = None

    # Read-only comparison only — P5-4 owns intrusive probes.
    diffs = compare_roles(snaps_a, snaps_b, intrusive=False)

    findings_created: list[dict[str, Any]] = []
    findings_updated: list[int] = []
    skipped_notes_only = 0
    for diff in diffs:
        if not _diff_is_meaningful(diff):
            skipped_notes_only += 1
            continue
        persisted = _persist_diff(
            session, engagement_id=eng.id, asset_id=asset_id, diff=diff, actor=who
        )
        if persisted is None:
            continue
        row, created = persisted
        if created:
            findings_created.append(
                {
                    "id": row.id,
                    "fingerprint": row.fingerprint,
                    "title": row.title,
                    "severity": row.severity,
                    "location": row.location,
                    "tools": list(row.tools or []),
                    "cwe": row.cwe,
                }
            )
        else:
            findings_updated.append(row.id)

    audit.record(
        session,
        who,
        "auth_web.role_comparison",
        "engagement",
        eng.id,
        asset_id=asset_id,
        role_a=role_a,
        role_b=role_b,
        urls=len(url_list) if url_list else len({*(s.url for s in snaps_a), *(s.url for s in snaps_b)}),
        diffs=len(diffs),
        findings_created=len(findings_created),
        findings_updated=len(findings_updated),
    )

    return {
        "engagement_id": eng.id,
        "asset_id": asset_id,
        "role_a": role_a,
        "role_b": role_b,
        "urls": url_list or sorted({s.url for s in snaps_a} | {s.url for s in snaps_b}),
        "diffs": [
            {
                "url": d.url,
                "role_a": d.role_a,
                "role_b": d.role_b,
                "status_differs": d.status_differs,
                "redirect_differs": d.redirect_differs,
                "controls_only_in_a": list(d.controls_only_in_a),
                "controls_only_in_b": list(d.controls_only_in_b),
                "notes": list(d.notes),
                "meaningful": _diff_is_meaningful(d),
            }
            for d in diffs
        ],
        "findings_created": findings_created,
        "findings_updated": findings_updated,
        "skipped_notes_only": skipped_notes_only,
        "intrusive": False,
        "tool": TOOL,
    }
