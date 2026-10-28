"""Business operations shared by the API and the CLI. Every write is audited."""
# @lat: [[architecture#System layers]]
# @lat: [[interfaces]]

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from attestra import audit, config, importers, scoring
from attestra.fingerprint import (
    caa_legacy_fingerprints,
    canonicalize_for_merge,
    fingerprint,
    is_caa_variant,
    is_cert_expiry_variant,
    normalize_title,
)
from attestra.models import (
    ASSET_KINDS,
    ENVIRONMENTS,
    FRAMEWORKS,
    NEW_ENGAGEMENT_TYPES,
    OPEN_STATUSES,
    TEST_TYPES,
    TRANSITIONS,
    Asset,
    AsvScan,
    Authorization,
    ControlAssessment,
    Engagement,
    Evidence,
    Finding,
    FindingObservation,
    ImportRun,
    Job,
    Nonconformity,
    RiskAcceptance,
    ScanRun,
    ScanSchedule,
    ScopeRule,
    SegmentationTest,
    Tenant,
    TenantMembership,
    allowed_test_types_for,
    default_tests_for,
    engagement_type_label,
    normalize_engagement_type,
    utcnow,
)


class ServiceError(Exception):
    """A request that breaks a business rule. Maps to HTTP 400/409."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name).name)[:120] or "file"


def _store(tenant_id: int | None, sub: str, sha: str, filename: str, data: bytes) -> Path:
    """Content-addressed, write-once storage under a per-tenant prefix via Storage backend."""
    from attestra.storage import get_storage
    from attestra.storage.local import LocalStorage

    config.ensure_dirs()
    if tenant_id is None:
        key = f"{sub}/{sha[:16]}_{_safe_name(filename)}"
    else:
        key = f"tenants/{tenant_id}/{sub}/{sha[:16]}_{_safe_name(filename)}"
    store = get_storage()
    uri = store.put(key, data)
    if isinstance(store, LocalStorage):
        return store.path_for(uri)
    # Non-local: write a sidecar path record under DATA_DIR for ORM path fields
    path = config.DATA_DIR / key
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(uri, encoding="utf-8")
    return path


# Evidence kinds accepted by add_evidence (portal uses client_upload).
EVIDENCE_KINDS = (
    "screenshot",
    "http_pair",
    "log",
    "file",
    "note",
    "code",
    "package",
    "capture_failure",
    "client_upload",
)
# client_viewer may download only their own remediation uploads, not scanner proof.
CLIENT_DOWNLOADABLE_KINDS = frozenset({"client_upload"})


def path_under_roots(path: Path, roots: list[Path]) -> bool:
    """True when ``path`` resolves under at least one allowed root (no prefix tricks)."""
    try:
        resolved = Path(path).resolve()
    except OSError:
        return False
    for root in roots:
        try:
            if resolved.is_relative_to(Path(root).resolve()):
                return True
        except (OSError, ValueError, TypeError):
            continue
    return False


def evidence_storage_roots(tenant_id: int) -> list[Path]:
    """Tenant evidence root plus legacy DATA_DIR for pre-tenant paths."""
    return [
        (config.DATA_DIR / "tenants" / str(tenant_id)).resolve(),
        config.DATA_DIR.resolve(),
    ]


def assert_evidence_path_readable(path: Path, tenant_id: int) -> Path:
    """Resolve and require the file to sit under the tenant (or legacy) data root."""
    # @lat: [[authorization#Evidence file security]]
    try:
        resolved = Path(path).resolve()
    except OSError as exc:
        raise LookupError("evidence not found") from exc
    if not path_under_roots(resolved, evidence_storage_roots(tenant_id)):
        raise LookupError("evidence not found")
    if not resolved.is_file():
        raise LookupError("evidence not found")
    return resolved


def client_may_download_evidence(role: str, kind: str) -> bool:
    """Whether ``role`` may download an evidence row of ``kind``."""
    # @lat: [[authorization#Evidence file security]]
    if role != "client_viewer":
        return True
    return kind in CLIENT_DOWNLOADABLE_KINDS


def tenant_ids_for(s: Session, principal) -> set[int] | None:
    """Tenant IDs the principal may access. ``None`` means unrestricted.

    Admin is always unrestricted. Client viewers are limited to their home tenant
    and memberships (empty set if none). Other staff with no home tenant and no
    memberships are treated as platform operators (unrestricted); once assigned,
    they see only those tenants.
    """
    if principal is None:
        return None
    role = getattr(principal, "role", None)
    if role == "admin":
        return None
    ids: set[int] = set()
    if principal.tenant_id is not None:
        ids.add(principal.tenant_id)
    for m in s.scalars(select(TenantMembership).where(TenantMembership.user_id == principal.user_id)):
        ids.add(m.tenant_id)
    if not ids:
        if role == "client_viewer":
            return set()
        return None
    return ids


def ensure_tenant_membership(s: Session, principal, tenant_id: int) -> None:
    """Grant membership so a scoped staff user can access a tenant they create."""
    if principal is None or getattr(principal, "role", None) == "admin":
        return
    allowed = tenant_ids_for(s, principal)
    if allowed is None or tenant_id in allowed:
        return
    if s.scalar(
        select(TenantMembership).where(
            TenantMembership.user_id == principal.user_id, TenantMembership.tenant_id == tenant_id
        )
    ):
        return
    s.add(TenantMembership(user_id=principal.user_id, tenant_id=tenant_id, role=principal.role))
    s.flush()


def scoped(s: Session, model, principal):
    """Return a ``select(model)`` filtered by the principal's tenant access."""
    q = select(model)
    allowed = tenant_ids_for(s, principal)
    if allowed is None:
        return q
    if model is Engagement:
        return q.where(Engagement.tenant_id.in_(allowed))
    if model is Tenant:
        return q.where(Tenant.id.in_(allowed))
    if hasattr(model, "engagement_id"):
        return q.join(Engagement, model.engagement_id == Engagement.id).where(Engagement.tenant_id.in_(allowed))
    return q.where(False)


def assert_engagement_access(s: Session, engagement_id: int, principal) -> Engagement:
    eng = s.get(Engagement, engagement_id)
    if not eng:
        raise LookupError(f"engagement {engagement_id} not found")
    allowed = tenant_ids_for(s, principal)
    if allowed is not None and eng.tenant_id not in allowed:
        raise LookupError(f"engagement {engagement_id} not found")
    return eng


# ---------------------------------------------------------------- engagements


def get_or_create_tenant(
    s: Session,
    name: str,
    actor: str,
    *,
    industry: str = "",
    country: str = "",
    regulatory_status: str = "",
    technical_scope: list[str] | None = None,
    contact_name: str = "",
    contact_email: str = "",
) -> Tenant:
    name = name.strip()
    if not name:
        raise ServiceError("client name is required")
    if contact_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", contact_email.strip()):
        raise ServiceError("contact email looks invalid")
    # Validate catalogue keys when provided (legacy free-text industry remains readable).
    from attestra.compliance.recommend import load_countries, load_industries, load_technical_scopes

    ind = (industry or "").strip()
    cty = (country or "").strip().upper()
    reg = (regulatory_status or "").strip()
    scopes = list(dict.fromkeys((technical_scope or []) or []))
    industries = load_industries()
    countries = load_countries()
    known_scopes = load_technical_scopes()
    if ind and ind not in industries:
        # Allow legacy free-text until the client is edited onto a catalogue key.
        pass
    if cty and cty not in countries:
        raise ServiceError(f"unknown country {cty!r}; choose from the country catalogue")
    bad_scopes = [x for x in scopes if x not in known_scopes]
    if bad_scopes:
        raise ServiceError(f"unknown technical scope {bad_scopes}; choose from {sorted(known_scopes)}")

    t = s.scalar(select(Tenant).where(Tenant.name == name))
    if t is None:
        t = Tenant(name=name)
        s.add(t)
        s.flush()
        audit.record(s, actor, "tenant.create", "tenant", t.id, name=name)
        from attestra.credits import ensure_account

        ensure_account(s, t.id, actor=actor)
    changed = {}
    for field, value in (
        ("industry", ind),
        ("country", cty),
        ("regulatory_status", reg),
        ("contact_name", contact_name),
        ("contact_email", contact_email),
    ):
        if value and value != getattr(t, field):
            setattr(t, field, value)
            changed[field] = value
    if scopes and list(t.technical_scope or []) != scopes:
        t.technical_scope = scopes
        changed["technical_scope"] = scopes
    if changed:
        audit.record(s, actor, "tenant.update", "tenant", t.id, **changed)
    return t


def create_engagement(
    s: Session,
    *,
    tenant: str,
    name: str,
    type: str,
    frameworks: list[str],
    window_start: date | None,
    window_end: date | None,
    actor: str,
    industry: str = "",
    country: str = "",
    regulatory_status: str = "",
    technical_scope: list[str] | None = None,
    contact_name: str = "",
    contact_email: str = "",
    principal=None,
) -> Engagement:
    if not name.strip():
        raise ServiceError("engagement name is required")
    type = normalize_engagement_type(type)
    if type not in NEW_ENGAGEMENT_TYPES:
        raise ServiceError(
            f"type must be one of {NEW_ENGAGEMENT_TYPES} "
            f"({', '.join(engagement_type_label(t) for t in NEW_ENGAGEMENT_TYPES)}); "
            "retest and continuous are preserved for existing engagements only"
        )
    from attestra.compliance import load_library

    known = tuple(load_library().frameworks) or FRAMEWORKS
    bad = [f for f in frameworks if f not in known]
    if bad:
        raise ServiceError(f"unknown frameworks {bad}; choose from {known}")
    if window_start and window_end and window_end < window_start:
        raise ServiceError("window_end is before window_start")
    t = get_or_create_tenant(
        s,
        tenant,
        actor,
        industry=industry,
        country=country,
        regulatory_status=regulatory_status,
        technical_scope=technical_scope,
        contact_name=contact_name,
        contact_email=contact_email,
    )
    ensure_tenant_membership(s, principal, t.id)
    e = Engagement(
        tenant_id=t.id, name=name.strip(), type=type, frameworks=frameworks, window_start=window_start, window_end=window_end
    )
    s.add(e)
    s.flush()
    audit.record(s, actor, "engagement.create", "engagement", e.id, name=name, type=type, frameworks=frameworks)
    return e


def update_engagement(
    s: Session,
    engagement_id: int,
    *,
    name: str,
    window_start: date | None,
    window_end: date | None,
    frameworks: list[str],
    actor: str,
    client_name: str | None = None,
) -> Engagement:
    """Edit an engagement's name, client name, test window and frameworks (UI audit #47). Audited.

    Delete is intentionally omitted: engagements hold signed evidence.
    """
    e = get_engagement(s, engagement_id)
    if not name.strip():
        raise ServiceError("engagement name is required")
    from attestra.compliance import load_library

    known = tuple(load_library().frameworks) or FRAMEWORKS
    bad = [f for f in frameworks if f not in known]
    if bad:
        raise ServiceError(f"unknown frameworks {bad}; choose from {known}")
    if window_start and window_end and window_end < window_start:
        raise ServiceError("the test window end must be on or after the start date")
    before = {
        "name": e.name,
        "client_name": e.tenant.name if e.tenant else "",
        "window_start": str(e.window_start or ""),
        "window_end": str(e.window_end or ""),
        "frameworks": list(e.frameworks or []),
    }
    e.name = name.strip()
    e.window_start = window_start
    e.window_end = window_end
    e.frameworks = list(frameworks)
    if client_name is not None and client_name.strip() and e.tenant is not None:
        new_client = client_name.strip()
        if new_client != e.tenant.name:
            clash = s.scalar(select(Tenant).where(Tenant.name == new_client, Tenant.id != e.tenant_id))
            if clash:
                raise ServiceError(f"another client is already named {new_client!r}")
            e.tenant.name = new_client
    audit.record(
        s, actor, "engagement.update", "engagement", e.id, before=before,
        after={
            "name": e.name,
            "client_name": e.tenant.name if e.tenant else "",
            "window_start": str(window_start or ""),
            "window_end": str(window_end or ""),
            "frameworks": list(frameworks),
        },
    )
    return e


def get_engagement(s: Session, engagement_id: int, principal=None) -> Engagement:
    if principal is not None:
        return assert_engagement_access(s, engagement_id, principal)
    e = s.get(Engagement, engagement_id)
    if not e:
        raise LookupError(f"engagement {engagement_id} not found")
    return e


def add_authorization(
    s: Session,
    engagement_id: int,
    *,
    filename: str,
    data: bytes,
    signer: str,
    signed_on: date,
    expires_on: date,
    rules_of_engagement: str,
    actor: str,
    environments: list[str] | None = None,
) -> Authorization:
    eng = get_engagement(s, engagement_id)
    if not data:
        raise ServiceError("authorization document is empty")
    if expires_on < signed_on:
        raise ServiceError("expires_on is before signed_on")
    environments = list(dict.fromkeys(environments or []))
    if not environments:
        raise ServiceError("select at least one environment the client authorized (production, staging, ...)")
    bad = [e for e in environments if e not in ENVIRONMENTS]
    if bad:
        raise ServiceError(f"unknown environments {bad}; choose from {ENVIRONMENTS}")
    sha = _sha256(data)
    path = _store(eng.tenant_id, "evidence", sha, filename, data)
    a = Authorization(
        engagement_id=engagement_id,
        document_name=filename,
        document_path=str(path),
        sha256=sha,
        signer=signer,
        signed_on=signed_on,
        expires_on=expires_on,
        rules_of_engagement=rules_of_engagement,
        environments=environments,
    )
    eng.authorizations.append(a)  # keep the loaded collection current within this session
    s.flush()
    audit.record(
        s, actor, "authorization.add", "authorization", a.id,
        engagement_id=engagement_id, sha256=sha, signer=signer, environments=environments,
    )
    return a


def authorization_public_dict(a: Authorization, *, include_document_access: bool = False) -> dict:
    """Safe authorization metadata for API/UI. Never includes ``document_path``."""
    out = {
        "id": a.id,
        "engagement_id": a.engagement_id,
        "document_name": a.document_name,
        "signer": a.signer,
        "signed_on": a.signed_on,
        "expires_on": a.expires_on,
        "environments": list(a.environments or []),
        "rules_of_engagement": a.rules_of_engagement or "",
        "sha256": a.sha256,
        "valid": a.is_valid(),
        "document_available": True,
    }
    if include_document_access:
        out["document_download"] = True
    return out


def open_authorization_document(
    s: Session,
    authorization_id: int,
    *,
    principal,
) -> tuple[Authorization, Path]:
    """Return the authorization row and on-disk path for Super Admin download only.

    Enforces ``authorization.document`` (admin), engagement tenant access, and
    path containment under the tenant data root. Does not put storage paths in
    raised error messages. Remains enforced when ``SUBSCRIPTION_SERVICE=OFF``.
    """
    # @lat: [[authorization#Authorization record#Super Admin document access]]
    from attestra.auth.roles import has_permission

    if principal is None or not has_permission(getattr(principal, "role", ""), "authorization.document"):
        raise PermissionError("only a Super Admin can access signed authorization documents")
    a = s.get(Authorization, authorization_id)
    if a is None:
        raise LookupError("authorization not found")
    eng = get_engagement(s, a.engagement_id, principal)
    raw = Path(a.document_path)
    try:
        path = raw.resolve()
    except OSError as exc:
        raise LookupError("authorization document not found") from exc
    tenant_root = (config.DATA_DIR / "tenants" / str(eng.tenant_id)).resolve()
    data_root = config.DATA_DIR.resolve()
    if not (path.is_relative_to(tenant_root) or path.is_relative_to(data_root)):
        raise LookupError("authorization document not found")
    if not path.is_file():
        raise LookupError("authorization document not found")
    audit.record(
        s,
        getattr(principal, "actor", None) or getattr(principal, "username", "unknown"),
        "authorization.document_download",
        "authorization",
        a.id,
        engagement_id=eng.id,
        sha256=a.sha256,
    )
    return a, path


def authorized_environments(eng: Engagement, on: date | None = None) -> set[str]:
    envs: set[str] = set()
    for a in eng.authorizations:
        if a.is_valid(on):
            envs.update(a.environments or ENVIRONMENTS)  # empty = legacy record covering all
    return envs


def add_asset(
    s: Session,
    engagement_id: int,
    *,
    kind: str,
    identifier: str,
    criticality: int = 3,
    exposure: str = "internal",
    in_cde: bool = False,
    owner: str = "",
    actor: str,
    name: str = "",
    environment: str = "production",
    test_types: list[str] | None = None,
    intrusive_allowed: bool = False,
    notes: str = "",
) -> Asset:
    eng = get_engagement(s, engagement_id)
    kind = {"url": "web_app"}.get(kind, kind)  # pre-0.1.1 name
    identifier = identifier.strip()
    if kind not in ASSET_KINDS:
        raise ServiceError(f"kind must be one of {list(ASSET_KINDS)}")
    if not identifier:
        raise ServiceError("target identifier is required")
    if kind in ("web_app", "api"):
        parts = urlsplit(identifier)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ServiceError("web app / API targets must be full URLs, e.g. https://staging.example.com")
    if environment not in ENVIRONMENTS:
        raise ServiceError(f"environment must be one of {ENVIRONMENTS}")
    if not 1 <= criticality <= 5:
        raise ServiceError("criticality must be 1..5")
    if exposure not in ("internet", "internal"):
        raise ServiceError("exposure must be 'internet' or 'internal'")
    allowed = allowed_test_types_for(eng.type)
    if test_types:
        tests = list(dict.fromkeys(test_types))
    else:
        tests = default_tests_for(kind, eng.type)
    bad = [x for x in tests if x not in TEST_TYPES]
    if bad:
        raise ServiceError(f"unknown test types {bad}; choose from {list(TEST_TYPES)}")
    disallowed = [x for x in tests if x not in allowed]
    if disallowed:
        raise ServiceError(
            f"test types {disallowed} are not part of the {engagement_type_label(eng.type)} workflow; "
            f"choose from {sorted(allowed)}"
        )
    if any(_asset_key(x.identifier) == _asset_key(identifier) for x in eng.assets):
        raise ServiceError(f"target '{identifier}' is already in scope for this engagement")
    a = Asset(
        engagement_id=engagement_id,
        kind=kind,
        identifier=identifier,
        name=name.strip(),
        environment=environment,
        test_types=tests,
        intrusive_allowed=intrusive_allowed,
        criticality=criticality,
        exposure=exposure,
        in_cde=in_cde,
        owner=owner,
        notes=notes,
    )
    eng.assets.append(a)  # keep the loaded collection current within this session
    s.flush()
    audit.record(
        s, actor, "asset.add", "asset", a.id, engagement_id=engagement_id, identifier=identifier,
        environment=environment, test_types=tests, intrusive_allowed=intrusive_allowed, in_cde=in_cde,
    )
    return a


def ensure_ownership_tokens(eng: Engagement) -> None:
    """Give every target that needs ownership proof a token, so the UI can show it."""
    from attestra.runner import ownership
    from attestra.runner.policy import OWNERSHIP_KINDS

    for a in eng.assets:
        if a.kind in OWNERSHIP_KINDS and not a.ownership_token:
            ownership.ensure_token(a)


def set_ownership_token(
    s: Session, engagement_id: int, asset_id: int, token: str, *, actor: str
) -> Asset:
    """Set or reuse an ownership token on a target (lead/admin enforced in the UI).

    Validates token format, clears ``ownership_verified_at`` when the value changes
    (must re-verify), and audits ``asset.ownership_token_set`` with a suffix only.
    """
    from attestra.runner import ownership
    from attestra.runner.policy import OWNERSHIP_KINDS

    get_engagement(s, engagement_id)
    a = s.get(Asset, asset_id)
    if not a or a.engagement_id != engagement_id:
        raise LookupError(f"target {asset_id} is not in this engagement")
    if a.kind not in OWNERSHIP_KINDS:
        raise ServiceError(f"{ASSET_KINDS.get(a.kind, a.kind)} targets do not need ownership proof")
    try:
        previous = a.ownership_token or ""
        cleaned = ownership.set_token(a, token, actor=actor)
    except ownership.OwnershipError as exc:
        raise ServiceError(str(exc)) from exc
    changed = cleaned != previous
    audit.record(
        s,
        actor,
        "asset.ownership_token_set",
        "asset",
        a.id,
        engagement_id=engagement_id,
        identifier=a.identifier,
        token_suffix=ownership.token_fingerprint(cleaned),
        changed=changed,
    )
    return a


def ownership_methods(s: Session, asset_ids: list[int]) -> dict[int, str]:
    """Method ('dns' | 'file' | 'owner_confirmed') of the latest successful ownership proof per target.

    Read from the audit log: ``asset.ownership_verified`` (DNS / file) and ``asset.ownership_confirmed``.
    """
    from attestra.models import AuditEvent

    if not asset_ids:
        return {}
    out: dict[int, str] = {}
    rows = s.scalars(
        select(AuditEvent).where(
            AuditEvent.action.in_(["asset.ownership_verified", "asset.ownership_confirmed"]),
            AuditEvent.entity == "asset",
            AuditEvent.entity_id.in_(asset_ids),
        ).order_by(AuditEvent.id)
    )
    for ev in rows:
        out[ev.entity_id] = (ev.details or {}).get("method", "")
    return out


def verify_asset_ownership(s: Session, engagement_id: int, asset_id: int, *, actor: str):
    """Run the ownership check (one DNS TXT lookup, at most one GET of the well-known file).

    Returns an ``OwnershipCheck``; never scans. Success and failure are both audited.
    """
    from attestra.runner import ownership
    from attestra.runner.authorization import AuthorizationError, authorize_target, scope_for_engagement
    from attestra.runner.policy import OWNERSHIP_KINDS

    get_engagement(s, engagement_id)
    a = s.get(Asset, asset_id)
    if not a or a.engagement_id != engagement_id:
        raise LookupError(f"target {asset_id} is not in this engagement")
    if a.kind not in OWNERSHIP_KINDS:
        raise ServiceError(f"{ASSET_KINDS.get(a.kind, a.kind)} targets do not need ownership proof")
    if a.ownership_verified_at is not None:
        result = ownership.OwnershipCheck(ok=True, method=ownership_methods(s, [a.id]).get(a.id, ""))
        result.notes.append("This target is already verified.")
        return result

    scope, scope_error = None, ""
    try:
        scope = scope_for_engagement(s, engagement_id)
        if (
            config.signed_authorization_required()
            and a.environment not in authorized_environments(a.engagement)
        ):
            raise AuthorizationError(f"the {a.environment} environment is not authorized")
        authorize_target(scope, ownership.well_known_url(a), "url")
    except AuthorizationError as exc:
        scope, scope_error = None, str(exc)

    result = ownership.check(a, scope=scope, scope_error=scope_error)
    if result.ok:
        audit.record(
            s, actor, "asset.ownership_verified", "asset", a.id, engagement_id=engagement_id,
            identifier=a.identifier, method=result.method, verified_at=a.ownership_verified_at.isoformat(),
        )
    else:
        audit.record(
            s, actor, "asset.ownership_check_failed", "asset", a.id, engagement_id=engagement_id,
            identifier=a.identifier, reason=result.message[:500],
        )
    return result


def confirm_private_ownership(
    s: Session, engagement_id: int, asset_id: int, *, actor: str, confirmed: bool, confirmed_by: str
) -> Asset:
    """Option C: the owner confirms control of a target on a private network address.

    Private addresses have no DNS name, and the well-known file check refuses non-global IPs on purpose,
    so a lead or admin records the owner's confirmation instead. Only literal private / loopback IPs or
    ``localhost`` qualify (never public IPs, domain names or blocked ranges), and the target's
    environment must be in a valid signed authorization. Audited as ``asset.ownership_confirmed``.
    """
    from attestra.runner import authorization
    from attestra.runner.policy import OWNERSHIP_KINDS

    eng = get_engagement(s, engagement_id)
    a = s.get(Asset, asset_id)
    if not a or a.engagement_id != engagement_id:
        raise LookupError(f"target {asset_id} is not in this engagement")
    if a.kind not in OWNERSHIP_KINDS:
        raise ServiceError(f"{ASSET_KINDS.get(a.kind, a.kind)} targets do not need ownership proof")
    if a.ownership_verified_at is not None:
        raise ServiceError("This target is already verified.")
    host = authorization.owner_confirm_host(a.kind, a.identifier)
    if not host:
        raise ServiceError(
            "Owner confirmation is only for private network addresses such as 192.168.x.x or 10.x.x.x. "
            "For this target, use the DNS record or the file."
        )
    if (
        config.signed_authorization_required()
        and a.environment not in authorized_environments(eng)
    ):
        raise ServiceError(
            f"The {a.environment} environment is not covered by a valid signed authorization. "
            "Add or renew the signed authorization first."
        )
    if not confirmed:
        raise ServiceError("Tick the box to confirm you own or control this private address.")
    who = " ".join((confirmed_by or "").split())
    if not who:
        raise ServiceError("Type who is confirming, as name and role.")
    if len(who) > 200:
        raise ServiceError("Confirmed by is too long (200 characters at most).")
    a.ownership_verified_at = utcnow()
    audit.record(
        s, actor, "asset.ownership_confirmed", "asset", a.id, engagement_id=engagement_id,
        identifier=a.identifier, host=host, method=authorization.OWNER_CONFIRMED, confirmed_by=who,
        verified_at=a.ownership_verified_at.isoformat(),
    )
    return a


def remove_asset(s: Session, asset_id: int, *, actor: str) -> None:
    a = s.get(Asset, asset_id)
    if not a:
        raise LookupError(f"target {asset_id} not found")
    linked = s.scalar(select(func.count(Finding.id)).where(Finding.asset_id == asset_id)) or 0
    if linked:
        raise ServiceError(f"target has {linked} finding(s) linked; it stays in scope for the audit trail")
    audit.record(s, actor, "asset.remove", "asset", a.id, engagement_id=a.engagement_id, identifier=a.identifier)
    a.engagement.assets.remove(a)
    s.delete(a)


# ---------------------------------------------------------------- imports


def _asset_key(identifier: str) -> str:
    ident = identifier.strip().lower()
    if "://" in ident:
        return urlsplit(ident).netloc
    return ident


def match_asset(assets: list[Asset], location: str) -> Asset | None:
    """Match a finding location to a target on label boundaries, so that
    staging.shop.example.com never matches the production target shop.example.com."""
    loc = location.lower()
    best = None
    for a in assets:
        key = _asset_key(a.identifier)
        if not key:
            continue
        if re.search(r"(^|[^a-z0-9.\-])" + re.escape(key) + r"($|[^a-z0-9.\-])", loc):
            if best is None or len(key) > len(_asset_key(best.identifier)):
                best = a
    return best


def import_results(
    s: Session,
    engagement_id: int,
    *,
    tool: str,
    filename: str,
    data: bytes,
    actor: str,
    default_asset_id: int | None = None,
) -> ImportRun:
    """Import a scanner result file.

    When ``SIGNED_AUTHORIZATION=ON`` (default), requires a currently valid
    signed authorization and refuses findings in unauthorized environments.
    """
    # @lat: [[authorization#Import gate]]
    # @lat: [[import-pipeline#Import run]]
    eng = get_engagement(s, engagement_id)
    auth_required = config.signed_authorization_required()
    if auth_required and not any(a.is_valid() for a in eng.authorizations):
        raise ServiceError("record a currently valid signed authorization before importing results")
    try:
        parsed = importers.parse(tool, data)
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        raise ServiceError(f"could not parse {tool} file: {exc}") from exc

    # Every finding that lands on a target must be in an environment the client authorized.
    allowed_envs = authorized_environments(eng) if auth_required else None
    assets = list(eng.assets)
    fallback = next((a for a in assets if default_asset_id is not None and a.id == default_asset_id), None)
    matched = [(nf, match_asset(assets, nf.location) or fallback) for nf in parsed]
    # Burp/Nessus multi-host exports: drop hosts with no matching in-scope asset.
    skipped_hosts = 0
    if tool in ("burp", "nessus"):
        kept = [(nf, a) for nf, a in matched if a is not None]
        skipped_hosts = len(matched) - len(kept)
        matched = kept
    if allowed_envs is not None:
        outside = sorted(
            {
                f"{a.identifier} ({a.environment})"
                for _, a in matched
                if a and a.environment not in allowed_envs
            }
        )
        if outside:
            raise ServiceError(
                "results include targets in environments the client has not authorized: "
                + ", ".join(outside) + ". Add a signed authorization covering them first."
            )

    from attestra.evidence.mask import mask_bytes

    ct = "application/json" if filename.lower().endswith((".json", ".jsonl", ".sarif")) else "text/plain"
    masked, _mask_report = mask_bytes(data, ct)
    sha = _sha256(masked)
    path = _store(eng.tenant_id, "imports", sha, filename, masked)
    run = ImportRun(engagement_id=engagement_id, tool=tool, filename=filename, raw_path=str(path), sha256=sha, imported_by=actor)
    # C5: derive passed/failed check rows for tools that expose them.
    try:
        from attestra import checks as checklib

        check_rows: list[dict] = []
        if tool == "zap":
            check_rows = checklib.zap_checks_from_report(masked)
        elif tool == "webcheck":
            try:
                doc = json.loads(masked.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                doc = {}
            if isinstance(doc, dict):
                check_rows = checklib.checks_from_webcheck_report(doc)
        elif tool == "observatory":
            from attestra.importers.observatory import checks_from_observatory

            check_rows = checks_from_observatory(masked)
        if check_rows:
            run.checks_json = json.dumps({"checks": check_rows})
            try:
                checklib.write_checks_sidecar(path, check_rows)
            except OSError:
                pass
    except Exception:
        # Check derivation must never block an import.
        pass
    # Scanner tool notes (testssl engine_problem / Nessus scan info) — stored, not findings.
    if tool == "testssl":
        try:
            from attestra.importers import testssl as testssl_importer

            note_list = testssl_importer.extract_notes(masked)
            if note_list:
                run.notes_json = json.dumps({"notes": note_list})
        except Exception:
            pass
    elif tool == "nessus":
        try:
            from attestra.importers import nessus as nessus_importer

            note_list = nessus_importer.extract_notes(masked)
            if note_list:
                run.notes_json = json.dumps({"notes": note_list})
        except Exception:
            pass
    s.add(run)
    s.flush()

    existing_rows = list(s.scalars(select(Finding).where(Finding.engagement_id == engagement_id)))
    existing = {f.fingerprint: f for f in existing_rows}
    now = utcnow()
    new = updated = suppressed = 0
    unmatched = skipped_hosts + sum(1 for _, a in matched if a is None)
    from attestra import tuning
    from attestra.dedup import classify_match, find_best_soft_match

    rules = tuning.active_suppressions(s, eng.tenant_id, engagement_id)
    known_fps = set(existing)

    def _record_observation(
        finding: Finding,
        nf,
        *,
        fp: str,
        match_confidence: float | None,
        match_rationale: str,
        possible_duplicate_of: int | None = None,
    ) -> None:
        obs = FindingObservation(
            finding_id=finding.id,
            engagement_id=engagement_id,
            import_run_id=run.id,
            tool=nf.tool,
            tool_version=getattr(nf, "tool_version", "") or "",
            original_id=(getattr(nf, "original_id", "") or nf.rule_id or "")[:200],
            title=(nf.title or "")[:500],
            description=nf.description or "",
            severity=nf.severity or "",
            confidence=str(getattr(nf, "confidence", "") or ""),
            location=(nf.location or "")[:1000],
            param=(nf.param or "")[:200],
            package=(nf.package or "")[:200],
            package_version=(getattr(nf, "package_version", "") or "")[:100],
            fixed_version=(getattr(nf, "fixed_version", "") or "")[:100],
            cwe=nf.cwe,
            cves=list(nf.cves or []),
            rule_ids=[nf.rule_id] if nf.rule_id else [],
            line_start=getattr(nf, "line_start", None),
            line_end=getattr(nf, "line_end", None),
            evidence_refs=list(getattr(nf, "evidence_refs", None) or []),
            fingerprint=fp,
            match_confidence=match_confidence,
            match_rationale=(match_rationale or "")[:500],
            possible_duplicate_of=possible_duplicate_of,
            observed_at=now,
        )
        s.add(obs)

    for nf, asset in matched:
        asset_id = asset.id if asset else None
        variant = getattr(nf, "variant", "") or ""
        raw_kwargs = dict(
            location=nf.location,
            cwe=nf.cwe,
            cves=nf.cves,
            title=nf.title,
            param=nf.param,
            package=nf.package,
            asset_id=asset_id,
            variant=variant,
        )
        # CAA: webcheck dns-caa and testssl DNS_CAArecord share one merge key (R15).
        merge_kwargs = canonicalize_for_merge(**raw_kwargs)
        fp = fingerprint(**merge_kwargs)
        f = existing.get(fp)
        match_confidence = 1.0 if f is not None else None
        match_rationale = "exact_fingerprint" if f is not None else ""
        possible_dup: int | None = None

        def _adopt(legacy_fp: str) -> None:
            nonlocal f, match_confidence, match_rationale
            legacy = existing.get(legacy_fp)
            if legacy is None:
                return
            f = legacy
            del existing[legacy_fp]
            f.fingerprint = fp
            existing[fp] = f
            match_confidence = 1.0
            match_rationale = "legacy_fingerprint"

        # Raw (pre-canonical) key so older testssl DNS_CAArecord rows still match.
        if f is None:
            raw_fp = fingerprint(**raw_kwargs)
            if raw_fp != fp:
                _adopt(raw_fp)
        # Legacy rows stored before variant existed: same title, old fingerprint (no variant).
        if f is None and variant:
            legacy_fp = fingerprint(
                location=nf.location,
                cwe=nf.cwe,
                cves=nf.cves,
                title=nf.title,
                param=nf.param,
                package=nf.package,
                asset_id=asset_id,
                variant="",
            )
            legacy = existing.get(legacy_fp)
            if legacy is not None and normalize_title(legacy.title) == normalize_title(nf.title):
                _adopt(legacy_fp)
        # Older testssl CAA shapes (host:port + DNS_CAArecord param/variant).
        if f is None and is_caa_variant(variant):
            for alt_fp in caa_legacy_fingerprints(host=str(merge_kwargs["location"]), asset_id=asset_id):
                if alt_fp == fp:
                    continue
                _adopt(alt_fp)
                if f is not None:
                    break
        # Phase 6: high-confidence cross-tool soft match when exact fingerprint misses.
        if f is None:
            soft = find_best_soft_match(
                engagement_findings=list(existing.values()),
                tool=nf.tool,
                location=nf.location,
                cwe=nf.cwe,
                cves=list(nf.cves or []),
                title=nf.title,
                param=nf.param,
                package=nf.package,
                asset_id=asset_id,
            )
            kind = classify_match(soft.confidence)
            if kind == "merge" and soft.finding is not None:
                f = soft.finding
                match_confidence = soft.confidence
                match_rationale = f"soft:{soft.rationale}"
                # Align fingerprint to the canonical row's key so later exact matches stick.
                if f.fingerprint not in existing:
                    existing[f.fingerprint] = f
            elif kind == "ambiguous" and soft.finding is not None:
                possible_dup = soft.finding.id
                match_confidence = soft.confidence
                match_rationale = f"ambiguous:{soft.rationale}"
        rule = tuning.first_match(rules, nf) if f is None and rules else None
        if rule is not None:
            # Suppressed (Phase 7.4): not stored; counted on the rule and in the audit event.
            rule.hits += 1
            suppressed += 1
            continue
        added_cross_tool = False
        if f is None:
            f = Finding(
                engagement_id=engagement_id,
                asset_id=asset.id if asset else None,
                fingerprint=fp,
                title=nf.title[:500],
                description=nf.description,
                recommendation=nf.recommendation,
                tools=[nf.tool],
                rule_ids=[nf.rule_id] if nf.rule_id else [],
                cwe=nf.cwe,
                cves=nf.cves,
                location=(nf.location + (f" [param: {nf.param}]" if nf.param else ""))[:1000],
                severity=nf.severity,
                cvss_score=nf.cvss_score,
                cvss_vector=scoring.soft_cvss_vector(nf.cvss_vector),
                first_seen=now,
                last_seen=now,
                dedup_confidence=match_confidence,
                dedup_rationale=(match_rationale or "new")[:500],
            )
            f.asset = asset
            _apply_owasp(f)
            s.add(f)
            s.flush()  # need finding.id for observation FK
            existing[fp] = f
            existing_rows.append(f)
            new += 1
        else:
            # Same issue seen again (another tool or a rescan): merge, keep the higher severity.
            if nf.tool and nf.tool not in (f.tools or []):
                added_cross_tool = True
            f.occurrences += 1
            f.last_seen = now
            if nf.tool not in f.tools:
                f.tools = [*f.tools, nf.tool]
            if nf.rule_id and nf.rule_id not in f.rule_ids:
                f.rule_ids = [*f.rule_ids, nf.rule_id]
            if match_confidence is not None:
                f.dedup_confidence = match_confidence
                f.dedup_rationale = (match_rationale or "")[:500]
            if is_cert_expiry_variant(variant):
                # Band change (30→14→7) updates the same row: title and severity in place.
                f.title = nf.title[:500]
                f.severity = nf.severity
                if nf.description:
                    f.description = nf.description
                if nf.recommendation:
                    f.recommendation = nf.recommendation
            elif _rank(nf.severity) > _rank(f.severity):
                f.severity = nf.severity
            if f.cvss_score is None and nf.cvss_score is not None:
                f.cvss_score = nf.cvss_score
                if not (f.cvss_vector or "").strip():
                    f.cvss_vector = scoring.soft_cvss_vector(nf.cvss_vector)
            elif not (f.cvss_vector or "").strip() and nf.cvss_vector:
                f.cvss_vector = scoring.soft_cvss_vector(nf.cvss_vector)
            if not f.cwe and nf.cwe:
                f.cwe = nf.cwe
                _apply_owasp(f)
            if f.status == "fixed":
                # Reappeared after being marked fixed: reopen.
                f.status = "validated" if f.validated_by else "triaged"
                audit.record(s, actor, "finding.reopened", "finding", f.id, import_run=run.id)
            updated += 1
            if f.id is None:
                s.flush()
        _record_observation(
            f,
            nf,
            fp=fp,
            match_confidence=match_confidence if match_confidence is not None else 0.0,
            match_rationale=match_rationale or ("new" if possible_dup is None else f"ambiguous:{match_rationale}"),
            possible_duplicate_of=possible_dup,
        )
        # Light audit for soft/ambiguous and cross-tool exact merges (Phase 9 auditability).
        if match_rationale.startswith("soft:") or match_rationale.startswith("ambiguous:"):
            audit.record(
                s,
                actor,
                "finding.dedup",
                "finding",
                f.id,
                match=match_rationale.split(":", 1)[0],
                confidence=match_confidence,
                rationale=(match_rationale or "")[:500],
                tool=nf.tool,
                import_run=run.id,
                possible_duplicate_of=possible_dup,
            )
        elif added_cross_tool and match_rationale == "exact_fingerprint":
            audit.record(
                s,
                actor,
                "finding.dedup",
                "finding",
                f.id,
                match="exact_cross_tool",
                confidence=match_confidence,
                rationale=match_rationale,
                tool=nf.tool,
                import_run=run.id,
            )
        rescore(f)

    # Renewed cert (>30 days left): close open expiry findings for this target.
    # Healthy imports emit no expiry finding, so matched may be empty — still close by asset.
    # Use the original ``data`` (not masked): date-like notAfter strings can look like phones.
    if tool in ("testssl", "webcheck"):
        from attestra.cert_expiry import close_renewed_for_asset, end_date_from_raw

        end = end_date_from_raw(tool, data)
        if end is not None:
            asset_ids = {a.id for _, a in matched if a is not None}
            if default_asset_id is not None:
                asset_ids.add(default_asset_id)
            if not asset_ids:
                # No finding rows (healthy cert): match host from the saved summary to assets.
                from attestra.fingerprint import caa_host

                host = ""
                if tool == "testssl":
                    from attestra.importers import testssl as testssl_importer

                    summary = testssl_importer.summarize(data)
                    host = caa_host(str(summary.get("host") or ""))
                for a in assets:
                    if host and (host in caa_host(a.identifier) or caa_host(a.identifier) in host):
                        asset_ids.add(a.id)
                    elif not host and a.kind in ("web_app", "host", "url"):
                        asset_ids.add(a.id)
            for aid in asset_ids:
                close_renewed_for_asset(
                    s, engagement_id=engagement_id, asset_id=aid, end=end, actor=actor,
                )

    run.new_findings, run.updated_findings, run.unmatched_findings = new, updated, unmatched
    s.flush()
    from attestra.proof.hooks import after_import

    after_import(s, engagement_id, tool, data, [existing[fp] for fp in existing if fp not in known_fps], actor=actor)
    audit.record(
        s, actor, "import.create", "import_run", run.id,
        engagement_id=engagement_id, tool=tool, sha256=sha, parsed=len(parsed), new=new, updated=updated,
        unmatched=unmatched, suppressed=suppressed,
    )
    return run


def _rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)


def _apply_owasp(f: Finding) -> None:
    from attestra.compliance.owasp import map_finding_to_owasp

    refs = map_finding_to_owasp(f)
    f.owasp_top10 = refs["owasp_top10"]
    f.asvs_ref = refs["asvs_ref"]
    f.wstg_ref = refs["wstg_ref"]


def _tenant_weights(f: Finding):
    from sqlalchemy.orm import object_session

    from attestra import tuning

    s = object_session(f)
    if s is None or f.engagement_id is None:
        return None
    eng = s.get(Engagement, f.engagement_id)
    return tuning.get_weights(s, eng.tenant_id) if eng else None


def rescore(f: Finding) -> None:
    a = f.asset
    f.risk_score = scoring.risk_score(
        f.cvss_score, f.severity, f.epss, f.kev,
        a.criticality if a else None, a.exposure if a else None, a.in_cde if a else False,
        weights=_tenant_weights(f),
    )
    if f.sla_due is None:
        f.sla_due = scoring.sla_due(f.severity, (f.first_seen or utcnow()).date())


# ---------------------------------------------------------------- enrichment


def enrich(s: Session, *, kev_json: bytes | None = None, epss_csv: bytes | None = None, actor: str) -> dict:
    """Apply CISA KEV (JSON) and FIRST EPSS (CSV) feeds downloaded by the operator."""
    kev: set[str] = set()
    if kev_json:
        doc = json.loads(kev_json)
        kev = {v["cveID"].upper() for v in doc.get("vulnerabilities", []) if v.get("cveID")}
    epss: dict[str, float] = {}
    if epss_csv:
        text = epss_csv.decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if not line.startswith("#")]
        for row in csv.DictReader(io.StringIO("\n".join(lines))):
            try:
                epss[row["cve"].upper()] = float(row["epss"])
            except (KeyError, ValueError):
                continue
    touched = 0
    for f in s.scalars(select(Finding)):
        cves = [c.upper() for c in (f.cves or [])]
        if not cves:
            continue
        new_kev = any(c in kev for c in cves) if kev else f.kev
        scores = [epss[c] for c in cves if c in epss]
        new_epss = max(scores) if scores else f.epss
        if new_kev != f.kev or new_epss != f.epss:
            f.kev, f.epss = new_kev, new_epss
            rescore(f)
            touched += 1
    audit.record(s, actor, "enrich.apply", "finding", None, kev_entries=len(kev), epss_entries=len(epss), updated=touched)
    return {"kev_entries": len(kev), "epss_entries": len(epss), "findings_updated": touched}


# ---------------------------------------------------------------- findings


def list_passed_checks(s: Session, engagement_id: int) -> list[dict]:
    """C5: merged pass/fail/skipped check rows from scan runs and imports."""
    from attestra.checks import FAILED, PASSED, SKIPPED, load_checks_json, merge_check_lists

    lists: list[list[dict]] = []
    for run in s.scalars(select(ScanRun).where(ScanRun.engagement_id == engagement_id).order_by(ScanRun.id)):
        rows = load_checks_json(run.checks_json)
        if rows:
            lists.append(rows)
    for run in s.scalars(select(ImportRun).where(ImportRun.engagement_id == engagement_id).order_by(ImportRun.id)):
        rows = load_checks_json(run.checks_json)
        if rows:
            lists.append(rows)
    merged = merge_check_lists(*lists)
    order = {FAILED: 0, SKIPPED: 1, PASSED: 2}
    return sorted(merged, key=lambda r: (order.get(r.get("status", ""), 9), r.get("name") or r.get("id") or ""))


def _read_bytes(path_str: str) -> bytes | None:
    """Read a local path when it exists; ignore missing or non-file URIs."""
    if not path_str:
        return None
    try:
        p = Path(path_str)
        if p.is_file():
            return p.read_bytes()
    except OSError:
        return None
    return None


def _tls_host_key(value: str) -> str:
    """Normalize host/URL labels so scan and import summaries for the same target merge."""
    text = (value or "").strip().lower()
    if not text or text == "—":
        return ""
    text = text.replace("https://", "").replace("http://", "")
    text = text.split("/")[0]
    text = text.split(":")[0]
    return text


def tls_summaries(s: Session, engagement_id: int) -> list[dict]:
    """C8: TLS summary boxes from the latest testssl import/scan per engagement.

    Returns a list of summary dicts (usually one). When no testssl data is present,
    returns a single ``{"scanned": False}`` entry so the report can show "not scanned".
    """
    from attestra.cert_expiry import days_left, parse_not_after, today_utc
    from attestra.importers import testssl as testssl_importer

    by_host: dict[str, dict] = {}

    def _add(summary: dict, asset_label: str) -> None:
        if not summary.get("scanned"):
            return
        summary = dict(summary)
        summary["asset"] = asset_label or summary.get("host") or "—"
        end = parse_not_after(str(summary.get("cert_expiry") or ""))
        summary["days_left"] = days_left(end, today=today_utc()) if end else None
        key = _tls_host_key(summary["asset"]) or _tls_host_key(str(summary.get("host") or ""))
        if not key:
            key = summary["asset"]
        # First wins (callers pass newest scan runs first).
        if key not in by_host:
            by_host[key] = summary

    # Prefer finished scan runs (tied to an asset), then imports.
    for run in s.scalars(
        select(ScanRun)
        .where(ScanRun.engagement_id == engagement_id, ScanRun.tool == "testssl")
        .order_by(ScanRun.id.desc())
    ):
        raw = _read_bytes(run.raw_artifact_uri or "")
        if raw is None and run.import_run_id:
            imp = s.get(ImportRun, run.import_run_id)
            if imp:
                raw = _read_bytes(imp.raw_path or "")
        if raw is None:
            continue
        summary = testssl_importer.summarize(raw)
        asset = s.get(Asset, run.asset_id) if run.asset_id else None
        _add(summary, asset.identifier if asset else str(summary.get("host") or ""))

    for run in s.scalars(
        select(ImportRun)
        .where(ImportRun.engagement_id == engagement_id, ImportRun.tool == "testssl")
        .order_by(ImportRun.id.desc())
    ):
        raw = _read_bytes(run.raw_path or "")
        if raw is None:
            continue
        summary = testssl_importer.summarize(raw)
        _add(summary, str(summary.get("host") or run.filename or ""))

    if not by_host:
        return [{"scanned": False, "asset": "—"}]
    return list(by_host.values())


def list_findings(
    s: Session,
    engagement_id: int,
    status: str | None = None,
    severity: str | None = None,
    *,
    tool: str | None = None,
    asset_id: int | None = None,
) -> list[Finding]:
    """List findings for an engagement, optionally filtered by status/severity/tool/target."""
    from sqlalchemy.orm import joinedload

    q = select(Finding).options(joinedload(Finding.asset)).where(Finding.engagement_id == engagement_id)
    if status:
        q = q.where(Finding.status == status)
    if severity:
        q = q.where(Finding.severity == severity)
    if asset_id is not None:
        q = q.where(Finding.asset_id == asset_id)
    rows = list(s.scalars(q.order_by(Finding.risk_score.desc(), Finding.id)).unique())
    if tool:
        needle = tool.strip().lower()
        rows = [f for f in rows if any(str(t).lower() == needle for t in (f.tools or []))]
    return rows


def transition(
    s: Session,
    finding_id: int,
    *,
    to: str,
    actor: str,
    note: str = "",
    _from_accept_risk: bool = False,
) -> Finding:
    f = s.get(Finding, finding_id)
    if not f:
        raise LookupError(f"finding {finding_id} not found")
    allowed = TRANSITIONS.get(f.status, set())
    if to not in allowed:
        raise ServiceError(f"cannot move finding from '{f.status}' to '{to}'; allowed: {sorted(allowed) or 'none'}")
    # P0-3: risk_accepted requires a RiskAcceptance row via accept_risk(), not a bare status flip.
    if to == "risk_accepted" and not _from_accept_risk:
        raise ServiceError(
            "risk_accepted requires a risk-acceptance record (owner, expiry, rationale); "
            "use accept-risk / POST /risk-acceptances instead of a bare status change"
        )
    if to == "false_positive" and not note.strip():
        raise ServiceError(f"a reason is required to mark a finding {to}")
    if to == "validated":
        f.validated_by = actor
    if to == "retest_passed" and f.validated_by == actor and f.validated_by:
        # Not blocking, but recorded: independent retest is preferred.
        note = (note + " [retested by original validator]").strip()
    prev = f.status
    f.status = to
    audit.record(s, actor, "finding.transition", "finding", f.id, frm=prev, to=to, note=note)
    from attestra.webhooks.service import safe_emit_finding

    safe_emit_finding(s, f, "finding.status_changed", actor=actor, **{"from": prev})
    return f


def add_evidence(
    s: Session,
    finding_id: int,
    *,
    kind: str,
    filename: str,
    data: bytes,
    note: str,
    actor: str,
    content_type: str = "",
    source_tool: str = "",
    observation_id: int | None = None,
    import_run_id: int | None = None,
    parent_evidence_id: int | None = None,
    role: str = "original",
    redaction_status: str = "",
    capture_status: str = "success",
    capture_failure_reason: str = "",
    annotation_meta: dict | None = None,
) -> Evidence:
    from attestra.evidence.mask import mask_bytes

    f = s.get(Finding, finding_id)
    if not f:
        raise LookupError(f"finding {finding_id} not found")
    eng = get_engagement(s, f.engagement_id)
    if kind not in EVIDENCE_KINDS:
        raise ServiceError(f"evidence kind must be one of {EVIDENCE_KINDS}")
    max_bytes = int(getattr(config, "EVIDENCE_MAX_BYTES", 20 * 1024 * 1024) or 0)
    if max_bytes > 0 and len(data) > max_bytes:
        raise ServiceError(f"evidence exceeds {max_bytes} byte limit")
    if role not in ("original", "annotated", "excerpt"):
        raise ServiceError("evidence role must be original, annotated, or excerpt")
    if parent_evidence_id is not None:
        parent = s.get(Evidence, parent_evidence_id)
        if parent is None or parent.finding_id != finding_id:
            raise ServiceError("parent evidence must belong to the same finding")
    default_ct = {
        "note": "text/plain",
        "http_pair": "application/json",
        "log": "text/plain",
        "code": "text/plain",
        "package": "application/json",
        "capture_failure": "text/plain",
        "screenshot": "image/png",
        "file": "application/octet-stream",
        "client_upload": "application/octet-stream",
    }.get(kind, "application/octet-stream")
    ct = (content_type or default_ct).strip()
    # Screenshots and binary files: mask only when text-like; images keep bytes intact aside from prior redaction.
    if kind in ("screenshot",) or ct.startswith("image/"):
        masked, mask_report = data, {}
    else:
        masked, mask_report = mask_bytes(data, ct if ct.startswith("text/") or ct.endswith("json") else "text/plain")
    sha = _sha256(masked)
    path = _store(eng.tenant_id, "evidence", sha, filename, masked)
    # Prefer explicit redaction_status; fall back to note marker used by older screenshot attach.
    redaction = (redaction_status or "").strip()
    if not redaction:
        for line in (note or "").splitlines():
            if line.strip().startswith("redaction_status="):
                redaction = line.strip().split("=", 1)[1].strip()
                break
    ev = Evidence(
        finding_id=finding_id,
        kind=kind,
        filename=filename,
        path=str(path),
        sha256=sha,
        note=note,
        masking_applied=mask_report,
        captured_by=actor,
        content_type=ct,
        source_tool=(source_tool or "")[:50],
        observation_id=observation_id,
        import_run_id=import_run_id,
        parent_evidence_id=parent_evidence_id,
        role=role,
        redaction_status=redaction[:20],
        capture_status=(capture_status or "success")[:20],
        capture_failure_reason=(capture_failure_reason or "")[:500],
        annotation_meta=dict(annotation_meta or {}),
    )
    s.add(ev)
    s.flush()
    audit.record(
        s,
        actor,
        "evidence.add",
        "evidence",
        ev.id,
        finding_id=finding_id,
        sha256=sha,
        masking=mask_report,
        role=role,
        capture_status=ev.capture_status,
    )
    return ev


def record_capture_failure(
    s: Session,
    finding_id: int,
    *,
    actor: str,
    reason: str,
    source_tool: str = "",
    note: str = "",
) -> Evidence:
    """Record an honest screenshot/evidence capture failure without fabricating media."""
    body = (reason or "capture unavailable").strip()[:500]
    return add_evidence(
        s,
        finding_id,
        kind="capture_failure",
        filename="capture_failure.txt",
        data=(body + "\n").encode("utf-8"),
        note=note or "Screenshot capture did not succeed; other evidence is unchanged.",
        actor=actor,
        content_type="text/plain",
        source_tool=source_tool,
        role="original",
        capture_status="failed" if body else "unavailable",
        capture_failure_reason=body,
        redaction_status="n/a",
    )


def attach_annotated_screenshot(
    s: Session,
    finding_id: int,
    *,
    original: Evidence,
    highlights: list,
    caption: str = "",
    actor: str,
    note: str = "",
) -> Evidence:
    """Create an annotated PNG derivative linked to an original screenshot evidence row."""
    from pathlib import Path

    from attestra.evidence.annotate import AnnotateError, annotate_png

    if original.finding_id != finding_id or original.kind != "screenshot":
        raise ServiceError("annotated derivatives require a screenshot original on the same finding")
    if original.role == "annotated":
        raise ServiceError("cannot annotate an already-annotated derivative; use the original")
    f = s.get(Finding, finding_id)
    if not f:
        raise LookupError(f"finding {finding_id} not found")
    eng = get_engagement(s, f.engagement_id)
    raw_path = assert_evidence_path_readable(Path(original.path), eng.tenant_id)
    raw = raw_path.read_bytes()
    if _sha256(raw) != original.sha256:
        raise ServiceError("original screenshot hash mismatch; refusing to annotate")
    try:
        annotated_bytes, meta = annotate_png(raw, highlights, caption=caption)
    except AnnotateError as e:
        raise ServiceError(str(e)) from e
    return add_evidence(
        s,
        finding_id,
        kind="screenshot",
        filename=(Path(original.filename).stem + ".annotated.png"),
        data=annotated_bytes,
        note=note or (caption or "Annotated screenshot derivative"),
        actor=actor,
        content_type="image/png",
        source_tool=original.source_tool,
        observation_id=original.observation_id,
        import_run_id=original.import_run_id,
        parent_evidence_id=original.id,
        role="annotated",
        redaction_status=original.redaction_status or "none",
        capture_status="success",
        annotation_meta=meta,
    )


# ---------------------------------------------------------------- compliance


def import_count(s: Session, engagement_id: int) -> int:
    return s.scalar(select(func.count(ImportRun.id)).where(ImportRun.engagement_id == engagement_id)) or 0


def compliance(s: Session, engagement_id: int, framework: str):
    from attestra.compliance import evaluate

    eng = get_engagement(s, engagement_id)
    findings = list(s.scalars(select(Finding).where(Finding.engagement_id == engagement_id)))
    assessments = list(s.scalars(select(ControlAssessment).where(ControlAssessment.engagement_id == engagement_id)))
    return evaluate(eng, findings, assessments, import_count(s, engagement_id), framework)


def confirm_control(
    s: Session,
    engagement_id: int,
    *,
    framework: str,
    ref: str,
    status: str,
    assessor: str,
    rationale: str,
    role: str | None = None,
    allow_open_findings_override: bool = False,
) -> ControlAssessment:
    """Confirm a control status. P0-1/P0-2: auditor/admin only; block 'met' with open findings."""
    from attestra.auth.roles import has_permission

    if role is not None and not has_permission(role, "compliance.confirm"):
        audit.record(
            s, assessor, "control.confirm_refused", "engagement", engagement_id,
            framework=framework, ref=ref, status=status, reason="role not allowed",
        )
        raise ServiceError("not allowed: only an auditor or admin may confirm controls")
    if status not in ("met", "partial", "not_met", "not_applicable"):
        raise ServiceError("status must be met | partial | not_met | not_applicable")
    if not rationale.strip():
        raise ServiceError("a rationale is required when confirming a control")
    results = compliance(s, engagement_id, framework)
    by_ref = {r.ref: r for r in results}
    if ref not in by_ref:
        raise ServiceError(f"control '{ref}' is not in the {framework} library")
    ctrl = by_ref[ref]
    # P0-2: only critical/high/medium open findings block "met" (low/info may remain).
    blocking = []
    for fid in ctrl.finding_ids or []:
        f = s.get(Finding, fid)
        if f is None or f.status not in OPEN_STATUSES:
            continue
        if _rank(f.severity) >= 2:  # medium or worse
            blocking.append(f)
    open_ids = [f.id for f in blocking]
    if status == "met" and open_ids and not allow_open_findings_override:
        named = ", ".join(
            f"F-{f.id} ({f.severity}: {f.title[:60]})" for f in blocking
        )
        audit.record(
            s, assessor, "control.confirm_refused", "engagement", engagement_id,
            framework=framework, ref=ref, status=status, open_finding_ids=open_ids,
        )
        raise ServiceError(
            f"not allowed: cannot confirm '{ref}' as met while open findings remain: "
            f"{named}. "
            "Close, retest-pass, false-positive, or risk-accept them first, "
            "or pass allow_open_findings_override with rationale."
        )
    if status == "met" and open_ids and allow_open_findings_override:
        rationale = (
            f"{rationale.strip()} [override: open findings "
            f"{', '.join(f'F-{i}' for i in open_ids)}]"
        )

    a = s.scalar(
        select(ControlAssessment).where(
            ControlAssessment.engagement_id == engagement_id,
            ControlAssessment.framework == framework,
            ControlAssessment.control_ref == ref,
        )
    )
    # P0-1: if an auditor already confirmed, a non-auditor/admin cannot overwrite
    # (permission check above covers this; keep explicit refuse + audit for clarity).
    if a is not None and role is not None and role not in ("auditor", "admin"):
        audit.record(
            s, assessor, "control.confirm_refused", "control_assessment", a.id,
            framework=framework, ref=ref, reason="overwrite not allowed",
        )
        raise ServiceError("not allowed: cannot overwrite an auditor's control confirmation")
    if a is None:
        a = ControlAssessment(
            engagement_id=engagement_id, framework=framework, control_ref=ref,
            status=status, assessor=assessor,
        )
        s.add(a)
    a.status, a.assessor, a.rationale, a.updated_at = status, assessor, rationale.strip(), utcnow()
    s.flush()
    audit.record(s, assessor, "control.confirm", "control_assessment", a.id, framework=framework, ref=ref, status=status)
    return a


def accept_risk(
    s: Session,
    finding_id: int,
    *,
    expires_on: date,
    rationale: str,
    actor: str,
    owner_user_id: int | None = None,
) -> RiskAcceptance:
    f = s.get(Finding, finding_id)
    if not f:
        raise LookupError(f"finding {finding_id} not found")
    if not rationale.strip():
        raise ServiceError("a rationale is required for risk acceptance")
    if expires_on < date.today():
        raise ServiceError("expires_on must be today or later")
    if f.status == "new":
        transition(s, finding_id, to="triaged", actor=actor, note="auto-triage for risk acceptance")
        s.refresh(f)
    if f.status != "risk_accepted":
        transition(
            s, finding_id, to="risk_accepted", actor=actor, note=rationale, _from_accept_risk=True
        )
    row = RiskAcceptance(
        engagement_id=f.engagement_id,
        finding_id=f.id,
        owner_user_id=owner_user_id,
        rationale=rationale.strip(),
        expires_on=expires_on,
    )
    s.add(row)
    s.flush()
    audit.record(s, actor, "risk.accept", "risk_acceptance", row.id, finding_id=f.id, expires_on=str(expires_on))
    return row


def expire_risk_acceptances(s: Session, *, today: date | None = None, actor: str = "system") -> int:
    """Revoke expired acceptances and reopen findings to ``validated`` (no bare ``open`` status)."""
    today = today or date.today()
    rows = list(
        s.scalars(
            select(RiskAcceptance).where(
                RiskAcceptance.revoked_at.is_(None),
                RiskAcceptance.expires_on < today,
            )
        )
    )
    n = 0
    for row in rows:
        f = s.get(Finding, row.finding_id)
        row.revoked_at = utcnow()
        if f and f.status == "risk_accepted":
            f.status = "validated"
            audit.record(
                s, actor, "risk.expire", "risk_acceptance", row.id,
                finding_id=f.id, frm="risk_accepted", to="validated",
            )
            n += 1
    return n


def add_asv_scan(
    s: Session,
    engagement_id: int,
    *,
    vendor: str,
    scan_date: date,
    passing: bool,
    filename: str,
    data: bytes,
    actor: str,
) -> AsvScan:
    eng = get_engagement(s, engagement_id)
    sha = _sha256(data)
    path = _store(eng.tenant_id, "evidence", sha, filename, data)
    row = AsvScan(
        engagement_id=engagement_id,
        vendor=vendor.strip(),
        scan_date=scan_date,
        passing=passing,
        attestation_path=str(path),
        sha256=sha,
    )
    s.add(row)
    s.flush()
    audit.record(s, actor, "asv.add", "asv_scan", row.id, vendor=vendor, passing=passing)
    return row


def add_segmentation_test(
    s: Session,
    engagement_id: int,
    *,
    boundary: str,
    method: str,
    result: str,
    tested_on: date,
    actor: str,
    evidence_id: int | None = None,
    source_zone: str = "",
    target_zone: str = "",
    tester: str = "",
    notes: str = "",
) -> SegmentationTest:
    get_engagement(s, engagement_id)
    result = result.strip().lower()
    if result not in ("pass", "fail", "inconclusive"):
        raise ServiceError("result must be pass, fail or inconclusive")
    row = SegmentationTest(
        engagement_id=engagement_id,
        boundary=boundary.strip(),
        method=method.strip(),
        result=result,
        tested_on=tested_on,
        evidence_id=evidence_id,
        source_zone=source_zone.strip(),
        target_zone=target_zone.strip(),
        tester=tester.strip() or actor,
        notes=notes.strip(),
    )
    s.add(row)
    s.flush()
    audit.record(s, actor, "segmentation.add", "segmentation_test", row.id, result=row.result)
    return row


def add_scan_schedule(
    s: Session,
    engagement_id: int,
    *,
    asset_id: int,
    tool: str,
    cadence: str,
    next_due: date,
    actor: str,
) -> ScanSchedule:
    get_engagement(s, engagement_id)
    if cadence not in ("quarterly", "monthly"):
        raise ServiceError("cadence must be quarterly or monthly")
    asset = s.get(Asset, asset_id)
    if not asset or asset.engagement_id != engagement_id:
        raise LookupError(f"asset {asset_id} not found on engagement")
    row = ScanSchedule(
        engagement_id=engagement_id,
        asset_id=asset_id,
        tool=tool,
        cadence=cadence,
        next_due=next_due,
    )
    s.add(row)
    s.flush()
    audit.record(s, actor, "schedule.add", "scan_schedule", row.id, tool=tool, cadence=cadence)
    return row


def enqueue_due_schedules(
    s: Session, *, today: date | None = None, actor: str = "system", engagement_id: int | None = None
) -> list[ScanRun]:
    """Enqueue scan runs for schedules that are due; update next_due and quarter_clean."""
    today = today or date.today()
    q = select(ScanSchedule).where(ScanSchedule.next_due <= today)
    if engagement_id is not None:
        q = q.where(ScanSchedule.engagement_id == engagement_id)
    due = list(s.scalars(q))
    created: list[ScanRun] = []
    for sch in due:
        try:
            run = request_scan(s, sch.engagement_id, asset_id=sch.asset_id, tool=sch.tool, profile="baseline", actor=actor)
        except (ServiceError, LookupError, OSError) as exc:
            audit.record(s, actor, "schedule.enqueue_failed", "scan_schedule", sch.id, error=str(exc)[:300])
            sch.next_due = today + timedelta(days=1)
            continue
        sch.last_enqueued_at = utcnow()
        if sch.cadence == "monthly":
            sch.next_due = today + timedelta(days=30)
        else:
            sch.next_due = today + timedelta(days=90)
        findings = list(s.scalars(select(Finding).where(Finding.engagement_id == sch.engagement_id)))
        open_high = [
            f for f in findings
            if f.status in OPEN_STATUSES and _rank(f.severity) >= 3
            and (f.asset_id is None or f.asset_id == sch.asset_id)
        ]
        sch.quarter_clean = not open_high and run.status != "refused"
        created.append(run)
        audit.record(s, actor, "schedule.enqueue", "scan_schedule", sch.id, scan_run_id=run.id)
    return created


def add_nonconformity(
    s: Session,
    engagement_id: int,
    *,
    control_ref: str,
    corrective_action: str,
    owner: str,
    actor: str,
    finding_id: int | None = None,
    due: date | None = None,
    description: str = "",
    grade: str = "minor",
) -> Nonconformity:
    get_engagement(s, engagement_id)
    if grade not in ("major", "minor", "observation"):
        raise ServiceError("grade must be major, minor or observation")
    if not control_ref.strip():
        raise ServiceError("control_ref is required")
    row = Nonconformity(
        engagement_id=engagement_id,
        control_ref=control_ref.strip(),
        finding_id=finding_id,
        corrective_action=corrective_action.strip(),
        owner=owner.strip(),
        due=due,
        description=description.strip(),
        grade=grade,
        status="open",
    )
    s.add(row)
    s.flush()
    audit.record(s, actor, "nonconformity.add", "nonconformity", row.id, control_ref=control_ref)
    return row


def sla_breaches(s: Session, engagement_id: int, *, today: date | None = None) -> list[Finding]:
    """Open findings past their SLA due date."""
    today = today or date.today()
    rows = list(
        s.scalars(
            select(Finding).where(
                Finding.engagement_id == engagement_id,
                Finding.status.in_(OPEN_STATUSES),
                Finding.sla_due.is_not(None),
                Finding.sla_due < today,
            ).order_by(Finding.severity, Finding.sla_due)
        )
    )
    return rows


def export_compliance_library_csv() -> str:
    """CSV export of control titles for external QSA / ISO review."""
    from attestra.compliance import load_library

    lib = load_library()
    lines = ["framework,ref,title"]
    for fw, titles in lib.titles.items():
        for ref, title in sorted(titles.items(), key=lambda x: x[0]):
            safe = title.replace('"', '""')
            lines.append(f'{fw},{ref},"{safe}"')
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- runner / scope / halt


def add_scope_rule(
    s: Session,
    engagement_id: int,
    *,
    action: str,
    kind: str,
    pattern: str,
    actor: str,
    note: str = "",
) -> ScopeRule:
    get_engagement(s, engagement_id)
    if action not in ("allow", "deny"):
        raise ServiceError("action must be allow or deny")
    if kind not in ("host", "url", "path", "image", "cidr"):
        raise ServiceError("kind must be host|url|path|image|cidr")
    if not pattern.strip():
        raise ServiceError("pattern is required")
    rule = ScopeRule(
        engagement_id=engagement_id,
        action=action,
        kind=kind,
        pattern=pattern.strip(),
        note=note,
        created_by=actor,
    )
    s.add(rule)
    s.flush()
    audit.record(
        s, actor, "scope_rule.add", "scope_rule", rule.id,
        rule_action=action, kind=kind, pattern=pattern,
    )
    return rule


def remove_scope_rule(s: Session, rule_id: int, *, actor: str) -> None:
    rule = s.get(ScopeRule, rule_id)
    if not rule:
        raise LookupError(f"scope rule {rule_id} not found")
    audit.record(
        s, actor, "scope_rule.remove", "scope_rule", rule.id,
        rule_action=rule.action, kind=rule.kind, pattern=rule.pattern,
    )
    s.delete(rule)


def request_scan(
    s: Session,
    engagement_id: int,
    *,
    asset_id: int,
    tool: str,
    profile: str = "baseline",
    actor: str,
    user_id: int | None = None,
    idempotency_key: str | None = None,
) -> ScanRun:
    """Create a ScanRun + Job after the dispatch gate accepts the request.

    Organization test-run credits are consumed once here on successful
    admission when ``SUBSCRIPTION_SERVICE=ON``. Schedules, API, UI, and CLI
    all call this function so charging is not duplicated in workers.
    """
    from attestra.credits import attach_scan_run, balance_view, consume_for_scan_admit, refund_for_scan
    from attestra.jobs.durable import enqueue
    from attestra.runner.gate import GateError, check

    eng = get_engagement(s, engagement_id)
    # Fail-fast when enforcement is on and the org has no credits (no debit yet).
    if config.subscription_enforcement_enabled():
        if balance_view(s, eng.tenant_id, actor=actor)["exhausted"]:
            raise ServiceError(
                "The organization has exhausted its available test-run credits. "
                "Request additional credits or ask a Super Admin to allocate more."
            )
    try:
        check(s, engagement_id, asset_id, tool=tool, profile=profile, actor=actor)
    except GateError as exc:
        run = ScanRun(
            engagement_id=engagement_id,
            asset_id=asset_id,
            tool=tool,
            profile=profile,
            status="refused",
            requested_by=actor,
            refuse_reason=exc.reason,
        )
        s.add(run)
        s.flush()
        return run

    # Single credit-charging point: after the gate accepts, before queue/dispatch.
    debit = consume_for_scan_admit(
        s,
        eng.tenant_id,
        actor=actor,
        engagement_id=engagement_id,
        user_id=user_id,
        idempotency_key=idempotency_key,
    )
    run = ScanRun(
        engagement_id=engagement_id,
        asset_id=asset_id,
        tool=tool,
        profile=profile,
        status="queued",
        requested_by=actor,
    )
    s.add(run)
    s.flush()
    attach_scan_run(s, debit, run.id)
    try:
        job = enqueue(s, run.id)
        from attestra.orchestration import dispatch_scan

        dispatch_scan(s, run.id, job.id)
    except Exception:
        refund_for_scan(
            s,
            eng.tenant_id,
            actor=actor,
            scan_run_id=run.id,
            engagement_id=engagement_id,
            debit_tx=debit,
            post_start=False,
            note="Refund after pre-start queue/dispatch failure",
        )
        raise
    audit.record(s, actor, "scan.request", "scan_run", run.id, tool=tool, profile=profile, asset_id=asset_id)
    return run


def list_scans(s: Session, engagement_id: int) -> list[ScanRun]:
    get_engagement(s, engagement_id)
    return list(s.scalars(select(ScanRun).where(ScanRun.engagement_id == engagement_id).order_by(ScanRun.id.desc())))


def get_asset(s: Session, asset_id: int, principal=None) -> Asset:
    """Load a target; when ``principal`` is set, enforce engagement access."""
    a = s.get(Asset, asset_id)
    if not a:
        raise LookupError(f"target {asset_id} not found")
    if principal is not None:
        get_engagement(s, a.engagement_id, principal)
    return a


def asset_scan_history(s: Session, asset_id: int, principal=None) -> list[dict]:
    """C11: per-target scan history with A–F grade and new/fixed/still-open diffs."""
    from attestra.history import asset_scan_history as _history

    get_asset(s, asset_id, principal)
    return _history(s, asset_id)


def asset_site_grade(s: Session, asset_id: int, principal=None) -> dict:
    """Overall Observatory-style site grade for a target from its open findings."""
    from attestra.grade import score_from_findings
    from attestra.models import Finding

    asset = get_asset(s, asset_id, principal)
    findings = list(
        s.scalars(
            select(Finding).where(
                Finding.asset_id == asset_id,
                Finding.engagement_id == asset.engagement_id,
            )
        )
    )
    result = score_from_findings(findings)
    result["asset_id"] = asset_id
    result["identifier"] = asset.identifier
    return result


def list_tenant_sites(
    s: Session,
    principal=None,
    *,
    sort: str = "grade",
    q: str = "",
) -> list[dict]:
    """All targets the principal can see, with grade, open counts, last scan, and trend.

    One grouped query for open severity counts; findings and scans loaded in bulk
    (no per-row queries). Cancelled and failed scans are ignored for grade and trend.
    Default sort is worst grade first.
    """
    # @lat: [[interfaces#Web dashboard#Sites dashboard]]
    from collections import defaultdict

    from attestra.grade import grade_rank, score_from_findings
    from attestra.history import _HISTORY_STATUSES, observatory_score_for_scan

    assets = list(s.scalars(scoped(s, Asset, principal).order_by(Asset.id.asc())))
    if not assets:
        return []

    asset_ids = [a.id for a in assets]
    eng_ids = {a.engagement_id for a in assets}
    engagements = {
        e.id: e
        for e in s.scalars(select(Engagement).where(Engagement.id.in_(eng_ids)))
    }

    # Open findings by asset (one query) for severity counts.
    open_rows = s.execute(
        select(Finding.asset_id, Finding.severity, func.count())
        .where(
            Finding.asset_id.in_(asset_ids),
            Finding.status.in_(OPEN_STATUSES),
        )
        .group_by(Finding.asset_id, Finding.severity)
    ).all()
    open_by_asset: dict[int, dict[str, int]] = defaultdict(lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    })
    for aid, sev, n in open_rows:
        if aid is None:
            continue
        key = (sev or "info").lower()
        if key not in open_by_asset[aid]:
            open_by_asset[aid][key] = 0
        open_by_asset[aid][key] += int(n)

    # All findings for grade (same inputs as asset_site_grade), bulk-loaded.
    all_findings = list(
        s.scalars(select(Finding).where(Finding.asset_id.in_(asset_ids)))
    )
    findings_by_asset: dict[int, list] = defaultdict(list)
    for f in all_findings:
        if f.asset_id is not None:
            findings_by_asset[f.asset_id].append(f)

    # All scans for last-scan display and finished-scan trend, one query.
    scans = list(
        s.scalars(
            select(ScanRun)
            .where(ScanRun.asset_id.in_(asset_ids))
            .order_by(ScanRun.id.asc())
        )
    )
    scans_by_asset: dict[int, list[ScanRun]] = defaultdict(list)
    for run in scans:
        scans_by_asset[run.asset_id].append(run)

    needle = (q or "").strip().lower()
    rows: list[dict] = []
    for asset in assets:
        eng = engagements.get(asset.engagement_id)
        label = (asset.name or "").strip() or asset.identifier
        if needle and needle not in label.lower() and needle not in asset.identifier.lower():
            continue

        asset_scans = scans_by_asset.get(asset.id, [])
        finished = [r for r in asset_scans if r.status in _HISTORY_STATUSES]
        last = asset_scans[-1] if asset_scans else None
        findings = findings_by_asset.get(asset.id, [])

        # Grade only when there is at least one finished (non-cancelled/failed) scan.
        if finished:
            graded = score_from_findings(findings)
            grade = graded["grade"]
            score = int(graded["score"])
        else:
            grade = None
            score = None

        trend = "-"
        if len(finished) >= 2:
            prev_score = observatory_score_for_scan(s, finished[-2], asset)
            cur_score = observatory_score_for_scan(s, finished[-1], asset)
            if prev_score is not None and cur_score is not None:
                if cur_score > prev_score:
                    trend = "up"
                elif cur_score < prev_score:
                    trend = "down"
                else:
                    trend = "same"

        last_at = None
        if last is not None:
            last_at = last.ended_at or last.started_at

        rows.append(
            {
                "asset_id": asset.id,
                "engagement_id": asset.engagement_id,
                "engagement_name": eng.name if eng else "",
                "identifier": asset.identifier,
                "name": asset.name or "",
                "kind": asset.kind,
                "grade": grade,
                "score": score,
                "last_scan_at": last_at,
                "last_scan_status": last.status if last else None,
                "open_by_sev": dict(open_by_asset[asset.id]),
                "trend": trend,
                "url": f"/engagements/{asset.engagement_id}/targets/{asset.id}",
            }
        )

    sort_key = (sort or "grade").strip().lower()
    if sort_key == "name":
        rows.sort(key=lambda r: ((r["name"] or r["identifier"] or "").lower(), r["asset_id"]))
    elif sort_key in ("last_scan", "last_scan_date", "date"):
        # Newest finished activity first; targets with no scans last.
        dated = [r for r in rows if r["last_scan_at"] is not None]
        undated = [r for r in rows if r["last_scan_at"] is None]
        dated.sort(key=lambda r: (r["last_scan_at"], r["asset_id"]), reverse=True)
        rows = dated + undated
    else:
        # Worst grade first; within a letter, lower score first; not graded last.
        rows.sort(
            key=lambda r: (
                grade_rank(r["grade"]),
                r["score"] if r["score"] is not None else 999,
                (r["name"] or r["identifier"] or "").lower(),
                r["asset_id"],
            )
        )
    return rows


def get_scan(s: Session, scan_id: int) -> ScanRun:
    run = s.get(ScanRun, scan_id)
    if not run:
        raise LookupError(f"scan {scan_id} not found")
    return run


# Statuses a user may cancel. Finished (done), failed, refused, quarantined, cancelled cannot.
_SCAN_CANCELABLE = frozenset({"queued", "running"})


def cancel_scan(s: Session, scan_id: int, *, actor: str, principal=None) -> ScanRun:
    """Cancel a queued or running scan. Reuses job cancel; writes scan.cancelled audit.

    Keeps any results already saved. Does not emit scan.finished webhooks.
    """
    from attestra.jobs import durable as durable_mod
    from attestra.models import utcnow
    from attestra.orchestration import cancel_scan_workflow, orchestrator

    run = get_scan(s, scan_id)
    get_engagement(s, run.engagement_id, principal)
    if run.status not in _SCAN_CANCELABLE:
        raise ServiceError(f"cannot cancel a {run.status} scan")

    job = s.scalars(select(Job).where(Job.scan_run_id == run.id)).first()
    if job is not None:
        durable_mod.request_cancel(s, job.id)
        if job.status in ("queued", "running", "cancelled"):
            job.status = "cancelled"
    run.status = "cancelled"
    run.ended_at = run.ended_at or utcnow()
    audit.record(s, actor, "scan.cancelled", "scan_run", run.id, tool=run.tool, profile=run.profile)

    if orchestrator() == "temporal":
        try:
            from attestra.orchestration import run_coro

            run_coro(cancel_scan_workflow(run.id))
        except Exception:  # noqa: BLE001 - inline cancel already applied; temporal best-effort
            pass
    return run


def halt_engagement(s: Session, engagement_id: int, *, actor: str) -> Engagement:
    """Engagement kill switch: halt, cancel jobs, signal running scanners."""
    from attestra.jobs import durable as durable_mod

    eng = get_engagement(s, engagement_id)
    eng.status = "halted"
    jobs = list(
        s.scalars(
            select(Job).join(ScanRun, Job.scan_run_id == ScanRun.id).where(ScanRun.engagement_id == engagement_id)
        )
    )
    for job in jobs:
        if job.status in ("queued", "running"):
            job.cancel_requested = True
    durable_mod.signal_engagement_cancel(engagement_id)
    audit.record(s, actor, "engagement.halt", "engagement", eng.id)
    return eng


def resume_engagement(s: Session, engagement_id: int, *, actor: str) -> Engagement:
    eng = get_engagement(s, engagement_id)
    if eng.status != "halted":
        raise ServiceError("engagement is not halted")
    eng.status = "active"
    from attestra.jobs import durable as durable_mod

    durable_mod.clear_engagement_cancel(engagement_id)
    audit.record(s, actor, "engagement.resume", "engagement", eng.id)
    return eng


# ---------------------------------------------------------------- Step 6.7: scheduler UI + CI/CD gate
# @lat: [[interfaces#Scheduled scans and CI gates]]

GATE_LEVELS = ("critical", "high", "medium", "low", "info")


def list_scan_schedules(s: Session, engagement_id: int) -> list[ScanSchedule]:
    get_engagement(s, engagement_id)
    return list(
        s.scalars(
            select(ScanSchedule)
            .where(ScanSchedule.engagement_id == engagement_id)
            .order_by(ScanSchedule.next_due, ScanSchedule.id)
        )
    )


def _schedule_on(s: Session, engagement_id: int, schedule_id: int) -> ScanSchedule:
    row = s.get(ScanSchedule, schedule_id)
    if not row or row.engagement_id != engagement_id:
        raise LookupError(f"schedule {schedule_id} not found on engagement")
    return row


def update_scan_schedule(
    s: Session,
    engagement_id: int,
    schedule_id: int,
    *,
    actor: str,
    cadence: str | None = None,
    next_due: date | None = None,
) -> ScanSchedule:
    row = _schedule_on(s, engagement_id, schedule_id)
    if cadence is not None:
        if cadence not in ("quarterly", "monthly"):
            raise ServiceError("cadence must be quarterly or monthly")
        row.cadence = cadence
    if next_due is not None:
        row.next_due = next_due
    s.flush()
    audit.record(s, actor, "schedule.update", "scan_schedule", row.id, cadence=row.cadence, next_due=str(row.next_due))
    return row


def remove_scan_schedule(s: Session, engagement_id: int, schedule_id: int, *, actor: str) -> None:
    row = _schedule_on(s, engagement_id, schedule_id)
    audit.record(s, actor, "schedule.remove", "scan_schedule", row.id, tool=row.tool)
    s.delete(row)
    s.flush()


def ci_gate(
    s: Session,
    engagement_id: int,
    *,
    fail_on: str = "high",
    tool: str | None = None,
    max_findings: int = 0,
) -> dict:
    """CI/CD policy: fail when open findings at/above ``fail_on`` exceed ``max_findings``.

    Accepted-risk, fixed and false-positive findings are not open, so they never block.
    ``tool`` limits the check to findings reported by that importer (e.g. the one the
    pipeline just uploaded).
    """
    get_engagement(s, engagement_id)
    fail_on = (fail_on or "high").lower()
    if fail_on not in GATE_LEVELS:
        raise ServiceError(f"fail_on must be one of {', '.join(GATE_LEVELS)}")
    if max_findings < 0:
        raise ServiceError("max_findings must be >= 0")
    threshold = _rank(fail_on)
    open_rows = [
        f for f in s.scalars(select(Finding).where(Finding.engagement_id == engagement_id))
        if f.status in OPEN_STATUSES and (not tool or tool in (f.tools or []))
    ]
    counts = {lvl: 0 for lvl in GATE_LEVELS}
    for f in open_rows:
        counts[f.severity if f.severity in counts else "info"] += 1
    blocking = [f for f in open_rows if _rank(f.severity) >= threshold]
    blocking.sort(key=lambda f: (-_rank(f.severity), -(f.risk_score or 0), f.id))
    passed = len(blocking) <= max_findings
    return {
        "engagement_id": engagement_id,
        "policy": {"fail_on": fail_on, "tool": tool or None, "max_findings": max_findings},
        "passed": passed,
        "open_counts": counts,
        "blocking_count": len(blocking),
        "blocking": [
            {"id": f.id, "severity": f.severity, "title": f.title, "location": f.location, "tools": f.tools}
            for f in blocking[:50]
        ],
    }


# ---------------------------------------------------------------- C9: PCI calendar, ASV import, segmentation


def _quarter_of(d: date) -> tuple[int, int]:
    return d.year, (d.month - 1) // 3 + 1


def _quarter_bounds(year: int, q: int) -> tuple[date, date]:
    start = date(year, 3 * (q - 1) + 1, 1)
    end = date(year + (q == 4), 1 if q == 4 else 3 * q + 1, 1) - timedelta(days=1)
    return start, end


def _prev_quarter(year: int, q: int) -> tuple[int, int]:
    return (year - 1, 4) if q == 1 else (year, q - 1)


def pci_scan_calendar(
    s: Session, engagement_id: int, *, today: date | None = None, quarters: int = 4
) -> dict:
    """PCI 11.3.1/11.3.2 quarterly calendar: one row per quarter, newest first.

    Status per quarter: ``done`` (passing ASV scan and, if scheduled, a clean
    internal scan), ``due`` (current quarter, not yet done), ``overdue`` (past
    quarter, not done). The engagement status is the worst of the rows.
    """
    today = today or date.today()
    eng = get_engagement(s, engagement_id)
    scans = list(s.scalars(select(AsvScan).where(AsvScan.engagement_id == engagement_id)))
    schedules = list_scan_schedules(s, engagement_id)
    y, q = _quarter_of(today)
    rows = []
    for _ in range(max(1, quarters)):
        start, end = _quarter_bounds(y, q)
        in_q = [a for a in scans if start <= a.scan_date <= end]
        passing = [a for a in in_q if a.passing]
        current = start <= today <= end
        if passing:
            status = "done"
        elif current:
            status = "due"
        else:
            status = "overdue"
        rows.append({
            "quarter": f"{y}-Q{q}",
            "start": start,
            "due": end,
            "external_scans": len(in_q),
            "external_passing": len(passing),
            "status": status,
            "days_left": (end - today).days if current else None,
        })
        y, q = _prev_quarter(y, q)
    internal_due = [sc for sc in schedules if sc.next_due < today]
    if any(r["status"] == "overdue" for r in rows) or internal_due:
        overall = "overdue"
    elif rows[0]["status"] == "due":
        overall = "due"
    else:
        overall = "done"
    return {
        "engagement_id": eng.id,
        "engagement": eng.name,
        "status": overall,
        "quarters": rows,
        "internal_overdue": [{"id": sc.id, "tool": sc.tool, "next_due": sc.next_due} for sc in internal_due],
    }


def pci_calendar_overview(s: Session, principal=None, *, today: date | None = None) -> list[dict]:
    """Calendar status for every PCI engagement the principal can see."""
    out = []
    for e in s.scalars(scoped(s, Engagement, principal).order_by(Engagement.id)):
        if "pci_dss_4" in (e.frameworks or []):
            out.append(pci_scan_calendar(s, e.id, today=today))
    return out


def import_asv_results(
    s: Session, engagement_id: int, *, filename: str, data: bytes, actor: str
) -> AsvScan:
    """Import scan-vendor results in the generic CSV/JSON layout (importers/asv.py)."""
    from attestra.importers import asv as asv_importer
    from attestra.models import AsvScanItem

    eng = get_engagement(s, engagement_id)
    try:
        result = asv_importer.parse(data)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ServiceError(f"could not parse ASV results: {exc}") from exc
    sha = _sha256(data)
    path = _store(eng.tenant_id, "evidence", sha, filename, data)
    row = AsvScan(
        engagement_id=engagement_id,
        vendor=result.vendor,
        scan_date=result.scan_date,
        passing=result.passing,
        attestation_path=str(path),
        sha256=sha,
        source="import",
        filename=_safe_name(filename),
        item_count=len(result.items),
        failing_count=result.failing_count,
    )
    s.add(row)
    s.flush()
    for it in result.items:
        s.add(AsvScanItem(
            asv_scan_id=row.id, host=it.host, port=it.port, title=it.title, severity=it.severity,
            cvss_score=it.cvss_score, cve=it.cve, passing=it.passing, note=it.note,
        ))
    s.flush()
    audit.record(
        s, actor, "asv.import", "asv_scan", row.id,
        vendor=row.vendor, passing=row.passing, items=row.item_count, failing=row.failing_count, sha256=sha,
    )
    return row


def list_asv_scans(s: Session, engagement_id: int) -> list[AsvScan]:
    get_engagement(s, engagement_id)
    return list(s.scalars(
        select(AsvScan).where(AsvScan.engagement_id == engagement_id).order_by(AsvScan.scan_date.desc(), AsvScan.id.desc())
    ))


def list_segmentation_tests(s: Session, engagement_id: int) -> list[SegmentationTest]:
    get_engagement(s, engagement_id)
    return list(s.scalars(
        select(SegmentationTest).where(SegmentationTest.engagement_id == engagement_id)
        .order_by(SegmentationTest.tested_on.desc(), SegmentationTest.id.desc())
    ))


# ---------------------------------------------------------------- C10: ISO SoA, NC/CA, 9.2 sampling

SOA_IMPLEMENTATION = ("implemented", "partial", "planned", "not_implemented")
NC_STATUSES = ("open", "in_progress", "closed")
NC_GRADES = ("major", "minor", "observation")
ISO_FRAMEWORK = "iso_27001_2022"


def list_soa(s: Session, engagement_id: int):
    from attestra.models import SoaEntry

    get_engagement(s, engagement_id)
    return list(s.scalars(select(SoaEntry).where(SoaEntry.engagement_id == engagement_id).order_by(SoaEntry.id)))


def generate_soa(s: Session, engagement_id: int, *, actor: str) -> int:
    """Seed SoA rows from the ISO library and current control results. Keeps existing rows."""
    from attestra.models import SoaEntry

    existing = {e.control_ref for e in list_soa(s, engagement_id)}
    added = 0
    status_map = {"met": "implemented", "no_exceptions": "implemented", "partial": "partial", "not_met": "not_implemented"}
    for r in compliance(s, engagement_id, ISO_FRAMEWORK):
        if r.ref in existing:
            continue
        st = r.confirmed or r.proposed
        s.add(SoaEntry(
            engagement_id=engagement_id, control_ref=r.ref, title=r.title[:300],
            applicable=st != "not_applicable",
            justification="" if st != "not_applicable" else (r.rationale or "Not applicable"),
            implementation=status_map.get(st, "planned"), updated_by=actor,
        ))
        added += 1
    s.flush()
    audit.record(s, actor, "soa.generate", "engagement", engagement_id, added=added)
    return added


def update_soa_entry(
    s: Session, engagement_id: int, entry_id: int, *, applicable: bool, justification: str,
    implementation: str, actor: str,
):
    from attestra.models import SoaEntry

    get_engagement(s, engagement_id)
    row = s.get(SoaEntry, entry_id)
    if not row or row.engagement_id != engagement_id:
        raise LookupError(f"SoA entry {entry_id} not found on engagement")
    if implementation not in SOA_IMPLEMENTATION:
        raise ServiceError(f"implementation must be one of {', '.join(SOA_IMPLEMENTATION)}")
    if not applicable and not justification.strip():
        raise ServiceError("an excluded control needs a justification (ISO 27001 6.1.3 d)")
    row.applicable = applicable
    row.justification = justification.strip()
    row.implementation = implementation if applicable else "not_implemented"
    row.updated_by = actor
    row.updated_at = utcnow()
    audit.record(s, actor, "soa.update", "soa_entry", row.id, control_ref=row.control_ref, applicable=applicable)
    return row


def list_nonconformities(s: Session, engagement_id: int) -> list[Nonconformity]:
    get_engagement(s, engagement_id)
    return list(s.scalars(select(Nonconformity).where(Nonconformity.engagement_id == engagement_id).order_by(Nonconformity.id)))


def update_nonconformity(
    s: Session, engagement_id: int, nc_id: int, *, actor: str, status: str | None = None,
    root_cause: str | None = None, corrective_action: str | None = None, verified_by: str = "",
) -> Nonconformity:
    """Move an NC through open -> in_progress -> closed. Closing needs a corrective action and a verifier."""
    get_engagement(s, engagement_id)
    row = s.get(Nonconformity, nc_id)
    if not row or row.engagement_id != engagement_id:
        raise LookupError(f"nonconformity {nc_id} not found on engagement")
    if row.status == "closed":
        raise ServiceError("nonconformity is already closed")
    if root_cause is not None:
        row.root_cause = root_cause.strip()
    if corrective_action is not None and corrective_action.strip():
        row.corrective_action = corrective_action.strip()
    if status:
        if status not in NC_STATUSES:
            raise ServiceError(f"status must be one of {', '.join(NC_STATUSES)}")
        if status == "closed":
            if not row.corrective_action:
                raise ServiceError("record the corrective action before closing (ISO 27001 10.2)")
            if not verified_by.strip():
                raise ServiceError("closing needs the name of who verified the corrective action")
            row.verified_by = verified_by.strip()
            row.closed_at = utcnow()
        row.status = status
    audit.record(s, actor, "nonconformity.update", "nonconformity", row.id, status=row.status)
    return row


def default_sample_size(population: int) -> int:
    """Documented sample size (shared ISO / SOC 2 table). See compliance.sampling."""
    from attestra.compliance.sampling import sample_size_for

    return sample_size_for(population)


def draw_audit_sample(
    s: Session, engagement_id: int, *, actor: str, population: str = "soa_applicable",
    sample_size: int | None = None, seed: str = "",
):
    """ISO 27001 9.2 internal audit sample, reproducible from the stored seed."""
    import random
    import secrets

    from attestra.compliance.sampling import seed_to_int
    from attestra.models import AuditSample

    eng = get_engagement(s, engagement_id)
    if population == "soa_applicable":
        items = [e.control_ref for e in list_soa(s, engagement_id) if e.applicable]
        if not items:
            items = [r.ref for r in compliance(s, engagement_id, ISO_FRAMEWORK)]
    elif population == "findings":
        items = [f"finding:{f.id}" for f in s.scalars(select(Finding).where(Finding.engagement_id == eng.id).order_by(Finding.id))]
    elif population == "nonconformities":
        items = [f"nc:{n.id}" for n in list_nonconformities(s, engagement_id)]
    else:
        raise ServiceError("population must be soa_applicable, findings or nonconformities")
    if not items:
        raise ServiceError("the population is empty; nothing to sample")
    n = default_sample_size(len(items)) if not sample_size else int(sample_size)
    if n < 1 or n > len(items):
        raise ServiceError(f"sample size must be between 1 and {len(items)}")
    seed = seed.strip() or secrets.token_hex(8)
    picked = sorted(random.Random(seed_to_int(seed)).sample(sorted(items), n))
    row = AuditSample(
        engagement_id=engagement_id, clause="9.2", population=population, population_size=len(items),
        sample_size=n, seed=seed, items=picked, created_by=actor,
    )
    s.add(row)
    s.flush()
    audit.record(s, actor, "audit_sample.draw", "audit_sample", row.id, population=population, size=n, seed=seed)
    return row


def list_audit_samples(s: Session, engagement_id: int):
    from attestra.models import AuditSample

    get_engagement(s, engagement_id)
    return list(s.scalars(select(AuditSample).where(AuditSample.engagement_id == engagement_id).order_by(AuditSample.id.desc())))
