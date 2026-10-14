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
from attestra.fingerprint import fingerprint
from attestra.models import (
    ASSET_KINDS,
    DEFAULT_TESTS,
    ENGAGEMENT_TYPES,
    ENVIRONMENTS,
    FRAMEWORKS,
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
    utcnow,
)


class ServiceError(Exception):
    """A request that breaks a business rule. Maps to HTTP 400/409."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name).name)[:120] or "file"


def _store(tenant_id: int | None, sub: str, sha: str, filename: str, data: bytes) -> Path:
    """Content-addressed, write-once storage under a per-tenant prefix."""
    config.ensure_dirs()
    if tenant_id is None:
        base = config.DATA_DIR / sub
    else:
        base = config.DATA_DIR / "tenants" / str(tenant_id) / sub
    base.mkdir(parents=True, exist_ok=True)
    path = base / f"{sha[:16]}_{_safe_name(filename)}"
    if not path.exists():
        path.write_bytes(data)
        path.chmod(0o444)
    return path


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
    s: Session, name: str, actor: str, *, industry: str = "", contact_name: str = "", contact_email: str = ""
) -> Tenant:
    name = name.strip()
    if not name:
        raise ServiceError("client name is required")
    if contact_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", contact_email.strip()):
        raise ServiceError("contact email looks invalid")
    t = s.scalar(select(Tenant).where(Tenant.name == name))
    if t is None:
        t = Tenant(name=name)
        s.add(t)
        s.flush()
        audit.record(s, actor, "tenant.create", "tenant", t.id, name=name)
    changed = {}
    for field, value in (("industry", industry), ("contact_name", contact_name), ("contact_email", contact_email)):
        if value and value.strip() != getattr(t, field):
            setattr(t, field, value.strip())
            changed[field] = value.strip()
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
    contact_name: str = "",
    contact_email: str = "",
    principal=None,
) -> Engagement:
    if not name.strip():
        raise ServiceError("engagement name is required")
    if type not in ENGAGEMENT_TYPES:
        raise ServiceError(f"type must be one of {ENGAGEMENT_TYPES}")
    bad = [f for f in frameworks if f not in FRAMEWORKS]
    if bad:
        raise ServiceError(f"unknown frameworks {bad}; choose from {FRAMEWORKS}")
    if window_start and window_end and window_end < window_start:
        raise ServiceError("window_end is before window_start")
    t = get_or_create_tenant(s, tenant, actor, industry=industry, contact_name=contact_name, contact_email=contact_email)
    ensure_tenant_membership(s, principal, t.id)
    e = Engagement(
        tenant_id=t.id, name=name.strip(), type=type, frameworks=frameworks, window_start=window_start, window_end=window_end
    )
    s.add(e)
    s.flush()
    audit.record(s, actor, "engagement.create", "engagement", e.id, name=name, type=type, frameworks=frameworks)
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
    tests = list(dict.fromkeys(test_types or DEFAULT_TESTS.get(kind, [])))
    bad = [x for x in tests if x not in TEST_TYPES]
    if bad:
        raise ServiceError(f"unknown test types {bad}; choose from {list(TEST_TYPES)}")
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


def import_results(s: Session, engagement_id: int, *, tool: str, filename: str, data: bytes, actor: str) -> ImportRun:
    """Import a scanner result file. Requires a currently valid signed authorization."""
    # @lat: [[authorization#Import gate]]
    # @lat: [[import-pipeline#Import run]]
    eng = get_engagement(s, engagement_id)
    if not any(a.is_valid() for a in eng.authorizations):
        raise ServiceError("record a currently valid signed authorization before importing results")
    try:
        parsed = importers.parse(tool, data)
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        raise ServiceError(f"could not parse {tool} file: {exc}") from exc

    # Every finding that lands on a target must be in an environment the client authorized.
    allowed_envs = authorized_environments(eng)
    assets = list(eng.assets)
    matched = [(nf, match_asset(assets, nf.location)) for nf in parsed]
    outside = sorted({f"{a.identifier} ({a.environment})" for _, a in matched if a and a.environment not in allowed_envs})
    if outside:
        raise ServiceError(
            "results include targets in environments the client has not authorized: "
            + ", ".join(outside) + ". Add a signed authorization covering them first."
        )

    sha = _sha256(data)
    path = _store(eng.tenant_id, "imports", sha, filename, data)
    run = ImportRun(engagement_id=engagement_id, tool=tool, filename=filename, raw_path=str(path), sha256=sha, imported_by=actor)
    s.add(run)
    s.flush()

    existing = {f.fingerprint: f for f in s.scalars(select(Finding).where(Finding.engagement_id == engagement_id))}
    now = utcnow()
    new = updated = 0
    unmatched = sum(1 for _, a in matched if a is None)
    for nf, asset in matched:
        fp = fingerprint(
            location=nf.location,
            cwe=nf.cwe,
            cves=nf.cves,
            title=nf.title,
            param=nf.param,
            package=nf.package,
            asset_id=asset.id if asset else None,
        )
        f = existing.get(fp)
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
                cvss_vector=nf.cvss_vector,
                first_seen=now,
                last_seen=now,
            )
            f.asset = asset
            _apply_owasp(f)
            s.add(f)
            existing[fp] = f
            new += 1
        else:
            # Same issue seen again (another tool or a rescan): merge, keep the higher severity.
            f.occurrences += 1
            f.last_seen = now
            if nf.tool not in f.tools:
                f.tools = [*f.tools, nf.tool]
            if nf.rule_id and nf.rule_id not in f.rule_ids:
                f.rule_ids = [*f.rule_ids, nf.rule_id]
            if _rank(nf.severity) > _rank(f.severity):
                f.severity = nf.severity
            if f.cvss_score is None and nf.cvss_score is not None:
                f.cvss_score, f.cvss_vector = nf.cvss_score, nf.cvss_vector
            if not f.cwe and nf.cwe:
                f.cwe = nf.cwe
                _apply_owasp(f)
            if f.status == "fixed":
                # Reappeared after being marked fixed: reopen.
                f.status = "validated" if f.validated_by else "triaged"
                audit.record(s, actor, "finding.reopened", "finding", f.id, import_run=run.id)
            updated += 1
        rescore(f)

    run.new_findings, run.updated_findings, run.unmatched_findings = new, updated, unmatched
    s.flush()
    audit.record(
        s, actor, "import.create", "import_run", run.id,
        engagement_id=engagement_id, tool=tool, sha256=sha, parsed=len(parsed), new=new, updated=updated,
        unmatched=unmatched,
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


def rescore(f: Finding) -> None:
    a = f.asset
    f.risk_score = scoring.risk_score(
        f.cvss_score, f.severity, f.epss, f.kev,
        a.criticality if a else None, a.exposure if a else None, a.in_cde if a else False,
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


def list_findings(s: Session, engagement_id: int, status: str | None = None, severity: str | None = None) -> list[Finding]:
    q = select(Finding).where(Finding.engagement_id == engagement_id)
    if status:
        q = q.where(Finding.status == status)
    if severity:
        q = q.where(Finding.severity == severity)
    return list(s.scalars(q.order_by(Finding.risk_score.desc(), Finding.id)))


def transition(s: Session, finding_id: int, *, to: str, actor: str, note: str = "") -> Finding:
    f = s.get(Finding, finding_id)
    if not f:
        raise LookupError(f"finding {finding_id} not found")
    allowed = TRANSITIONS.get(f.status, set())
    if to not in allowed:
        raise ServiceError(f"cannot move finding from '{f.status}' to '{to}'; allowed: {sorted(allowed) or 'none'}")
    if to in ("false_positive", "risk_accepted") and not note.strip():
        raise ServiceError(f"a reason is required to mark a finding {to}")
    if to == "validated":
        f.validated_by = actor
    if to == "retest_passed" and f.validated_by == actor and f.validated_by:
        # Not blocking, but recorded: independent retest is preferred.
        note = (note + " [retested by original validator]").strip()
    prev = f.status
    f.status = to
    audit.record(s, actor, "finding.transition", "finding", f.id, frm=prev, to=to, note=note)
    return f


def add_evidence(s: Session, finding_id: int, *, kind: str, filename: str, data: bytes, note: str, actor: str) -> Evidence:
    f = s.get(Finding, finding_id)
    if not f:
        raise LookupError(f"finding {finding_id} not found")
    eng = get_engagement(s, f.engagement_id)
    sha = _sha256(data)
    path = _store(eng.tenant_id, "evidence", sha, filename, data)
    ev = Evidence(finding_id=finding_id, kind=kind, filename=filename, path=str(path), sha256=sha, note=note, captured_by=actor)
    s.add(ev)
    s.flush()
    audit.record(s, actor, "evidence.add", "evidence", ev.id, finding_id=finding_id, sha256=sha)
    return ev


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
    s: Session, engagement_id: int, *, framework: str, ref: str, status: str, assessor: str, rationale: str
) -> ControlAssessment:
    if status not in ("met", "partial", "not_met", "not_applicable"):
        raise ServiceError("status must be met | partial | not_met | not_applicable")
    if not rationale.strip():
        raise ServiceError("a rationale is required when confirming a control")
    refs = {r.ref for r in compliance(s, engagement_id, framework)}
    if ref not in refs:
        raise ServiceError(f"control '{ref}' is not in the {framework} library")
    a = s.scalar(
        select(ControlAssessment).where(
            ControlAssessment.engagement_id == engagement_id,
            ControlAssessment.framework == framework,
            ControlAssessment.control_ref == ref,
        )
    )
    if a is None:
        a = ControlAssessment(engagement_id=engagement_id, framework=framework, control_ref=ref, status=status, assessor=assessor)
        s.add(a)
    a.status, a.assessor, a.rationale, a.updated_at = status, assessor, rationale, utcnow()
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
        transition(s, finding_id, to="risk_accepted", actor=actor, note=rationale)
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
) -> SegmentationTest:
    get_engagement(s, engagement_id)
    row = SegmentationTest(
        engagement_id=engagement_id,
        boundary=boundary.strip(),
        method=method.strip(),
        result=result.strip().lower(),
        tested_on=tested_on,
        evidence_id=evidence_id,
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


def enqueue_due_schedules(s: Session, *, today: date | None = None, actor: str = "system") -> list[ScanRun]:
    """Enqueue scan runs for schedules that are due; update next_due and quarter_clean."""
    today = today or date.today()
    due = list(s.scalars(select(ScanSchedule).where(ScanSchedule.next_due <= today)))
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
) -> Nonconformity:
    get_engagement(s, engagement_id)
    row = Nonconformity(
        engagement_id=engagement_id,
        control_ref=control_ref.strip(),
        finding_id=finding_id,
        corrective_action=corrective_action.strip(),
        owner=owner.strip(),
        due=due,
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
) -> ScanRun:
    """Create a ScanRun + Job after the dispatch gate accepts the request."""
    from attestra.jobs.durable import enqueue
    from attestra.runner.gate import GateError, check

    get_engagement(s, engagement_id)
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
    enqueue(s, run.id)
    audit.record(s, actor, "scan.request", "scan_run", run.id, tool=tool, profile=profile, asset_id=asset_id)
    return run


def list_scans(s: Session, engagement_id: int) -> list[ScanRun]:
    get_engagement(s, engagement_id)
    return list(s.scalars(select(ScanRun).where(ScanRun.engagement_id == engagement_id).order_by(ScanRun.id.desc())))


def get_scan(s: Session, scan_id: int) -> ScanRun:
    run = s.get(ScanRun, scan_id)
    if not run:
        raise LookupError(f"scan {scan_id} not found")
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
