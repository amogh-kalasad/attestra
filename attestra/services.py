"""Business operations shared by the API and the CLI. Every write is audited."""
# @lat: [[architecture#System layers]]
# @lat: [[interfaces]]

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import date
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
    TEST_TYPES,
    TRANSITIONS,
    Asset,
    Authorization,
    ControlAssessment,
    Engagement,
    Evidence,
    Finding,
    ImportRun,
    Tenant,
    utcnow,
)


class ServiceError(Exception):
    """A request that breaks a business rule. Maps to HTTP 400/409."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name).name)[:120] or "file"


def _store(sub: str, sha: str, filename: str, data: bytes) -> Path:
    """Content-addressed, write-once storage. Existing files are never overwritten."""
    config.ensure_dirs()
    path = config.DATA_DIR / sub / f"{sha[:16]}_{_safe_name(filename)}"
    if not path.exists():
        path.write_bytes(data)
        path.chmod(0o444)
    return path


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
    e = Engagement(
        tenant_id=t.id, name=name.strip(), type=type, frameworks=frameworks, window_start=window_start, window_end=window_end
    )
    s.add(e)
    s.flush()
    audit.record(s, actor, "engagement.create", "engagement", e.id, name=name, type=type, frameworks=frameworks)
    return e


def get_engagement(s: Session, engagement_id: int) -> Engagement:
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
    path = _store("evidence", sha, filename, data)
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
    path = _store("imports", sha, filename, data)
    run = ImportRun(engagement_id=engagement_id, tool=tool, filename=filename, raw_path=str(path), sha256=sha, imported_by=actor)
    s.add(run)
    s.flush()

    existing = {f.fingerprint: f for f in s.scalars(select(Finding).where(Finding.engagement_id == engagement_id))}
    now = utcnow()
    new = updated = 0
    unmatched = sum(1 for _, a in matched if a is None)
    for nf, asset in matched:
        fp = fingerprint(location=nf.location, cwe=nf.cwe, cves=nf.cves, title=nf.title, param=nf.param, package=nf.package)
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
        lines = [l for l in text.splitlines() if not l.startswith("#")]
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
    sha = _sha256(data)
    path = _store("evidence", sha, filename, data)
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
