"""REST API and server-rendered dashboard.

Identity: Bearer API keys or signed session cookies. Roles enforced via
``require(permission)``. Optional OIDC behind ``ATTESTRA_OIDC_ENABLED``.
"""
# @lat: [[interfaces#REST API]]
# @lat: [[authorization#Identity]]

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from attestra import __version__, audit, config, db, observability, services
from attestra.api_security import RateLimitMiddleware, SecurityHeadersMiddleware
from attestra.auth.keys import Principal, authenticate_api_key
from attestra.auth.roles import has_permission
from attestra.auth.session import COOKIE_NAME, read_session
from attestra.compliance import load_library
from attestra.models import ASSET_KINDS, ENVIRONMENTS, FRAMEWORKS, TEST_TYPES, Engagement, Report, User
from attestra.reports import (
    approve_report,
    generate_report,
    qa_approve,
    qa_reject,
    sign_report,
    submit_report,
    verify_report,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init(use_migrations=True)
    observability.instrument_engine(db._engine)
    yield


app = FastAPI(title="Attestra", version=__version__, description="From findings to signed attestation.", lifespan=lifespan)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
if observability.METRICS_ENABLED:
    app.add_middleware(observability.MetricsMiddleware)
observability.configure_json_logging()
observability.setup_otel(app)


def get_principal(request: Request) -> Principal:
    """Resolve the caller from Bearer API key, OIDC access token (if enabled) or session cookie."""
    auth = request.headers.get("authorization") or ""
    with db.session() as s:
        if auth.lower().startswith("bearer "):
            principal = authenticate_api_key(s, auth[7:].strip())
            if principal is None and config.OIDC_ENABLED:
                from attestra.auth.oidc import authenticate_bearer_jwt  # Step 6.4

                principal = authenticate_bearer_jwt(s, auth[7:].strip())
            if principal:
                return principal
        data = read_session(request.cookies.get(COOKIE_NAME))
        if data and data.get("uid"):
            user = s.get(User, int(data["uid"]))
            if user and user.active:
                return Principal(
                    user_id=user.id,
                    username=user.username,
                    display_name=user.display_name,
                    role=user.role,
                    tenant_id=user.tenant_id,
                )
    raise HTTPException(401, "authentication required")


def require(permission: str):
    def dep(principal: Principal = Depends(get_principal)) -> Principal:
        if not has_permission(principal.role, permission):
            raise HTTPException(403, f"permission denied: {permission}")
        return principal

    return dep


def _run(fn, *args, **kwargs):
    try:
        with db.session() as s:
            return fn(s, *args, **kwargs)
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except services.ServiceError as e:
        msg = str(e)
        code = (
            403
            if "not allowed" in msg
            or "not verified" in msg
            or "halted" in msg
            or "authorization" in msg
            or "window" in msg
            or "rate limit" in msg
            or "not in scope" in msg
            else 409
        )
        raise HTTPException(code, msg) from e


# ---------------------------------------------------------------- schemas


class EngagementIn(BaseModel):
    tenant: str
    name: str
    type: str = Field(description="va | pt | vapt | retest | continuous")
    frameworks: list[str] = []
    window_start: date | None = None
    window_end: date | None = None
    industry: str = ""
    contact_name: str = ""
    contact_email: str = ""


class AssetIn(BaseModel):
    kind: str = Field(description=" | ".join(ASSET_KINDS))
    identifier: str = Field(description="URL, host/IP/CIDR, repo path, image, account ID or app ID")
    name: str = ""
    environment: str = Field("production", description=" | ".join(ENVIRONMENTS))
    test_types: list[str] = Field(default_factory=list, description="keys from /api/catalog; empty = defaults for the kind")
    intrusive_allowed: bool = False
    criticality: int = 3
    exposure: str = "internal"
    in_cde: bool = False
    owner: str = ""
    notes: str = ""


class TransitionIn(BaseModel):
    to: str
    note: str = ""


class ConfirmIn(BaseModel):
    framework: str
    ref: str
    status: str
    rationale: str


class ReportIn(BaseModel):
    kind: str
    framework: str = ""


def _eng_dict(e) -> dict:
    return {
        "id": e.id,
        "tenant": e.tenant.name,
        "name": e.name,
        "type": e.type,
        "frameworks": e.frameworks,
        "window_start": e.window_start,
        "window_end": e.window_end,
        "status": e.status,
        "assets": len(e.assets),
        "authorized": any(a.is_valid() for a in e.authorizations),
    }


def _finding_dict(f) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "status": f.status,
        "risk_score": f.risk_score,
        "cvss_score": f.cvss_score,
        "epss": f.epss,
        "kev": f.kev,
        "cwe": f.cwe,
        "cves": f.cves,
        "location": f.location,
        "tools": f.tools,
        "occurrences": f.occurrences,
        "sla_due": f.sla_due,
        "validated_by": f.validated_by,
        "asset_id": f.asset_id,
        "owasp_top10": f.owasp_top10,
        "asvs_ref": f.asvs_ref,
        "wstg_ref": f.wstg_ref,
    }


def _report_dict(r) -> dict:
    return {
        "id": r.id,
        "kind": r.kind,
        "framework": r.framework,
        "version": r.version,
        "status": r.status,
        "sha256": r.sha256,
        "generated_by": r.generated_by,
        "qa_by": r.qa_by,
        "approved_by": r.approved_by,
        "algorithm": r.algorithm,
        "signature": r.signature,
        "rejection_note": r.rejection_note,
        "docx_sha256": r.docx_sha256,
        "pdf_sha256": r.pdf_sha256,
    }


# ---------------------------------------------------------------- API


@app.get("/metrics", include_in_schema=False)
def metrics(request: Request):
    """Prometheus scrape endpoint (Phase 6.6). Optional token via ATTESTRA_METRICS_TOKEN."""
    if not observability.METRICS_ENABLED:
        raise HTTPException(404, "metrics disabled")
    return observability.metrics_response(request)


@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__}


@app.get("/api/catalog")
def catalog():
    return {"environments": ENVIRONMENTS, "asset_kinds": ASSET_KINDS, "test_types": TEST_TYPES}


@app.get("/api/frameworks")
def frameworks():
    lib = load_library()
    return {k: v["name"] for k, v in lib.frameworks.items()}


@app.get("/api/me")
def me(principal: Principal = Depends(get_principal)):
    return {
        "user_id": principal.user_id,
        "username": principal.username,
        "display_name": principal.display_name,
        "role": principal.role,
        "tenant_id": principal.tenant_id,
    }


@app.post("/api/engagements", status_code=201)
def create_engagement(body: EngagementIn, principal: Principal = Depends(require("engagement.create"))):
    return _run(
        lambda s: _eng_dict(
            services.create_engagement(s, **body.model_dump(), actor=principal.actor, principal=principal)
        )
    )


@app.get("/api/engagements")
def list_engagements(principal: Principal = Depends(require("engagement.read"))):
    with db.session() as s:
        q = services.scoped(s, Engagement, principal).order_by(Engagement.id.desc())
        return [_eng_dict(e) for e in s.scalars(q)]


@app.get("/api/engagements/{eid}")
def get_engagement(eid: int, principal: Principal = Depends(require("engagement.read"))):
    return _run(lambda s: _eng_dict(services.get_engagement(s, eid, principal)))


@app.post("/api/engagements/{eid}/authorizations", status_code=201)
async def add_authorization(
    eid: int,
    document: UploadFile = File(...),
    signer: str = Form(...),
    signed_on: date = Form(...),
    expires_on: date = Form(...),
    environments: list[str] = Form(..., description=" | ".join(ENVIRONMENTS)),
    rules_of_engagement: str = Form(""),
    principal: Principal = Depends(require("authorization.add")),
):
    data = await document.read()

    def fn(s):
        services.get_engagement(s, eid, principal)
        return services.add_authorization(
            s,
            eid,
            filename=document.filename or "authorization",
            data=data,
            signer=signer,
            signed_on=signed_on,
            expires_on=expires_on,
            rules_of_engagement=rules_of_engagement,
            environments=environments,
            actor=principal.actor,
        )

    a = _run(fn)
    return {"id": a.id, "sha256": a.sha256, "valid": a.is_valid(), "environments": a.environments}


@app.post("/api/engagements/{eid}/assets", status_code=201)
def add_asset(eid: int, body: AssetIn, principal: Principal = Depends(require("asset.write"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return services.add_asset(s, eid, **body.model_dump(), actor=principal.actor)

    a = _run(fn)
    return {"id": a.id, "identifier": a.identifier, "environment": a.environment, "test_types": a.test_types}


@app.get("/api/engagements/{eid}/assets")
def list_assets(eid: int, principal: Principal = Depends(require("engagement.read"))):
    return _run(
        lambda s: [
            {
                "id": a.id,
                "kind": a.kind,
                "identifier": a.identifier,
                "name": a.name,
                "environment": a.environment,
                "test_types": a.test_types or [],
                "intrusive_allowed": a.intrusive_allowed,
                "criticality": a.criticality,
                "exposure": a.exposure,
                "in_cde": a.in_cde,
                "owner": a.owner,
                "notes": a.notes,
            }
            for a in services.get_engagement(s, eid, principal).assets
        ]
    )


@app.delete("/api/assets/{aid}", status_code=204)
def remove_asset(aid: int, principal: Principal = Depends(require("asset.write"))):
    _run(services.remove_asset, aid, actor=principal.actor)


@app.post("/api/engagements/{eid}/imports", status_code=201)
async def import_results(
    eid: int,
    tool: str = Form(...),
    file: UploadFile = File(...),
    principal: Principal = Depends(require("import.create")),
):
    data = await file.read()

    def fn(s):
        services.get_engagement(s, eid, principal)
        return services.import_results(
            s, eid, tool=tool, filename=file.filename or f"{tool}.json", data=data, actor=principal.actor
        )

    run = _run(fn)
    return {
        "id": run.id,
        "sha256": run.sha256,
        "new_findings": run.new_findings,
        "updated_findings": run.updated_findings,
        "unmatched_findings": run.unmatched_findings,
    }


@app.get("/api/engagements/{eid}/findings")
def findings(
    eid: int,
    status: str | None = None,
    severity: str | None = None,
    principal: Principal = Depends(require("finding.read")),
):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return [_finding_dict(f) for f in services.list_findings(s, eid, status, severity)]

    return _run(fn)


@app.post("/api/findings/{fid}/transition")
def transition(fid: int, body: TransitionIn, principal: Principal = Depends(require("finding.write"))):
    return _run(
        lambda s: _finding_dict(
            services.transition(s, fid, to=body.to, note=body.note, actor=principal.actor)
        )
    )


@app.post("/api/findings/{fid}/evidence", status_code=201)
async def add_evidence(
    fid: int,
    kind: str = Form(...),
    note: str = Form(""),
    file: UploadFile = File(...),
    principal: Principal = Depends(require("finding.write")),
):
    data = await file.read()
    ev = _run(
        services.add_evidence,
        fid,
        kind=kind,
        filename=file.filename or "evidence",
        data=data,
        note=note,
        actor=principal.actor,
    )
    return {"id": ev.id, "sha256": ev.sha256}


@app.get("/api/engagements/{eid}/compliance")
def compliance(
    eid: int,
    framework: str = Query(..., description=", ".join(FRAMEWORKS)),
    principal: Principal = Depends(require("compliance.read")),
):
    def fn(s):
        services.get_engagement(s, eid, principal)
        try:
            results = services.compliance(s, eid, framework)
        except ValueError as e:
            raise services.ServiceError(str(e)) from e
        return [
            {
                "ref": r.ref,
                "title": r.title,
                "status": r.status,
                "proposed": r.proposed,
                "confirmed": r.confirmed,
                "assessor": r.assessor,
                "reason": r.reason,
                "objectives": r.objectives,
                "finding_ids": r.finding_ids,
            }
            for r in results
        ]

    return _run(fn)


@app.post("/api/engagements/{eid}/compliance/confirm")
def confirm(eid: int, body: ConfirmIn, principal: Principal = Depends(require("compliance.confirm"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return services.confirm_control(s, eid, **body.model_dump(), assessor=principal.actor)

    a = _run(fn)
    return {"id": a.id, "status": a.status}


class RiskAcceptIn(BaseModel):
    finding_id: int
    expires_on: date
    rationale: str


@app.post("/api/engagements/{eid}/risk-acceptances", status_code=201)
def risk_accept(eid: int, body: RiskAcceptIn, principal: Principal = Depends(require("finding.write"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return services.accept_risk(
            s,
            body.finding_id,
            expires_on=body.expires_on,
            rationale=body.rationale,
            actor=principal.actor,
            owner_user_id=principal.user_id,
        )

    row = _run(fn)
    return {"id": row.id, "finding_id": row.finding_id, "expires_on": row.expires_on}


class AsvIn(BaseModel):
    vendor: str
    scan_date: date
    passing: bool = False


@app.post("/api/engagements/{eid}/asv", status_code=201)
async def add_asv(
    eid: int,
    vendor: str = Form(...),
    scan_date: date = Form(...),
    passing: bool = Form(False),
    file: UploadFile = File(...),
    principal: Principal = Depends(require("compliance.confirm")),
):
    data = await file.read()

    def fn(s):
        services.get_engagement(s, eid, principal)
        return services.add_asv_scan(
            s, eid, vendor=vendor, scan_date=scan_date, passing=passing,
            filename=file.filename or "asv.pdf", data=data, actor=principal.actor,
        )

    row = _run(fn)
    return {"id": row.id, "passing": row.passing, "sha256": row.sha256}


class SegIn(BaseModel):
    boundary: str
    method: str = ""
    result: str
    tested_on: date


@app.post("/api/engagements/{eid}/segmentation", status_code=201)
def add_segmentation(eid: int, body: SegIn, principal: Principal = Depends(require("compliance.confirm"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return services.add_segmentation_test(s, eid, **body.model_dump(), actor=principal.actor)

    row = _run(fn)
    return {"id": row.id, "result": row.result}


@app.get("/api/engagements/{eid}/sla")
def engagement_sla(eid: int, principal: Principal = Depends(require("finding.read"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return [_finding_dict(f) for f in services.sla_breaches(s, eid)]

    return _run(fn)


@app.post("/api/engagements/{eid}/reports", status_code=201)
def create_report(eid: int, body: ReportIn, principal: Principal = Depends(require("report.generate"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return _report_dict(
            generate_report(
                s,
                eid,
                kind=body.kind,
                framework=body.framework,
                actor=principal.actor,
                user_id=principal.user_id,
            )
        )

    return _run(fn)


@app.post("/api/reports/{rid}/submit")
def report_submit(rid: int, principal: Principal = Depends(require("report.submit"))):
    return _run(lambda s: _report_dict(submit_report(s, rid, actor=principal.actor, user_id=principal.user_id)))


class RejectIn(BaseModel):
    note: str


@app.post("/api/reports/{rid}/qa-approve")
def report_qa_approve(rid: int, principal: Principal = Depends(require("report.approve"))):
    return _run(lambda s: _report_dict(qa_approve(s, rid, actor=principal.actor, user_id=principal.user_id)))


@app.post("/api/reports/{rid}/qa-reject")
def report_qa_reject(rid: int, body: RejectIn, principal: Principal = Depends(require("report.approve"))):
    return _run(
        lambda s: _report_dict(qa_reject(s, rid, actor=principal.actor, note=body.note, user_id=principal.user_id))
    )


@app.post("/api/reports/{rid}/sign")
def report_sign(rid: int, principal: Principal = Depends(require("report.sign"))):
    return _run(
        lambda s: _report_dict(
            sign_report(s, rid, actor=principal.actor, user_id=principal.user_id, role=principal.role)
        )
    )


@app.post("/api/reports/{rid}/approve")
def approve(rid: int, principal: Principal = Depends(require("report.approve"))):
    """Legacy shortcut: draft → signed (or sign if already QA-approved)."""
    return _run(
        lambda s: _report_dict(
            approve_report(s, rid, actor=principal.actor, user_id=principal.user_id)
        )
    )


@app.get("/api/reports/{rid}/verify")
def verify(rid: int, principal: Principal = Depends(require("report.read"))):
    return _run(verify_report, rid)


@app.post("/api/reports/{rid}/export")
def report_export(rid: int, principal: Principal = Depends(require("report.read"))):
    from attestra.reports.export import export_report_formats

    def fn(s):
        from attestra.models import Report

        r = s.get(Report, rid)
        if not r:
            raise LookupError(f"report {rid} not found")
        services.get_engagement(s, r.engagement_id, principal)
        return export_report_formats(r)

    return _run(fn)


@app.get("/api/engagements/{eid}/export/sarif")
def export_sarif(eid: int, principal: Principal = Depends(require("finding.read"))):
    from attestra.reports.sarif import findings_to_sarif

    def fn(s):
        services.get_engagement(s, eid, principal)
        return findings_to_sarif(s, eid)

    return _run(fn)


@app.get("/api/engagements/{eid}/packs/{framework}")
def framework_pack(eid: int, framework: str, principal: Principal = Depends(require("report.read"))):
    from fastapi.responses import FileResponse

    from attestra.reports.packs import build_framework_pack

    with db.session() as s:
        services.get_engagement(s, eid, principal)
        path = build_framework_pack(s, eid, framework)
    return FileResponse(path, filename=path.name, media_type="application/zip")


@app.get("/reports/{rid}")
def download_report(rid: int, principal: Principal = Depends(require("report.read"))):
    from attestra import config as cfg

    with db.session() as s:
        r = s.scalar(services.scoped(s, Report, principal).where(Report.id == rid))
        if not r:
            raise HTTPException(404, "report not found")
        eng = services.get_engagement(s, r.engagement_id, principal)
        path = Path(r.path).resolve()
        allowed_roots = [
            (cfg.DATA_DIR / "tenants" / str(eng.tenant_id)).resolve(),
            cfg.DATA_DIR.resolve(),  # legacy pre-tenant paths
        ]
        if not any(str(path).startswith(str(root)) for root in allowed_roots):
            raise HTTPException(404, "report not found")
        audit.record(s, principal.actor, "report.download", "report", r.id)
        return FileResponse(r.path, media_type="text/html")


@app.get("/api/evidence/{eid}/download")
def download_evidence(eid: int, principal: Principal = Depends(require("finding.read"))):
    from attestra import config as cfg
    from attestra.models import Evidence, Finding

    with db.session() as s:
        ev = s.get(Evidence, eid)
        if not ev:
            raise HTTPException(404, "evidence not found")
        f = s.get(Finding, ev.finding_id)
        if not f:
            raise HTTPException(404, "evidence not found")
        eng = services.get_engagement(s, f.engagement_id, principal)
        path = Path(ev.path).resolve()
        allowed_roots = [
            (cfg.DATA_DIR / "tenants" / str(eng.tenant_id)).resolve(),
            cfg.DATA_DIR.resolve(),
        ]
        if not any(str(path).startswith(str(root)) for root in allowed_roots):
            raise HTTPException(404, "evidence not found")
        if not path.is_file():
            raise HTTPException(404, "evidence not found")
        audit.record(s, principal.actor, "evidence.download", "evidence", ev.id, finding_id=f.id)
        return FileResponse(str(path), filename=ev.filename, media_type="application/octet-stream")


@app.get("/api/audit/verify")
def audit_verify(principal: Principal = Depends(require("audit.read"))):
    with db.session() as s:
        ok, bad = audit.verify(s)
    return {"ok": ok, "first_bad_event": bad}


@app.get("/api/audit/export")
def audit_export(
    format: str = Query("json", pattern="^(json|csv)$"),
    principal: Principal = Depends(require("audit.read")),
):
    """Export audit events with chain proof (prev_hash + hash per row)."""
    import csv
    import io

    from fastapi.responses import PlainTextResponse, Response
    from sqlalchemy import select

    from attestra.models import AuditEvent

    with db.session() as s:
        events = list(s.scalars(select(AuditEvent).order_by(AuditEvent.id)))
        ok, bad = audit.verify(s)
        rows = [
            {
                "id": e.id,
                "ts": e.ts.isoformat() if e.ts else "",
                "actor": e.actor,
                "action": e.action,
                "entity": e.entity,
                "entity_id": e.entity_id,
                "details": e.details,
                "prev_hash": e.prev_hash,
                "hash": e.hash,
            }
            for e in events
        ]
    proof = {"chain_ok": ok, "first_bad_event": bad, "count": len(rows)}
    if format == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(
            buf,
            fieldnames=["id", "ts", "actor", "action", "entity", "entity_id", "prev_hash", "hash"],
        )
        w.writeheader()
        for r in rows:
            w.writerow({k: r[k] for k in w.fieldnames})
        body = f"# chain_ok={ok} first_bad_event={bad} count={len(rows)}\n" + buf.getvalue()
        return PlainTextResponse(body, media_type="text/csv")
    import json

    return Response(
        json.dumps({"proof": proof, "events": rows}, indent=2, default=str),
        media_type="application/json",
    )


class ScanIn(BaseModel):
    asset_id: int
    tool: str
    profile: str = "baseline"


def _scan_dict(r) -> dict:
    return {
        "id": r.id,
        "engagement_id": r.engagement_id,
        "asset_id": r.asset_id,
        "tool": r.tool,
        "profile": r.profile,
        "status": r.status,
        "requested_by": r.requested_by,
        "tool_version": r.tool_version,
        "image_digest": r.image_digest,
        "raw_sha256": r.raw_sha256,
        "refuse_reason": r.refuse_reason,
        "started_at": r.started_at,
        "ended_at": r.ended_at,
    }


@app.post("/api/engagements/{eid}/scans", status_code=201)
def start_scan(eid: int, body: ScanIn, principal: Principal = Depends(require("scan.start"))):
    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            run = services.request_scan(s, eid, **body.model_dump(), actor=principal.actor)
            payload = _scan_dict(run)
            refused = run.status == "refused"
            reason = run.refuse_reason or "scan refused"
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except services.ServiceError as e:
        raise HTTPException(409, str(e)) from e
    if refused:
        raise HTTPException(403, reason)
    return payload


@app.get("/api/engagements/{eid}/scans")
def list_scans(eid: int, principal: Principal = Depends(require("scan.read"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return [_scan_dict(r) for r in services.list_scans(s, eid)]

    return _run(fn)


@app.get("/api/scans/{sid}")
def get_scan(sid: int, principal: Principal = Depends(require("scan.read"))):
    def fn(s):
        run = services.get_scan(s, sid)
        services.get_engagement(s, run.engagement_id, principal)
        return _scan_dict(run)

    return _run(fn)


@app.post("/api/engagements/{eid}/halt")
def halt(eid: int, principal: Principal = Depends(require("engagement.halt"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return {"id": eid, "status": services.halt_engagement(s, eid, actor=principal.actor).status}

    return _run(fn)


@app.post("/api/engagements/{eid}/resume")
def resume(eid: int, principal: Principal = Depends(require("engagement.resume"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return {"id": eid, "status": services.resume_engagement(s, eid, actor=principal.actor).status}

    return _run(fn)


# ---------------------------------------------------------------- Step 6.7: schedules + CI gate


class ScheduleIn(BaseModel):
    asset_id: int
    tool: str
    cadence: str = Field("quarterly", description="quarterly | monthly")
    next_due: date


class ScheduleUpdateIn(BaseModel):
    cadence: str | None = None
    next_due: date | None = None


def _schedule_dict(r) -> dict:
    return {
        "id": r.id,
        "engagement_id": r.engagement_id,
        "asset_id": r.asset_id,
        "tool": r.tool,
        "cadence": r.cadence,
        "next_due": r.next_due,
        "last_enqueued_at": r.last_enqueued_at,
        "quarter_clean": bool(r.quarter_clean),
    }


@app.get("/api/engagements/{eid}/schedules")
def list_schedules(eid: int, principal: Principal = Depends(require("scan.read"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return [_schedule_dict(r) for r in services.list_scan_schedules(s, eid)]

    return _run(fn)


@app.post("/api/engagements/{eid}/schedules", status_code=201)
def add_schedule(eid: int, body: ScheduleIn, principal: Principal = Depends(require("scan.start"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return _schedule_dict(services.add_scan_schedule(s, eid, **body.model_dump(), actor=principal.actor))

    return _run(fn)


@app.patch("/api/engagements/{eid}/schedules/{sid}")
def update_schedule(eid: int, sid: int, body: ScheduleUpdateIn, principal: Principal = Depends(require("scan.start"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return _schedule_dict(services.update_scan_schedule(s, eid, sid, **body.model_dump(), actor=principal.actor))

    return _run(fn)


@app.delete("/api/engagements/{eid}/schedules/{sid}", status_code=204)
def delete_schedule(eid: int, sid: int, principal: Principal = Depends(require("scan.start"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        services.remove_scan_schedule(s, eid, sid, actor=principal.actor)

    _run(fn)


@app.post("/api/engagements/{eid}/schedules/run-due")
def run_due_schedules(eid: int, principal: Principal = Depends(require("scan.start"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        runs = services.enqueue_due_schedules(s, engagement_id=eid, actor=principal.actor)
        return {"enqueued": [_scan_dict(r) for r in runs]}

    return _run(fn)


@app.get("/api/engagements/{eid}/gate")
def ci_gate(
    eid: int,
    fail_on: str = Query("high", description="critical | high | medium | low | info"),
    tool: str | None = Query(None, description="only findings reported by this importer"),
    max_findings: int = Query(0, ge=0),
    principal: Principal = Depends(require("finding.read")),
):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return services.ci_gate(s, eid, fail_on=fail_on, tool=tool, max_findings=max_findings)

    return _run(fn)


# ---------------------------------------------------------------- dashboard

from attestra.web.ui import router as ui_router  # noqa: E402

app.include_router(ui_router)
