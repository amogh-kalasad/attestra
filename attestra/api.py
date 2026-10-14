"""REST API and server-rendered dashboard.

Identity: v0.1 takes the acting user from the `X-Attestra-Actor` header so the
audit trail and four-eyes rules work end to end. Replace with Keycloak OIDC
before any shared deployment (see docs/ARCHITECTURE.md).
"""
# @lat: [[interfaces#REST API]]
# @lat: [[authorization#Identity placeholder]]

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import date

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from attestra import __version__, audit, db, services
from attestra.compliance import load_library
from attestra.models import ASSET_KINDS, ENVIRONMENTS, FRAMEWORKS, TEST_TYPES, Report
from attestra.reports import approve_report, generate_report, verify_report


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init()
    yield


app = FastAPI(title="Attestra", version=__version__, description="From findings to signed attestation.", lifespan=lifespan)


def actor(x_attestra_actor: str | None = Header(default=None)) -> str:
    if not x_attestra_actor or not x_attestra_actor.strip():
        raise HTTPException(401, "X-Attestra-Actor header is required for write operations")
    return x_attestra_actor.strip()


def _run(fn, *args, **kwargs):
    try:
        with db.session() as s:
            return fn(s, *args, **kwargs)
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except services.ServiceError as e:
        raise HTTPException(409, str(e)) from e


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
        "id": e.id, "tenant": e.tenant.name, "name": e.name, "type": e.type, "frameworks": e.frameworks,
        "window_start": e.window_start, "window_end": e.window_end, "status": e.status,
        "assets": len(e.assets), "authorized": any(a.is_valid() for a in e.authorizations),
    }


def _finding_dict(f) -> dict:
    return {
        "id": f.id, "title": f.title, "severity": f.severity, "status": f.status, "risk_score": f.risk_score,
        "cvss_score": f.cvss_score, "epss": f.epss, "kev": f.kev, "cwe": f.cwe, "cves": f.cves,
        "location": f.location, "tools": f.tools, "occurrences": f.occurrences, "sla_due": f.sla_due,
        "validated_by": f.validated_by, "asset_id": f.asset_id,
    }


def _report_dict(r) -> dict:
    return {
        "id": r.id, "kind": r.kind, "framework": r.framework, "version": r.version, "status": r.status,
        "sha256": r.sha256, "generated_by": r.generated_by, "approved_by": r.approved_by, "signature": r.signature,
    }


# ---------------------------------------------------------------- API


@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__}


@app.get("/api/catalog")
def catalog():
    """Allowed values for targets: environments, target kinds and test types."""
    return {"environments": ENVIRONMENTS, "asset_kinds": ASSET_KINDS, "test_types": TEST_TYPES}


@app.get("/api/frameworks")
def frameworks():
    lib = load_library()
    return {k: v["name"] for k, v in lib.frameworks.items()}


@app.post("/api/engagements", status_code=201)
def create_engagement(body: EngagementIn, who: str = Depends(actor)):
    return _run(lambda s: _eng_dict(services.create_engagement(s, **body.model_dump(), actor=who)))


@app.get("/api/engagements")
def list_engagements():
    from attestra.models import Engagement

    with db.session() as s:
        return [_eng_dict(e) for e in s.scalars(select(Engagement).order_by(Engagement.id.desc()))]


@app.get("/api/engagements/{eid}")
def get_engagement(eid: int):
    return _run(lambda s: _eng_dict(services.get_engagement(s, eid)))


@app.post("/api/engagements/{eid}/authorizations", status_code=201)
async def add_authorization(
    eid: int,
    document: UploadFile = File(...),
    signer: str = Form(...),
    signed_on: date = Form(...),
    expires_on: date = Form(...),
    environments: list[str] = Form(..., description=" | ".join(ENVIRONMENTS)),
    rules_of_engagement: str = Form(""),
    who: str = Depends(actor),
):
    data = await document.read()
    a = _run(
        services.add_authorization, eid, filename=document.filename or "authorization", data=data,
        signer=signer, signed_on=signed_on, expires_on=expires_on, rules_of_engagement=rules_of_engagement,
        environments=environments, actor=who,
    )
    return {"id": a.id, "sha256": a.sha256, "valid": a.is_valid(), "environments": a.environments}


@app.post("/api/engagements/{eid}/assets", status_code=201)
def add_asset(eid: int, body: AssetIn, who: str = Depends(actor)):
    a = _run(services.add_asset, eid, **body.model_dump(), actor=who)
    return {"id": a.id, "identifier": a.identifier, "environment": a.environment, "test_types": a.test_types}


@app.get("/api/engagements/{eid}/assets")
def list_assets(eid: int):
    return _run(lambda s: [
        {"id": a.id, "kind": a.kind, "identifier": a.identifier, "name": a.name, "environment": a.environment,
         "test_types": a.test_types or [], "intrusive_allowed": a.intrusive_allowed, "criticality": a.criticality,
         "exposure": a.exposure, "in_cde": a.in_cde, "owner": a.owner, "notes": a.notes}
        for a in services.get_engagement(s, eid).assets
    ])


@app.delete("/api/assets/{aid}", status_code=204)
def remove_asset(aid: int, who: str = Depends(actor)):
    _run(services.remove_asset, aid, actor=who)


@app.post("/api/engagements/{eid}/imports", status_code=201)
async def import_results(eid: int, tool: str = Form(...), file: UploadFile = File(...), who: str = Depends(actor)):
    data = await file.read()
    run = _run(services.import_results, eid, tool=tool, filename=file.filename or f"{tool}.json", data=data, actor=who)
    return {"id": run.id, "sha256": run.sha256, "new_findings": run.new_findings,
            "updated_findings": run.updated_findings, "unmatched_findings": run.unmatched_findings}


@app.get("/api/engagements/{eid}/findings")
def findings(eid: int, status: str | None = None, severity: str | None = None):
    return _run(lambda s: [_finding_dict(f) for f in services.list_findings(s, eid, status, severity)])


@app.post("/api/findings/{fid}/transition")
def transition(fid: int, body: TransitionIn, who: str = Depends(actor)):
    return _run(lambda s: _finding_dict(services.transition(s, fid, to=body.to, note=body.note, actor=who)))


@app.post("/api/findings/{fid}/evidence", status_code=201)
async def add_evidence(
    fid: int, kind: str = Form(...), note: str = Form(""), file: UploadFile = File(...), who: str = Depends(actor)
):
    data = await file.read()
    ev = _run(services.add_evidence, fid, kind=kind, filename=file.filename or "evidence", data=data, note=note, actor=who)
    return {"id": ev.id, "sha256": ev.sha256}


@app.get("/api/engagements/{eid}/compliance")
def compliance(eid: int, framework: str = Query(..., description=", ".join(FRAMEWORKS))):
    def fn(s):
        try:
            results = services.compliance(s, eid, framework)
        except ValueError as e:
            raise services.ServiceError(str(e)) from e
        return [
            {"ref": r.ref, "title": r.title, "status": r.status, "proposed": r.proposed, "confirmed": r.confirmed,
             "assessor": r.assessor, "reason": r.reason, "objectives": r.objectives, "finding_ids": r.finding_ids}
            for r in results
        ]

    return _run(fn)


@app.post("/api/engagements/{eid}/compliance/confirm")
def confirm(eid: int, body: ConfirmIn, who: str = Depends(actor)):
    a = _run(services.confirm_control, eid, **body.model_dump(), assessor=who)
    return {"id": a.id, "status": a.status}


@app.post("/api/engagements/{eid}/reports", status_code=201)
def create_report(eid: int, body: ReportIn, who: str = Depends(actor)):
    return _run(lambda s: _report_dict(generate_report(s, eid, kind=body.kind, framework=body.framework, actor=who)))


@app.post("/api/reports/{rid}/approve")
def approve(rid: int, who: str = Depends(actor)):
    return _run(lambda s: _report_dict(approve_report(s, rid, actor=who)))


@app.get("/api/reports/{rid}/verify")
def verify(rid: int):
    return _run(verify_report, rid)


@app.get("/reports/{rid}")
def download_report(rid: int):
    with db.session() as s:
        r = s.get(Report, rid)
        if not r:
            raise HTTPException(404, "report not found")
        return FileResponse(r.path, media_type="text/html")


@app.get("/api/audit/verify")
def audit_verify():
    with db.session() as s:
        ok, bad = audit.verify(s)
    return {"ok": ok, "first_bad_event": bad}


# ---------------------------------------------------------------- dashboard

from attestra.web.ui import router as ui_router  # noqa: E402

app.include_router(ui_router)
