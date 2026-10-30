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
from attestra.models import (
    ASSET_KINDS,
    ENVIRONMENTS,
    FRAMEWORKS,
    NEW_ENGAGEMENT_TYPES,
    TEST_TYPES,
    Engagement,
    Report,
    User,
    new_engagement_type_labels,
)
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
    # @lat: [[interfaces#Configuration#Subscription service flag]]
    config.validate_runtime_config()
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
    type: str = Field(description="va | pt | vapt (retest and continuous are historical only)")
    frameworks: list[str] = []
    window_start: date | None = None
    window_end: date | None = None
    industry: str = ""
    country: str = ""
    regulatory_status: str = ""
    technical_scope: list[str] = []
    contact_name: str = ""
    contact_email: str = ""


class RecommendIn(BaseModel):
    industry: str
    country: str
    regulatory_status: str = ""
    technical_scope: list[str] = []
    engagement_type: str = ""
    confirmed_frameworks: list[str] = []
    excluded_frameworks: list[str] = []


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


class AssignIn(BaseModel):
    assignee: str = Field(..., min_length=1, max_length=100)


class TransitionIn(BaseModel):
    to: str
    note: str = ""


class CommentIn(BaseModel):
    body: str = Field(..., min_length=1, max_length=5000)


class ConfirmIn(BaseModel):
    framework: str
    ref: str
    status: str
    rationale: str
    allow_open_findings_override: bool = False


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


def _detected_by(f) -> str:
    from attestra.dedup import detected_by_label

    return detected_by_label(f.tools)


def _observation_dict(o) -> dict:
    from attestra.dedup import tool_display_name

    return {
        "id": o.id,
        "tool": o.tool,
        "tool_label": tool_display_name(o.tool),
        "tool_version": o.tool_version,
        "original_id": o.original_id,
        "title": o.title,
        "severity": o.severity,
        "confidence": o.confidence,
        "location": o.location,
        "param": o.param,
        "package": o.package,
        "package_version": o.package_version,
        "fixed_version": o.fixed_version,
        "cwe": o.cwe,
        "cves": list(o.cves or []),
        "rule_ids": list(o.rule_ids or []),
        "match_confidence": o.match_confidence,
        "match_rationale": o.match_rationale,
        "possible_duplicate_of": o.possible_duplicate_of,
        "import_run_id": o.import_run_id,
        "observed_at": o.observed_at,
    }


def _finding_dict(f, fix: dict | None = None) -> dict:
    from attestra.library.fix_snippets import empty_fix_fields

    out = {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "status": f.status,
        "risk_score": f.risk_score,
        "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector,
        "epss": f.epss,
        "kev": f.kev,
        "cwe": f.cwe,
        "cves": f.cves,
        "location": f.location,
        "impact": f.impact or "",
        "affected_urls": list(f.affected_urls or []),
        "merged_into_id": getattr(f, "merged_into_id", None),
        "merge_rationale": getattr(f, "merge_rationale", "") or "",
        "references": list(f.references or []),
        "tools": f.tools,
        "detected_by": _detected_by(f),
        "dedup_confidence": f.dedup_confidence,
        "dedup_rationale": f.dedup_rationale or "",
        "occurrences": f.occurrences,
        "sla_due": f.sla_due,
        "validated_by": f.validated_by,
        "asset_id": f.asset_id,
        "owasp_top10": f.owasp_top10,
        "asvs_ref": f.asvs_ref,
        "wstg_ref": f.wstg_ref,
    }
    out.update(fix if fix is not None else empty_fix_fields())
    return out


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
    """Liveness plus PDF engine probe for ops/admin (clear message when engines are missing)."""
    from attestra.reports.pdf import pdf_engine_status

    pdf = pdf_engine_status()
    return {
        "status": "ok",
        "version": __version__,
        "pdf": pdf,
        "pdf_engine": pdf["engine"],
        "pdf_message": pdf["message"],
    }


@app.get("/api/catalog")
def catalog():
    from attestra.compliance.recommend import catalogues

    return {
        "environments": ENVIRONMENTS,
        "asset_kinds": ASSET_KINDS,
        "test_types": TEST_TYPES,
        "new_engagement_types": new_engagement_type_labels(),
        "new_engagement_type_keys": list(NEW_ENGAGEMENT_TYPES),
        **catalogues(),
    }


@app.get("/api/frameworks")
def frameworks():
    lib = load_library()
    return {k: v["name"] for k, v in lib.frameworks.items()}


@app.get("/api/profile/catalogues")
def profile_catalogues():
    """Industry, country, and technical-scope catalogues for organization profiles."""
    from attestra.compliance.recommend import catalogues

    return catalogues()


@app.post("/api/frameworks/recommend")
def recommend_frameworks_api(body: RecommendIn, principal: Principal = Depends(require("engagement.create"))):
    """Recommend configured catalogue frameworks from industry + country (and optional profile)."""
    from attestra.compliance.recommend import RecommendError, recommend_frameworks, recommendation_to_dict

    try:
        rows = recommend_frameworks(**body.model_dump())
    except RecommendError as e:
        raise HTTPException(400, str(e)) from e
    return {
        "recommendations": [recommendation_to_dict(r) for r in rows],
        "actor": principal.actor,
    }


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
    return services.authorization_public_dict(a, include_document_access=principal.role == "admin")


@app.get("/api/engagements/{eid}/authorizations")
def list_authorizations(eid: int, principal: Principal = Depends(require("engagement.read"))):
    """List authorization metadata for an engagement. Never returns document_path."""

    def fn(s):
        eng = services.get_engagement(s, eid, principal)
        admin = principal.role == "admin"
        return [
            services.authorization_public_dict(a, include_document_access=admin)
            for a in eng.authorizations
        ]

    return _run(fn)


@app.get("/api/authorizations/{aid}/document")
def download_authorization_document(aid: int, principal: Principal = Depends(require("authorization.document"))):
    """Download the signed authorization file. Super Admin only; path never in the JSON error body."""
    from fastapi.responses import FileResponse

    try:
        with db.session() as s:
            a, path = services.open_authorization_document(s, aid, principal=principal)
            filename = a.document_name or "authorization"
            # Read path while session is open; FileResponse needs a stable path string.
            return FileResponse(
                str(path),
                filename=filename,
                media_type="application/octet-stream",
                headers={"Cache-Control": "no-store"},
            )
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except PermissionError as e:
        raise HTTPException(403, str(e)) from e


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


@app.get("/api/engagements/{eid}/assets/{aid}/grade")
def asset_grade(eid: int, aid: int, principal: Principal = Depends(require("engagement.read"))):
    """Site grade, score, and breakdown for one target (tenant-scoped)."""

    def fn(s):
        services.get_engagement(s, eid, principal)
        asset = services.get_asset(s, aid, principal)
        if asset.engagement_id != eid:
            raise LookupError("target not found")
        return services.asset_site_grade(s, aid, principal)

    try:
        return _run(fn)
    except LookupError:
        raise HTTPException(404, "target not found")


@app.get("/api/sites")
def list_sites(
    sort: str = Query("grade"),
    q: str = Query(""),
    principal: Principal = Depends(require("engagement.read")),
):
    """Tenant-scoped list of all targets with grade, open counts, last scan, and trend."""

    def fn(s):
        rows = services.list_tenant_sites(s, principal, sort=sort, q=q)
        out = []
        for r in rows:
            item = dict(r)
            at = item.get("last_scan_at")
            if at is not None and hasattr(at, "isoformat"):
                item["last_scan_at"] = at.isoformat()
            out.append(item)
        return out

    return _run(fn)


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
        "library_suggestions": _library_suggestion_count(eid),
    }


def _library_suggestion_count(eid: int) -> int:
    """Findings in the engagement that have a matching library writeup (by rule id or CWE)."""
    from attestra.library.service import suggestions_for_engagement

    with db.session() as s:
        return len(suggestions_for_engagement(s, eid))


@app.get("/api/engagements/{eid}/findings")
def findings(
    eid: int,
    status: str | None = None,
    severity: str | None = None,
    tool: str | None = None,
    asset_id: int | None = Query(None, description="limit to one target"),
    principal: Principal = Depends(require("finding.read")),
):
    def fn(s):
        from attestra.library import service as lib

        services.get_engagement(s, eid, principal)
        rows = services.list_findings(
            s, eid, status, severity, tool=tool, asset_id=asset_id,
        )
        return [_finding_dict(f, lib.finding_api_fix_fields(s, f)) for f in rows]

    return _run(fn)


@app.post("/api/engagements/{eid}/findings/cross-merge")
def findings_cross_merge(eid: int, principal: Principal = Depends(require("finding.write"))):
    """Recompute cross-tool links (same issue, different tools) for one engagement."""

    def fn(s):
        from attestra import crossmerge

        services.get_engagement(s, eid, principal)
        return crossmerge.recompute(s, eid, actor=principal.actor)

    return _run(fn)


@app.get("/api/engagements/{eid}/findings/export")
def findings_export(
    eid: int,
    asset_id: int | None = Query(None, description="limit to one target"),
    principal: Principal = Depends(require("finding.read")),
):
    """CSV export of findings (formula-injection guarded). Audited as findings.exported."""
    from fastapi.responses import PlainTextResponse

    from attestra.reports.findings_csv import export_findings_csv

    def fn(s):
        services.get_engagement(s, eid, principal)
        if asset_id is not None:
            asset = services.get_asset(s, asset_id, principal)
            if asset.engagement_id != eid:
                raise LookupError("target not found")
        return export_findings_csv(s, eid, actor=principal.actor, asset_id=asset_id)

    body = _run(fn)
    name = f"eng{eid}-findings.csv" if asset_id is None else f"eng{eid}-asset{asset_id}-findings.csv"
    return PlainTextResponse(
        body,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@app.get("/api/engagements/{eid}/scope/suggestions")
def scope_suggestions_status(
    eid: int,
    principal: Principal = Depends(require("asset.write")),
):
    """Which apex domains can run CT subdomain suggestions (in signed scope only)."""
    from attestra.runner.authorization import AuthorizationError, scope_for_engagement
    from attestra.runner.ct_suggestions import in_scope_apexes

    def fn(s):
        services.get_engagement(s, eid, principal)
        try:
            scope = scope_for_engagement(s, eid)
        except AuthorizationError:
            return {"enabled": False, "apexes": []}
        apexes = in_scope_apexes(scope)
        return {"enabled": bool(apexes), "apexes": apexes}

    return _run(fn)


@app.post("/api/engagements/{eid}/scope/suggestions")
def scope_suggestions_fetch(
    eid: int,
    apex: str = Query(..., description="in-scope apex domain, for example example.com"),
    principal: Principal = Depends(require("asset.write")),
):
    """One passive CT lookup. Suggestions only — never adds to scope or starts a scan."""
    from attestra.runner.ct_suggestions import suggestions_for_engagement

    def fn(s):
        services.get_engagement(s, eid, principal)
        return suggestions_for_engagement(s, eid, apex, actor=principal.actor)

    return _run(fn)


@app.get("/api/findings/{fid}/observations")
def list_finding_observations(fid: int, principal: Principal = Depends(require("finding.read"))):
    """Scanner observations retained under a canonical finding (Phase 6)."""
    from sqlalchemy import select

    from attestra.models import Finding, FindingObservation

    def fn(s):
        f = s.get(Finding, fid)
        if not f:
            raise LookupError(f"finding {fid} not found")
        services.assert_engagement_access(s, f.engagement_id, principal)
        rows = list(
            s.scalars(
                select(FindingObservation)
                .where(FindingObservation.finding_id == fid)
                .order_by(FindingObservation.id)
            )
        )
        return {
            "finding_id": fid,
            "detected_by": _detected_by(f),
            "tools": list(f.tools or []),
            "observations": [_observation_dict(o) for o in rows],
        }

    return _run(fn)


@app.get("/api/engagements/{eid}/dedup-suggestions")
def engagement_dedup_suggestions(eid: int, principal: Principal = Depends(require("finding.read"))):
    """Non-destructive historical duplicate suggestions within one engagement."""
    from sqlalchemy import select

    from attestra.dedup import suggest_historical_duplicates
    from attestra.models import Finding

    def fn(s):
        services.get_engagement(s, eid, principal)
        rows = list(s.scalars(select(Finding).where(Finding.engagement_id == eid)))
        return {"engagement_id": eid, "suggestions": suggest_historical_duplicates(rows)}

    return _run(fn)


@app.post("/api/findings/{fid}/transition")
def transition(fid: int, body: TransitionIn, principal: Principal = Depends(require("finding.write"))):
    def fn(s):
        from attestra.library import service as lib
        from attestra.models import Finding

        row = s.get(Finding, fid)
        if not row:
            raise LookupError(f"finding {fid} not found")
        services.assert_engagement_access(s, row.engagement_id, principal)
        f = services.transition(s, fid, to=body.to, note=body.note, actor=principal.actor)
        return _finding_dict(f, lib.finding_api_fix_fields(s, f))

    return _run(fn)


@app.post("/api/findings/{fid}/assign")
def assign_finding_api(fid: int, body: AssignIn, principal: Principal = Depends(require("finding.write"))):
    """Assign a finding to a tenant username (audited)."""
    from attestra.assignments import assign_finding, current_assignee
    from attestra.models import Finding

    def fn(s):
        f = s.get(Finding, fid)
        if not f:
            raise LookupError(f"finding {fid} not found")
        services.assert_engagement_access(s, f.engagement_id, principal)
        row = assign_finding(
            s, fid, assignee=body.assignee, actor=principal.actor, user_id=principal.user_id
        )
        return {"id": fid, "assignee": row.assignee, "current": current_assignee(s, fid)}

    return _run(fn)


@app.post("/api/findings/{fid}/unassign")
def unassign_finding_api(fid: int, principal: Principal = Depends(require("finding.write"))):
    """Clear the current finding assignee (audited)."""
    from attestra.assignments import current_assignee, unassign_finding
    from attestra.models import Finding

    def fn(s):
        f = s.get(Finding, fid)
        if not f:
            raise LookupError(f"finding {fid} not found")
        services.assert_engagement_access(s, f.engagement_id, principal)
        unassign_finding(s, fid, actor=principal.actor)
        return {"id": fid, "assignee": None, "current": current_assignee(s, fid)}

    return _run(fn)


@app.get("/api/findings/{fid}/assignee")
def get_finding_assignee(fid: int, principal: Principal = Depends(require("finding.read"))):
    from attestra.assignments import current_assignee
    from attestra.models import Finding

    def fn(s):
        f = s.get(Finding, fid)
        if not f:
            raise LookupError(f"finding {fid} not found")
        services.assert_engagement_access(s, f.engagement_id, principal)
        return {"id": fid, "assignee": current_assignee(s, fid)}

    return _run(fn)


@app.get("/api/findings/{fid}/comments")
def list_finding_comments(fid: int, principal: Principal = Depends(require("finding.read"))):
    from attestra import comments as finding_comments

    return _run(lambda s: finding_comments.list_comments(s, fid, principal))


@app.post("/api/findings/{fid}/comments", status_code=201)
def add_finding_comment(fid: int, body: CommentIn, principal: Principal = Depends(get_principal)):
    from attestra import comments as finding_comments

    if not finding_comments.can_add_comment(principal.role):
        raise HTTPException(403, "permission denied: cannot add comments")
    return _run(lambda s: finding_comments.add_comment(s, fid, body=body.body, principal=principal))


@app.delete("/api/findings/{fid}/comments/{cid}")
def delete_finding_comment(fid: int, cid: int, principal: Principal = Depends(require("finding.read"))):
    from attestra import comments as finding_comments

    return _run(lambda s: finding_comments.delete_comment(s, fid, cid, principal))


@app.post("/api/findings/{fid}/evidence", status_code=201)
async def add_evidence(
    fid: int,
    kind: str = Form(...),
    note: str = Form(""),
    file: UploadFile = File(...),
    principal: Principal = Depends(require("finding.write")),
):
    from attestra.models import Finding

    data = await file.read()
    max_bytes = config.EVIDENCE_MAX_BYTES
    if max_bytes > 0 and len(data) > max_bytes:
        raise HTTPException(413, f"evidence exceeds {max_bytes} byte limit")

    def fn(s):
        f = s.get(Finding, fid)
        if not f:
            raise LookupError(f"finding {fid} not found")
        services.assert_engagement_access(s, f.engagement_id, principal)
        return services.add_evidence(
            s,
            fid,
            kind=kind,
            filename=file.filename or "evidence",
            data=data,
            note=note,
            actor=principal.actor,
        )

    ev = _run(fn)
    return {"id": ev.id, "sha256": ev.sha256}


class AnnotateEvidenceIn(BaseModel):
    highlights: list[dict] = Field(default_factory=list)
    caption: str = ""
    note: str = ""


@app.get("/api/findings/{fid}/evidence/gallery")
def finding_evidence_gallery(fid: int, principal: Principal = Depends(require("finding.read"))):
    """Grouped evidence cards for a finding (no storage paths)."""
    from sqlalchemy import select

    from attestra.evidence.gallery import build_gallery
    from attestra.models import Evidence, Finding

    def fn(s):
        f = s.get(Finding, fid)
        if not f:
            raise LookupError(f"finding {fid} not found")
        services.assert_engagement_access(s, f.engagement_id, principal)
        rows = list(s.scalars(select(Evidence).where(Evidence.finding_id == fid).order_by(Evidence.id)))
        gallery = build_gallery(rows)
        gallery["finding_id"] = fid
        return gallery

    return _run(fn)


@app.post("/api/findings/{fid}/evidence/{eid}/annotate", status_code=201)
def annotate_finding_evidence(
    fid: int,
    eid: int,
    body: AnnotateEvidenceIn,
    principal: Principal = Depends(require("finding.write")),
):
    """Create an annotated screenshot derivative without altering the original."""
    from attestra.models import Evidence, Finding

    def fn(s):
        f = s.get(Finding, fid)
        if not f:
            raise LookupError(f"finding {fid} not found")
        services.assert_engagement_access(s, f.engagement_id, principal)
        original = s.get(Evidence, eid)
        if not original or original.finding_id != fid:
            raise LookupError(f"evidence {eid} not found on finding {fid}")
        ev = services.attach_annotated_screenshot(
            s,
            fid,
            original=original,
            highlights=body.highlights,
            caption=body.caption,
            actor=principal.actor,
            note=body.note,
        )
        return {
            "id": ev.id,
            "sha256": ev.sha256,
            "role": ev.role,
            "parent_evidence_id": ev.parent_evidence_id,
            "annotation_meta": dict(ev.annotation_meta or {}),
        }

    return _run(fn)


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
                "mapping_strength": r.mapping_strength,
                "mapping_rationale": r.mapping_rationale,
                "mappings": r.mappings,
            }
            for r in results
        ]

    return _run(fn)


@app.post("/api/engagements/{eid}/compliance/confirm")
def confirm(eid: int, body: ConfirmIn, principal: Principal = Depends(get_principal)):
    """Confirm a control. Auth required; P0-1 permission + audit live in confirm_control.

    Refusals are caught inside the unit of work so ``control.confirm_refused`` commits
    before the 403 is returned (same pattern as refused scans).
    """
    refused: str | None = None
    result: dict | None = None
    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            try:
                a = services.confirm_control(
                    s,
                    eid,
                    **body.model_dump(),
                    assessor=principal.actor,
                    role=principal.role,
                )
                result = {"id": a.id, "status": a.status}
            except services.ServiceError as e:
                msg = str(e)
                if "not allowed" in msg:
                    refused = msg
                else:
                    raise
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except services.ServiceError as e:
        raise HTTPException(409, str(e)) from e
    if refused:
        raise HTTPException(403, refused)
    return result


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
    principal: Principal = Depends(require("import.create")),
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
def add_segmentation(eid: int, body: SegIn, principal: Principal = Depends(require("engagement.write"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return services.add_segmentation_test(s, eid, **body.model_dump(), actor=principal.actor)

    row = _run(fn)
    return {"id": row.id, "result": row.result}


@app.get("/api/engagements/{eid}/sla")
def engagement_sla(eid: int, principal: Principal = Depends(require("finding.read"))):
    def fn(s):
        from attestra.library import service as lib

        services.get_engagement(s, eid, principal)
        rows = services.sla_breaches(s, eid)
        return [_finding_dict(f, lib.finding_api_fix_fields(s, f)) for f in rows]

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
        r, html_path = _report_file(s, rid, principal)
        return export_report_formats(r, html_path)

    return _run(fn)


@app.get("/api/engagements/{eid}/export/oscal")
def export_oscal(eid: int, framework: str = "", principal: Principal = Depends(require("report.read"))):
    """OSCAL assessment results for one framework, or the POA&M when no framework is given."""
    from attestra.reports.oscal import assessment_results, poam

    def fn(s):
        eng = services.get_engagement(s, eid, principal)
        if not framework:
            return poam(s, eid)
        if framework not in (eng.frameworks or []):
            raise LookupError("framework is not part of this engagement")
        return assessment_results(s, eid, framework)

    return _run(fn)


@app.get("/api/engagements/{eid}/export/sarif")
def export_sarif(eid: int, principal: Principal = Depends(require("finding.read"))):
    from attestra.reports.sarif import findings_to_sarif

    def fn(s):
        services.get_engagement(s, eid, principal)
        return findings_to_sarif(s, eid)

    return _run(fn)


@app.get("/api/engagements/{eid}/export/xlsx")
def export_xlsx(eid: int, principal: Principal = Depends(require("finding.read"))):
    """Excel workbook: Findings, Controls, and Evidence metadata sheets."""
    from fastapi.responses import Response

    from attestra.reports.xlsx_export import export_engagement_xlsx

    def fn(s):
        services.get_engagement(s, eid, principal)
        return export_engagement_xlsx(s, eid, actor=principal.actor)

    data = _run(fn)
    return Response(
        data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="eng{eid}-export.xlsx"'},
    )


@app.get("/api/engagements/{eid}/export/json")
def export_engagement_json_api(eid: int, principal: Principal = Depends(require("finding.read"))):
    """Full engagement JSON (findings, controls, evidence metadata, reports) with version fields."""
    from attestra.reports.engagement_export import export_engagement_json

    def fn(s):
        services.get_engagement(s, eid, principal)
        return export_engagement_json(s, eid, actor=principal.actor)

    return _run(fn)


@app.get("/api/engagements/{eid}/export/markdown")
def export_engagement_markdown_api(eid: int, principal: Principal = Depends(require("finding.read"))):
    """Consolidated findings Markdown (evidence references only; no public URLs)."""
    from fastapi.responses import PlainTextResponse

    from attestra.reports.markdown_export import export_engagement_markdown

    def fn(s):
        services.get_engagement(s, eid, principal)
        return export_engagement_markdown(s, eid, actor=principal.actor)

    body = _run(fn)
    return PlainTextResponse(
        body,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="eng{eid}-findings.md"'},
    )


@app.get("/api/engagements/{eid}/packs/{framework}")
def framework_pack(eid: int, framework: str, principal: Principal = Depends(require("report.read"))):
    from fastapi.responses import FileResponse

    from attestra.reports.packs import build_framework_pack

    with db.session() as s:
        services.get_engagement(s, eid, principal)
        path = build_framework_pack(s, eid, framework)
    return FileResponse(path, filename=path.name, media_type="application/zip")


def _report_file(s, rid: int, principal: Principal) -> tuple[Report, Path]:
    """The report row and its sealed file path, after the tenant scope and data-folder checks."""
    from attestra import config as cfg

    r = s.scalar(services.scoped(s, Report, principal).where(Report.id == rid))
    if not r:
        raise HTTPException(404, "report not found")
    eng = services.get_engagement(s, r.engagement_id, principal)
    path = Path(r.path).resolve()
    data_root = cfg.DATA_DIR.resolve()
    tenant_root = (cfg.DATA_DIR / "tenants" / str(eng.tenant_id)).resolve()
    allowed_roots = [tenant_root, data_root]  # legacy pre-tenant paths under DATA_DIR
    if not services.path_under_roots(path, allowed_roots):
        # DATA_DIR moved (or a temp DB copy): remap .../tenants/<id>/... under the current root.
        parts = path.parts
        if "tenants" in parts:
            idx = parts.index("tenants")
            candidate = (cfg.DATA_DIR.joinpath(*parts[idx:])).resolve()
            if services.path_under_roots(candidate, [tenant_root]) and candidate.is_file():
                path = candidate
            else:
                raise HTTPException(404, "report not found")
        else:
            raise HTTPException(404, "report not found")
    if not path.is_file():
        raise HTTPException(404, "report not found")
    return r, path


_REPORT_EXPORT_TYPES = {
    "pdf": ("application/pdf", "pdf_path"),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx_path"),
}


@app.get("/reports/{rid}")
def download_report(rid: int, principal: Principal = Depends(require("report.read"))):
    """View a report: the sealed HTML with a sign-off record added on top. The file itself is not changed."""
    from fastapi.responses import HTMLResponse

    from attestra.reports.signoff import banner_html, inject

    with db.session() as s:
        r, path = _report_file(s, rid, principal)
        sealed = path.read_bytes()
        banner = banner_html(
            r,
            verify_report(s, rid),
            sealed_url=f"/reports/{rid}/sealed",
            pdf_url=f"/reports/{rid}/export/pdf",
            docs_url=f"/reports/{rid}/export/docx",
        )
        audit.record(s, principal.actor, "report.download", "report", r.id)
    return HTMLResponse(inject(sealed, banner), headers={"Cache-Control": "no-store"})


@app.get("/reports/{rid}/export/{fmt}")
def download_report_export(rid: int, fmt: str, principal: Principal = Depends(require("report.read"))):
    """Build (or rebuild) the PDF / Word copy of a sealed report and download it."""
    from attestra.reports.export import export_report_formats

    if fmt not in _REPORT_EXPORT_TYPES:
        raise HTTPException(404, "unknown export format")
    media, key = _REPORT_EXPORT_TYPES[fmt]
    try:
        with db.session() as s:
            r, html_path = _report_file(s, rid, principal)
            out = export_report_formats(r, html_path)
            audit.record(s, principal.actor, "report.exported", "report", r.id, format=fmt)
            name = (
                f"eng{r.engagement_id}-{r.kind}"
                f"{'-' + r.framework if r.framework else ''}-v{r.version}.{fmt}"
            )
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except services.ServiceError as e:
        raise HTTPException(409, str(e)) from e
    return FileResponse(out[key], media_type=media, filename=name, headers={"Cache-Control": "no-store"})


@app.get("/reports/{rid}/sealed")
def download_sealed_report(rid: int, principal: Principal = Depends(require("report.read"))):
    """The sealed report file, byte for byte, exactly as it was hashed and signed."""
    with db.session() as s:
        r, path = _report_file(s, rid, principal)
        audit.record(s, principal.actor, "report.download", "report", r.id, sealed=True)
    return FileResponse(path, media_type="text/html", filename=path.name)


@app.get("/api/evidence/{eid}/download")
def download_evidence(eid: int, principal: Principal = Depends(require("finding.read"))):
    from attestra.models import Evidence, Finding

    with db.session() as s:
        ev = s.get(Evidence, eid)
        if not ev:
            raise HTTPException(404, "evidence not found")
        f = s.get(Finding, ev.finding_id)
        if not f:
            raise HTTPException(404, "evidence not found")
        eng = services.get_engagement(s, f.engagement_id, principal)
        if not services.client_may_download_evidence(principal.role, ev.kind):
            raise HTTPException(403, "client viewers may download only client_upload evidence")
        try:
            path = services.assert_evidence_path_readable(Path(ev.path), eng.tenant_id)
        except LookupError:
            raise HTTPException(404, "evidence not found") from None
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
    idempotency_key: str | None = None


class CreditAllocateIn(BaseModel):
    tenant_id: int
    amount: int = Field(ge=1, le=10000)
    note: str = ""
    idempotency_key: str | None = None


class CreditRenewalIn(BaseModel):
    tenant_id: int
    credits_requested: int = Field(ge=1, le=10000)
    note: str = ""
    idempotency_key: str | None = None


class CreditRenewalResolveIn(BaseModel):
    approve: bool
    admin_note: str = ""
    allocate_amount: int | None = Field(default=None, ge=1, le=10000)


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
            data = body.model_dump()
            idem = data.pop("idempotency_key", None)
            run = services.request_scan(
                s,
                eid,
                **data,
                actor=principal.actor,
                user_id=principal.user_id,
                idempotency_key=idem,
            )
            payload = _scan_dict(run)
            refused = run.status == "refused"
            reason = run.refuse_reason or "scan refused"
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except services.ServiceError as e:
        msg = str(e)
        code = 402 if "exhausted its available test-run credits" in msg else 409
        raise HTTPException(code, msg) from e
    if refused:
        raise HTTPException(403, reason)
    return payload


def _credits_tenant_allowed(principal: Principal, tenant_id: int) -> bool:
    if principal.role == "admin":
        return True
    return principal.tenant_id == tenant_id


@app.get("/api/tenants/{tenant_id}/credits")
def get_tenant_credits(tenant_id: int, principal: Principal = Depends(require("credits.read"))):
    if not _credits_tenant_allowed(principal, tenant_id):
        raise HTTPException(403, "cross-tenant credit access denied")
    from attestra.credits import balance_view

    def fn(s):
        return balance_view(s, tenant_id, actor=principal.actor)

    return _run(fn)


@app.post("/api/credits/allocate", status_code=201)
def allocate_credits_api(body: CreditAllocateIn, principal: Principal = Depends(require("credits.allocate"))):
    from attestra.credits import allocate_credits, balance_view

    try:
        with db.session() as s:
            tx = allocate_credits(
                s,
                body.tenant_id,
                amount=body.amount,
                actor=principal.actor,
                user_id=principal.user_id,
                note=body.note,
                idempotency_key=body.idempotency_key,
            )
            view = balance_view(s, body.tenant_id, actor=principal.actor)
            return {"transaction_id": tx.id, "credits": view}
    except services.ServiceError as e:
        raise HTTPException(400, str(e)) from e


@app.post("/api/credits/renewal-requests", status_code=201)
def create_renewal_request(body: CreditRenewalIn, principal: Principal = Depends(require("credits.request"))):
    if not _credits_tenant_allowed(principal, body.tenant_id):
        raise HTTPException(403, "cross-tenant credit access denied")
    from attestra.credits import request_renewal

    try:
        with db.session() as s:
            row = request_renewal(
                s,
                body.tenant_id,
                credits_requested=body.credits_requested,
                actor=principal.actor,
                user_id=principal.user_id,
                note=body.note,
                idempotency_key=body.idempotency_key,
            )
            return {
                "id": row.id,
                "tenant_id": row.tenant_id,
                "credits_requested": row.credits_requested,
                "status": row.status,
            }
    except services.ServiceError as e:
        raise HTTPException(400, str(e)) from e


@app.get("/api/credits/renewal-requests")
def list_renewal_requests_api(
    status: str | None = Query("pending"),
    tenant_id: int | None = None,
    principal: Principal = Depends(require("credits.read")),
):
    from attestra.credits import list_renewal_requests

    if tenant_id is not None and not _credits_tenant_allowed(principal, tenant_id):
        raise HTTPException(403, "cross-tenant credit access denied")
    if principal.role != "admin":
        tenant_id = principal.tenant_id
        if tenant_id is None:
            return []

    def fn(s):
        rows = list_renewal_requests(s, tenant_id=tenant_id, status=status)
        return [
            {
                "id": r.id,
                "tenant_id": r.tenant_id,
                "credits_requested": r.credits_requested,
                "status": r.status,
                "requested_by": r.requested_by,
                "note": r.note,
                "created_at": r.created_at,
            }
            for r in rows
        ]

    return _run(fn)


@app.post("/api/credits/renewal-requests/{rid}/resolve")
def resolve_renewal_api(
    rid: int,
    body: CreditRenewalResolveIn,
    principal: Principal = Depends(require("credits.allocate")),
):
    from attestra.credits import resolve_renewal

    try:
        with db.session() as s:
            row = resolve_renewal(
                s,
                rid,
                approve=body.approve,
                actor=principal.actor,
                admin_note=body.admin_note,
                allocate_amount=body.allocate_amount,
            )
            return {"id": row.id, "status": row.status, "tenant_id": row.tenant_id}
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except services.ServiceError as e:
        raise HTTPException(400, str(e)) from e


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


@app.post("/api/scans/{sid}/cancel")
def cancel_scan(sid: int, principal: Principal = Depends(require("scan.start"))):
    """Cancel a queued or running scan. Same permission as starting a scan."""

    def fn(s):
        run = services.cancel_scan(s, sid, actor=principal.actor, principal=principal)
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

@app.get("/api/engagements/{eid}/soc2/sample")
def soc2_sample(
    eid: int,
    population: str = Query("findings", description="findings | remediations"),
    period_start: date | None = None,
    period_end: date | None = None,
    seed: int | None = None,
    size: int | None = Query(None, ge=0),
    format: str = Query("json", pattern="^(json|csv)$"),
    principal: Principal = Depends(require("compliance.read")),
):
    """C11: SOC 2 Type II population with a reproducible seeded sample."""
    from fastapi.responses import PlainTextResponse

    from attestra.reports import soc2_sampling

    def fn(s):
        services.get_engagement(s, eid, principal)
        return soc2_sampling.build_sample(
            s, eid, population, period_start=period_start, period_end=period_end, seed=seed, size=size
        )

    result = _run(fn)
    if format == "csv":
        return PlainTextResponse(
            soc2_sampling.to_csv(result),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="eng{eid}-soc2-{population}-sample.csv"'},
        )
    return result


from attestra.web.ui import router as ui_router  # noqa: E402

app.include_router(ui_router)

from attestra.integrations.routes import router as tickets_router  # noqa: E402
from attestra.web.portal import router as portal_router  # noqa: E402

app.include_router(portal_router)
app.include_router(tickets_router)

from attestra.web.ai_routes import api_router as ai_api_router  # noqa: E402
from attestra.web.ai_routes import ui_router as ai_ui_router  # noqa: E402

app.include_router(ai_api_router)
app.include_router(ai_ui_router)

from attestra.proof.routes import router as proof_router  # noqa: E402
from attestra.webhooks.routes import router as webhooks_router  # noqa: E402

app.include_router(proof_router)
app.include_router(webhooks_router)

from attestra.users.routes import api_router as users_api_router  # noqa: E402
from attestra.users.routes import ui_router as users_ui_router  # noqa: E402

app.include_router(users_api_router)
app.include_router(users_ui_router)

from attestra.alerts.routes import api_router as alerts_api_router  # noqa: E402
from attestra.alerts.routes import ui_router as alerts_ui_router  # noqa: E402

app.include_router(alerts_api_router)
app.include_router(alerts_ui_router)

from attestra.certification.routes import api_router as ca_api_router  # noqa: E402
from attestra.certification.routes import ui_router as ca_ui_router  # noqa: E402

app.include_router(ca_api_router)
app.include_router(ca_ui_router)


# ---------------------------------------------------------------- C9 / C10: PCI calendar, ASV import, ISO records


@app.get("/api/engagements/{eid}/pci/calendar")
def pci_calendar(eid: int, principal: Principal = Depends(require("finding.read"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return services.pci_scan_calendar(s, eid)

    return _run(fn)


@app.post("/api/engagements/{eid}/asv/import", status_code=201)
async def import_asv(
    eid: int,
    file: UploadFile = File(...),
    principal: Principal = Depends(require("import.create")),
):
    data = await file.read()

    def fn(s):
        services.get_engagement(s, eid, principal)
        row = services.import_asv_results(s, eid, filename=file.filename or "asv.json", data=data, actor=principal.actor)
        return {"id": row.id, "vendor": row.vendor, "scan_date": row.scan_date, "passing": row.passing,
                "items": row.item_count, "failing": row.failing_count, "sha256": row.sha256}

    return _run(fn)


@app.get("/api/engagements/{eid}/iso/soa")
def iso_soa(eid: int, principal: Principal = Depends(require("finding.read"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return [{"id": r.id, "control_ref": r.control_ref, "title": r.title, "applicable": r.applicable,
                 "implementation": r.implementation, "justification": r.justification}
                for r in services.list_soa(s, eid)]

    return _run(fn)


@app.post("/api/engagements/{eid}/iso/soa/generate")
def iso_soa_generate(eid: int, principal: Principal = Depends(require("engagement.write"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return {"added": services.generate_soa(s, eid, actor=principal.actor)}

    return _run(fn)


class AuditSampleIn(BaseModel):
    population: str = "soa_applicable"
    sample_size: int | None = None
    seed: str = ""


@app.post("/api/engagements/{eid}/iso/samples", status_code=201)
def iso_sample(eid: int, body: AuditSampleIn, principal: Principal = Depends(require("engagement.write"))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        row = services.draw_audit_sample(s, eid, actor=principal.actor, **body.model_dump())
        return {"id": row.id, "population_size": row.population_size, "sample_size": row.sample_size,
                "seed": row.seed, "items": row.items}

    return _run(fn)


from attestra.trust.routes import api_router as trust_api_router  # noqa: E402
from attestra.trust.routes import public_router as trust_public_router  # noqa: E402

app.include_router(trust_api_router)
app.include_router(trust_public_router)


from attestra.library.routes import api_router as library_api_router  # noqa: E402
from attestra.library.routes import ui_router as library_ui_router  # noqa: E402

app.include_router(library_api_router)
app.include_router(library_ui_router)

from attestra.share.routes import api_router as share_api_router  # noqa: E402
from attestra.share.routes import public_router as share_public_router  # noqa: E402
from attestra.share.routes import ui_router as share_ui_router  # noqa: E402

app.include_router(share_api_router)
app.include_router(share_public_router)
app.include_router(share_ui_router)

from attestra.auth_web.routes import api_router as auth_web_api_router  # noqa: E402

app.include_router(auth_web_api_router)

from attestra.automated_vapt.routes import api_router as automated_vapt_api_router  # noqa: E402

app.include_router(automated_vapt_api_router)

# Phase 8 P6-6: SEBI CSCRF security-testing timeline staff UI (parent include_router)
from attestra.web.sebi_routes import ui_router as sebi_ui_router  # noqa: E402

app.include_router(sebi_ui_router)

from attestra.verify.routes import public_router as verify_public_router  # noqa: E402

app.include_router(verify_public_router)

from attestra.web.errors import install as install_ui_errors  # noqa: E402

install_ui_errors(app)
