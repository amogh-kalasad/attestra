"""Server-rendered dashboard: clients, engagements, scope and targets, test plan, imports.

The acting user's name is kept in a cookie (`attestra_actor`) so every form
submission is attributed in the audit log. This stands in for SSO in v0.1.
"""

from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from attestra import __version__, db, services
from attestra.compliance import load_library
from attestra.importers import PARSERS
from attestra.models import (
    ASSET_KINDS,
    DEFAULT_TESTS,
    ENGAGEMENT_TYPES,
    ENVIRONMENTS,
    OPEN_STATUSES,
    TEST_TYPES,
    Engagement,
    ImportRun,
    Report,
)

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
COOKIE = "attestra_actor"

ENGAGEMENT_TYPE_LABELS = {
    "va": "Vulnerability Assessment (VA)",
    "pt": "Penetration Test (PT)",
    "vapt": "VAPT (VA + PT)",
    "retest": "Retest",
    "continuous": "Continuous scanning",
}


def _actor(request: Request) -> str | None:
    name = (request.cookies.get(COOKIE) or "").strip()
    return name or None


def _render(request: Request, template: str, ctx: dict) -> HTMLResponse:
    base = {
        "version": __version__,
        "actor": _actor(request),
        "msg": request.query_params.get("msg"),
        "error": request.query_params.get("error"),
        "path": request.url.path,
    }
    return templates.TemplateResponse(request, template, {**base, **ctx})


def _back(url: str, *, msg: str | None = None, error: str | None = None, anchor: str = "") -> RedirectResponse:
    q = f"?msg={quote(msg)}" if msg else f"?error={quote(error)}" if error else ""
    return RedirectResponse(f"{url}{q}{anchor}", status_code=303)


def _do(request: Request, url: str, anchor: str, ok_msg: str, fn, *args, **kwargs) -> RedirectResponse:
    who = _actor(request)
    if not who:
        return _back(url, error="Enter your name in the top bar first, so the action is recorded in the audit log.", anchor=anchor)
    try:
        with db.session() as s:
            fn(s, *args, **kwargs, actor=who)
    except (services.ServiceError, LookupError) as e:
        return _back(url, error=str(e), anchor=anchor)
    return _back(url, msg=ok_msg, anchor=anchor)


# ---------------------------------------------------------------- identity


@router.post("/actor")
def set_actor(request: Request, name: str = Form(""), next: str = Form("/")):
    target = next if next.startswith("/") and not next.startswith("//") else "/"
    resp = RedirectResponse(target, status_code=303)
    if name.strip():
        resp.set_cookie(COOKIE, name.strip()[:100], httponly=True, samesite="lax")
    else:
        resp.delete_cookie(COOKIE)
    return resp


# ---------------------------------------------------------------- home and new engagement


@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    with db.session() as s:
        rows = []
        for e in s.scalars(select(Engagement).order_by(Engagement.id.desc())):
            open_f = [f for f in e.findings if f.status in OPEN_STATUSES]
            rows.append({
                "e": e,
                "open": Counter(f.severity for f in open_f),
                "total": len(e.findings),
                "envs": sorted(services.authorized_environments(e)),
                "targets": len(e.assets),
            })
        return _render(request, "home.html", {"rows": rows})


@router.get("/engagements/new", response_class=HTMLResponse)
def new_engagement_form(request: Request):
    lib = load_library()
    return _render(request, "new_engagement.html", {
        "types": ENGAGEMENT_TYPE_LABELS,
        "frameworks": {k: v["name"] for k, v in lib.frameworks.items()},
        "today": date.today(),
    })


@router.post("/engagements/new")
def create_engagement(
    request: Request,
    tenant: str = Form(...),
    industry: str = Form(""),
    contact_name: str = Form(""),
    contact_email: str = Form(""),
    name: str = Form(...),
    type: str = Form(...),
    frameworks: list[str] = Form([]),
    window_start: str = Form(""),
    window_end: str = Form(""),
):
    who = _actor(request)
    if not who:
        return _back("/engagements/new", error="Enter your name in the top bar first.")
    try:
        ws = date.fromisoformat(window_start) if window_start else None
        we = date.fromisoformat(window_end) if window_end else None
        with db.session() as s:
            e = services.create_engagement(
                s, tenant=tenant, name=name, type=type, frameworks=frameworks, window_start=ws, window_end=we,
                industry=industry, contact_name=contact_name, contact_email=contact_email, actor=who,
            )
            eid = e.id
    except (services.ServiceError, ValueError) as e:
        return _back("/engagements/new", error=str(e))
    return _back(f"/engagements/{eid}", msg="Engagement created. Next: record the signed authorization and add targets.", anchor="#scope")


# ---------------------------------------------------------------- engagement page


def _test_plan(e: Engagement) -> list[dict]:
    """Per target: planned tests, which result formats to import, and what has been imported so far."""
    by_asset: dict[int, list] = {}
    for f in e.findings:
        if f.asset_id:
            by_asset.setdefault(f.asset_id, []).append(f)
    plan = []
    for a in e.assets:
        found = by_asset.get(a.id, [])
        tools_seen = sorted({t for f in found for t in (f.tools or [])})
        tests = []
        for key in a.test_types or DEFAULT_TESTS.get(a.kind, []):
            tt = TEST_TYPES.get(key)
            if not tt:
                continue
            evidence = [i for i in tt["imports"] if i in tools_seen]
            if key == "manual_pt":
                validated = [f for f in found if f.validated_by]
                status = f"{len(validated)} validated" if validated else "pending"
            else:
                status = "results imported" if evidence else "awaiting results"
            tests.append({"key": key, **tt, "status": status, "done": status not in ("pending", "awaiting results")})
        plan.append({"a": a, "tests": tests, "findings": len(found)})
    return plan


@router.get("/engagements/{eid}", response_class=HTMLResponse)
def engagement_page(request: Request, eid: int, framework: str | None = None):
    with db.session() as s:
        try:
            e = services.get_engagement(s, eid)
        except LookupError:
            raise HTTPException(404, "engagement not found")
        lib = load_library()
        fw = framework if framework in lib.frameworks else (e.frameworks[0] if e.frameworks else "pci_dss_4")
        results = services.compliance(s, eid, fw)
        findings = services.list_findings(s, eid)
        imports = list(s.scalars(select(ImportRun).where(ImportRun.engagement_id == eid).order_by(ImportRun.id.desc())))
        reports = list(s.scalars(select(Report).where(Report.engagement_id == eid).order_by(Report.id.desc())))
        authorized = services.authorized_environments(e)
        return _render(request, "engagement.html", {
            "e": e,
            "type_label": ENGAGEMENT_TYPE_LABELS.get(e.type, e.type),
            "findings": findings,
            "imports": imports,
            "reports": reports,
            "results": results,
            "fw": fw,
            "fw_names": {k: v["name"] for k, v in lib.frameworks.items()},
            "counts": Counter(r.status for r in results),
            "sev": Counter(f.severity for f in findings if f.status in OPEN_STATUSES),
            "authorized_envs": authorized,
            "plan": _test_plan(e),
            "environments": ENVIRONMENTS,
            "asset_kinds": ASSET_KINDS,
            "test_types": TEST_TYPES,
            "default_tests": DEFAULT_TESTS,
            "import_formats": sorted(PARSERS),
            "today": date.today(),
        })


@router.post("/engagements/{eid}/authorizations")
async def add_authorization(
    request: Request,
    eid: int,
    document: UploadFile = File(...),
    signer: str = Form(...),
    signed_on: date = Form(...),
    expires_on: date = Form(...),
    environments: list[str] = Form([]),
    rules_of_engagement: str = Form(""),
):
    data = await document.read()
    return _do(
        request, f"/engagements/{eid}", "#scope", "Signed authorization recorded.",
        services.add_authorization, eid, filename=document.filename or "authorization", data=data, signer=signer,
        signed_on=signed_on, expires_on=expires_on, environments=environments, rules_of_engagement=rules_of_engagement,
    )


@router.post("/engagements/{eid}/targets")
def add_target(
    request: Request,
    eid: int,
    kind: str = Form(...),
    identifier: str = Form(...),
    name: str = Form(""),
    environment: str = Form(...),
    test_types: list[str] = Form([]),
    intrusive_allowed: bool = Form(False),
    criticality: int = Form(3),
    exposure: str = Form("internet"),
    in_cde: bool = Form(False),
    owner: str = Form(""),
    notes: str = Form(""),
):
    return _do(
        request, f"/engagements/{eid}", "#scope", f"Target {identifier.strip()} added to scope.",
        services.add_asset, eid, kind=kind, identifier=identifier, name=name, environment=environment,
        test_types=test_types, intrusive_allowed=intrusive_allowed, criticality=criticality, exposure=exposure,
        in_cde=in_cde, owner=owner, notes=notes,
    )


@router.post("/engagements/{eid}/targets/{aid}/remove")
def remove_target(request: Request, eid: int, aid: int):
    return _do(request, f"/engagements/{eid}", "#scope", "Target removed from scope.", services.remove_asset, aid)


@router.post("/engagements/{eid}/imports")
async def import_results(request: Request, eid: int, tool: str = Form(...), file: UploadFile = File(...)):
    data = await file.read()
    who = _actor(request)
    url = f"/engagements/{eid}"
    if not who:
        return _back(url, error="Enter your name in the top bar first.", anchor="#import")
    try:
        with db.session() as s:
            run = services.import_results(s, eid, tool=tool, filename=file.filename or f"{tool}.json", data=data, actor=who)
            msg = f"Imported {file.filename}: {run.new_findings} new, {run.updated_findings} merged"
            if run.unmatched_findings:
                msg += f", {run.unmatched_findings} not matched to any target (check scope)"
    except (services.ServiceError, LookupError) as e:
        return _back(url, error=str(e), anchor="#import")
    return _back(url, msg=msg + ".", anchor="#findings")
