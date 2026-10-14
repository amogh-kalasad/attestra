"""Server-rendered dashboard: clients, engagements, scope and targets, test plan, imports.

Identity is a signed session cookie (``attestra_session``) established via ``/login``.
Every write is attributed to the authenticated username in the audit log.
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
from attestra.auth.session import COOKIE_NAME as COOKIE
from attestra.compliance import load_library
from attestra.importers import PARSERS
from attestra.models import (
    ASSET_KINDS,
    DEFAULT_TESTS,
    ENVIRONMENTS,
    OPEN_STATUSES,
    TEST_TYPES,
    Engagement,
    ImportRun,
    Report,
)

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

ENGAGEMENT_TYPE_LABELS = {
    "va": "Vulnerability Assessment (VA)",
    "pt": "Penetration Test (PT)",
    "vapt": "VAPT (VA + PT)",
    "retest": "Retest",
    "continuous": "Continuous scanning",
}


def _actor(request: Request) -> str | None:
    from attestra.auth.session import read_session

    data = read_session(request.cookies.get(COOKIE))
    if data and data.get("u"):
        return str(data["u"])
    return None


def _principal(request: Request):
    from attestra.auth.keys import Principal
    from attestra.auth.session import read_session
    from attestra.models import User

    data = read_session(request.cookies.get(COOKIE))
    if not data or not data.get("uid"):
        return None
    with db.session() as s:
        user = s.get(User, int(data["uid"]))
        if not user or not user.active:
            return None
        return Principal(
            user_id=user.id,
            username=user.username,
            display_name=user.display_name,
            role=user.role,
            tenant_id=user.tenant_id,
        )


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


def _require_login(request: Request, next_url: str = "/"):
    principal = _principal(request)
    if not principal:
        return None, _back("/login", error="Sign in to continue.")
    return principal, None


def _do(request: Request, url: str, anchor: str, ok_msg: str, fn, *args, **kwargs) -> RedirectResponse:
    who = _actor(request)
    if not who:
        return _back("/login", error="Sign in to continue.", anchor=anchor)
    try:
        with db.session() as s:
            fn(s, *args, **kwargs, actor=who)
    except (services.ServiceError, LookupError) as e:
        return _back(url, error=str(e), anchor=anchor)
    return _back(url, msg=ok_msg, anchor=anchor)


# ---------------------------------------------------------------- identity


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return _render(request, "login.html", {})


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/")):
    from attestra.auth.keys import authenticate_password
    from attestra.auth.session import issue_session

    target = next if next.startswith("/") and not next.startswith("//") else "/"
    with db.session() as s:
        principal = authenticate_password(s, username, password)
    if not principal:
        return _back("/login", error="Invalid username or password.")
    resp = RedirectResponse(target, status_code=303)
    resp.set_cookie(COOKIE, issue_session(principal.user_id, principal.username), httponly=True, samesite="lax")
    return resp


@router.post("/logout")
def logout(next: str = Form("/")):
    target = next if next.startswith("/") and not next.startswith("//") else "/"
    resp = RedirectResponse(target, status_code=303)
    resp.delete_cookie(COOKIE)
    return resp


# ---------------------------------------------------------------- home and new engagement


@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    with db.session() as s:
        rows = []
        for e in s.scalars(services.scoped(s, Engagement, principal).order_by(Engagement.id.desc())):
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
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
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
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    try:
        ws = date.fromisoformat(window_start) if window_start else None
        we = date.fromisoformat(window_end) if window_end else None
        with db.session() as s:
            e = services.create_engagement(
                s, tenant=tenant, name=name, type=type, frameworks=frameworks, window_start=ws, window_end=we,
                industry=industry, contact_name=contact_name, contact_email=contact_email,
                actor=principal.actor, principal=principal,
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
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    with db.session() as s:
        try:
            e = services.get_engagement(s, eid, principal)
        except LookupError:
            raise HTTPException(404, "engagement not found")
        lib = load_library()
        fw = framework if framework in lib.frameworks else (e.frameworks[0] if e.frameworks else "pci_dss_4")
        results = services.compliance(s, eid, fw)
        findings = services.list_findings(s, eid)
        imports = list(s.scalars(select(ImportRun).where(ImportRun.engagement_id == eid).order_by(ImportRun.id.desc())))
        reports = list(s.scalars(select(Report).where(Report.engagement_id == eid).order_by(Report.id.desc())))
        scans = services.list_scans(s, eid)
        authorized = services.authorized_environments(e)
        asv_scans = list(e.asv_scans)
        segmentation_tests = list(e.segmentation_tests)
        nonconformities = list(e.nonconformities)
        schedules = services.list_scan_schedules(s, eid)
        return _render(request, "engagement.html", {
            "e": e,
            "type_label": ENGAGEMENT_TYPE_LABELS.get(e.type, e.type),
            "findings": findings,
            "imports": imports,
            "scans": scans,
            "reports": reports,
            "asv_scans": asv_scans,
            "segmentation_tests": segmentation_tests,
            "nonconformities": nonconformities,
            "schedules": schedules,
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
        return _back("/login", error="Sign in to continue.", anchor="#import")
    try:
        with db.session() as s:
            run = services.import_results(s, eid, tool=tool, filename=file.filename or f"{tool}.json", data=data, actor=who)
            msg = f"Imported {file.filename}: {run.new_findings} new, {run.updated_findings} merged"
            if run.unmatched_findings:
                msg += f", {run.unmatched_findings} not matched to any target (check scope)"
    except (services.ServiceError, LookupError) as e:
        return _back(url, error=str(e), anchor="#import")
    return _back(url, msg=msg + ".", anchor="#findings")


@router.post("/engagements/{eid}/scans")
def queue_scan(
    request: Request,
    eid: int,
    asset_id: int = Form(...),
    tool: str = Form(...),
    profile: str = Form("baseline"),
):
    who = _actor(request)
    url = f"/engagements/{eid}"
    if not who:
        return _back("/login", error="Sign in to continue.", anchor="#scans")
    try:
        with db.session() as s:
            run = services.request_scan(s, eid, asset_id=asset_id, tool=tool, profile=profile, actor=who)
            if run.status == "refused":
                return _back(url, error=run.refuse_reason or "scan refused", anchor="#scans")
    except (services.ServiceError, LookupError) as e:
        return _back(url, error=str(e), anchor="#scans")
    return _back(url, msg=f"Scan #{run.id} queued ({tool}/{profile}).", anchor="#scans")


@router.post("/engagements/{eid}/asv")
async def ui_add_asv(
    request: Request,
    eid: int,
    vendor: str = Form(...),
    scan_date: date = Form(...),
    file: UploadFile = File(...),
    passing: str = Form(""),
):
    data = await file.read()
    who = _actor(request)
    if not who:
        return _back("/login", error="Sign in to continue.")
    try:
        with db.session() as s:
            services.add_asv_scan(
                s, eid, vendor=vendor, scan_date=scan_date, passing=bool(passing),
                filename=file.filename or "asv.pdf", data=data, actor=who,
            )
    except (services.ServiceError, LookupError) as e:
        return _back(f"/engagements/{eid}", error=str(e), anchor="#pci-records")
    return _back(f"/engagements/{eid}", msg="ASV record added.", anchor="#pci-records")


@router.post("/engagements/{eid}/segmentation")
def ui_add_segmentation(
    request: Request,
    eid: int,
    boundary: str = Form(...),
    method: str = Form(""),
    result: str = Form(...),
    tested_on: date = Form(...),
):
    return _do(
        request, f"/engagements/{eid}", "#pci-records", "Segmentation test recorded.",
        services.add_segmentation_test, eid, boundary=boundary, method=method, result=result, tested_on=tested_on,
    )


@router.post("/engagements/{eid}/halt")
def halt_engagement(request: Request, eid: int):
    return _do(request, f"/engagements/{eid}", "#scans", "Engagement halted.", services.halt_engagement, eid)


@router.post("/engagements/{eid}/resume")
def resume_engagement(request: Request, eid: int):
    return _do(request, f"/engagements/{eid}", "#scans", "Engagement resumed.", services.resume_engagement, eid)


# ---------------------------------------------------------------- Step 6.7: scheduler UI


@router.post("/engagements/{eid}/schedules")
def ui_add_schedule(
    request: Request,
    eid: int,
    asset_id: int = Form(...),
    tool: str = Form(...),
    cadence: str = Form("quarterly"),
    next_due: date = Form(...),
):
    return _do(
        request, f"/engagements/{eid}", "#schedules", f"Scheduled {tool} ({cadence}).",
        services.add_scan_schedule, eid, asset_id=asset_id, tool=tool, cadence=cadence, next_due=next_due,
    )


@router.post("/engagements/{eid}/schedules/{sid}/update")
def ui_update_schedule(
    request: Request,
    eid: int,
    sid: int,
    cadence: str = Form(...),
    next_due: date = Form(...),
):
    return _do(
        request, f"/engagements/{eid}", "#schedules", "Schedule updated.",
        services.update_scan_schedule, eid, sid, cadence=cadence, next_due=next_due,
    )


@router.post("/engagements/{eid}/schedules/{sid}/remove")
def ui_remove_schedule(request: Request, eid: int, sid: int):
    return _do(
        request, f"/engagements/{eid}", "#schedules", "Schedule removed.",
        services.remove_scan_schedule, eid, sid,
    )


@router.post("/engagements/{eid}/schedules/run-due")
def ui_run_due(request: Request, eid: int):
    who = _actor(request)
    if not who:
        return _back("/login", error="Sign in to continue.", anchor="#schedules")
    try:
        with db.session() as s:
            runs = services.enqueue_due_schedules(s, engagement_id=eid, actor=who)
    except (services.ServiceError, LookupError) as e:
        return _back(f"/engagements/{eid}", error=str(e), anchor="#schedules")
    return _back(f"/engagements/{eid}", msg=f"{len(runs)} due scan(s) enqueued.", anchor="#schedules")
