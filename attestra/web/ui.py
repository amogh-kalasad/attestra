"""Server-rendered dashboard: clients, engagements, scope and targets, test plan, imports.

Identity is a signed session cookie (``attestra_session``) established via ``/login``.
Every write is attributed to the authenticated username in the audit log.
"""

from __future__ import annotations

import os
from collections import Counter
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from attestra import __version__, ai_narratives, db, services
from attestra.auth.roles import has_permission
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

READ_ONLY_ROLES = frozenset({"client_viewer", "auditor"})


def _block_read_only_writes(request: Request) -> None:
    """Step 7.1: client_viewer and auditor sessions may never write through the UI."""
    if request.method != "POST" or request.url.path in ("/login", "/logout"):
        return
    principal = _principal(request)
    if principal and principal.role in READ_ONLY_ROLES:
        raise HTTPException(403, "read-only role")


router = APIRouter(include_in_schema=False, dependencies=[Depends(_block_read_only_writes)])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

ENGAGEMENT_TYPE_LABELS = {
    "va": "Vulnerability Assessment (VA)",
    "pt": "Penetration Test (PT)",
    "vapt": "VAPT (VA + PT)",
    "retest": "Retest",
    "continuous": "Continuous scanning",
}

# Tools the scan runner and the scheduler accept (one list for both forms).
SCAN_TOOLS = ("zap", "nuclei", "testssl", "naabu", "trivy", "semgrep", "gitleaks", "checkov")
SCAN_TOOL_LABELS = {
    "zap": "zap: web app scan (DAST), web targets",
    "nuclei": "nuclei: known issues and misconfigurations, web targets",
    "testssl": "testssl: TLS / SSL configuration, https targets",
    "naabu": "naabu: open ports, web or host targets",
    "trivy": "trivy: vulnerable packages, repo or image targets",
    "semgrep": "semgrep: code scan (SAST), repo targets",
    "gitleaks": "gitleaks: hard-coded secrets, repo targets",
    "checkov": "checkov: infrastructure-as-code checks, repo targets",
}
IMPORT_FORMAT_LABELS = {
    "zap": "OWASP ZAP (JSON report)",
    "nuclei": "Nuclei (JSONL)",
    "trivy": "Trivy (JSON)",
    "sarif": "SARIF 2.1 (Semgrep, CodeQL, Checkov, Gitleaks...)",
}
ROLE_LABELS = {
    "admin": "Admin",
    "lead": "Lead",
    "tester": "Tester",
    "reviewer": "Reviewer (QA)",
    "client_viewer": "Client viewer",
    "auditor": "Auditor",
}
SMALL_SAMPLE = 20


def _display_tz():
    name = os.environ.get("ATTESTRA_DISPLAY_TZ", "Asia/Kolkata")
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception:  # noqa: BLE001 - no tz database on this host
        if name == "Asia/Kolkata":
            return timezone(timedelta(hours=5, minutes=30), "IST")
        return UTC


DISPLAY_TZ = _display_tz()
TZ_LABEL = datetime.now(DISPLAY_TZ).strftime("%Z") or "UTC"


def format_dt(value, fmt: str = "%Y-%m-%d %H:%M") -> str:
    """One formatter for every timestamp shown in the UI: display zone plus its label."""
    if value in (None, ""):
        return "-"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        local = value.astimezone(DISPLAY_TZ)
        return f"{local.strftime(fmt)} {local.strftime('%Z') or TZ_LABEL}"
    return str(value)


def label(value) -> str:
    """snake_case value -> 'Sentence case' for display."""
    if value is None:
        return ""
    text = str(value).replace("_", " ").strip()
    return text[:1].upper() + text[1:]


def fw_name(key) -> str:
    try:
        fw = load_library().frameworks.get(key)
    except Exception:  # noqa: BLE001
        fw = None
    return fw["name"] if fw else str(key)


templates.env.filters["dt"] = format_dt
templates.env.filters["label"] = label
templates.env.filters["fw_name"] = fw_name
templates.env.globals.update(
    type_labels=ENGAGEMENT_TYPE_LABELS, role_labels=ROLE_LABELS, can=has_permission, tz_label=TZ_LABEL,
)


def _actor(request: Request) -> str | None:
    # Resolve through _principal so sessions of disabled or deleted users are rejected.
    principal = _principal(request)
    return principal.username if principal else None


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


def _render(request: Request, template: str, ctx: dict, status_code: int = 200) -> HTMLResponse:
    principal = _principal(request)
    base = {
        "version": __version__,
        "actor": principal.username if principal else None,
        "principal": principal,
        "msg": request.query_params.get("msg"),
        "error": request.query_params.get("error"),
        "path": request.url.path,
    }
    return templates.TemplateResponse(request, template, {**base, **ctx}, status_code=status_code)


def _safe_next(target: str | None) -> str:
    target = target or "/"
    return target if target.startswith("/") and not target.startswith("//") and "\\" not in target else "/"


def _login_redirect(next_url: str = "/", error: str = "Sign in to continue.") -> RedirectResponse:
    nxt = _safe_next(next_url)
    q = f"?next={quote(nxt, safe='/')}" if nxt not in ("/", "/login") else "?"
    sep = "&" if q != "?" else ""
    return RedirectResponse(f"/login{q}{sep}error={quote(error)}", status_code=303)


def _back(url: str, *, msg: str | None = None, error: str | None = None, anchor: str = "") -> RedirectResponse:
    q = f"?msg={quote(msg)}" if msg else f"?error={quote(error)}" if error else ""
    return RedirectResponse(f"{url}{q}{anchor}", status_code=303)


def _require_login(request: Request, next_url: str | None = None):
    principal = _principal(request)
    if not principal:
        if next_url is None:
            next_url = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        return None, _login_redirect(next_url)
    return principal, None


def _do(request: Request, url: str, anchor: str, ok_msg: str, fn, *args, **kwargs) -> RedirectResponse:
    who = _actor(request)
    if not who:
        return _login_redirect(url)
    try:
        with db.session() as s:
            fn(s, *args, **kwargs, actor=who)
    except (services.ServiceError, LookupError) as e:
        return _back(url, error=str(e), anchor=anchor)
    return _back(url, msg=ok_msg, anchor=anchor)


# ---------------------------------------------------------------- identity


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/"):
    return _render(request, "login.html", {"next_url": _safe_next(next)})


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/")):
    from attestra.auth.keys import authenticate_password
    from attestra.auth.session import issue_session

    target = _safe_next(next)
    with db.session() as s:
        principal = authenticate_password(s, username, password)
    if not principal:
        return _login_redirect(target, "Invalid username or password.")
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
    if principal.role in READ_ONLY_ROLES:
        return RedirectResponse("/portal", status_code=303)
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


@router.get("/tuning/false-positives", response_class=HTMLResponse)
def false_positive_rates(request: Request):
    """Phase 7.4: share of each tool's findings marked false_positive, within the user's tenants."""
    from attestra import tuning

    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if principal.role in READ_ONLY_ROLES:
        return RedirectResponse("/portal", status_code=303)
    with db.session() as s:
        rows = tuning.fp_rate_by_tool(s, services.tenant_ids_for(s, principal))
        return _render(request, "tuning_fp.html", {"rows": rows, "small_sample": SMALL_SAMPLE})


@router.get("/engagements/new", response_class=HTMLResponse)
def new_engagement_form(request: Request):
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if principal.role in READ_ONLY_ROLES:
        return _back("/portal", error="Your role is read-only, so you can't create engagements.")
    if not has_permission(principal.role, "engagement.create"):
        return _back("/", error="Only leads and admins can create engagements. Ask your lead to set one up.")
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
    except ValueError:
        return _back("/engagements/new", error="The test window dates aren't valid. Pick them with the date picker.")
    if ws and we and we < ws:
        return _back("/engagements/new", error="The test window end must be on or after the start date.")
    try:
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


def _has_pci(frameworks) -> bool:
    return any(str(f).startswith("pci") for f in frameworks or [])


def _has_iso(frameworks) -> bool:
    return any(str(f).startswith("iso27001") or str(f).startswith("iso_27001") for f in frameworks or [])


def _report_kinds() -> tuple[str, ...]:
    from attestra.reports.render import KINDS

    return tuple(KINDS)


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
    if principal.role in READ_ONLY_ROLES:
        return RedirectResponse(f"/portal/engagements/{eid}", status_code=303)
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
        today = date.today()
        asset_findings = Counter(f.asset_id for f in e.findings if f.asset_id)
        asset_schedules = Counter(sch.asset_id for sch in schedules)
        frameworks = e.frameworks or []
        from attestra.runner import ownership
        from attestra.runner.policy import OWNERSHIP_KINDS

        services.ensure_ownership_tokens(e)
        ov = request.query_params.get("ov", "")
        return _render(request, "engagement.html", {
            "ownership_kinds": OWNERSHIP_KINDS,
            "ownership_info": {a.id: ownership.instructions(a) for a in e.assets if a.kind in OWNERSHIP_KINDS},
            "ownership_methods": services.ownership_methods(s, [a.id for a in e.assets]),
            "ov_open": int(ov) if ov.isdigit() else None,
            "ov_message": request.query_params.get("ovmsg", ""),
            "scan_tools": SCAN_TOOLS,
            "scan_tool_labels": SCAN_TOOL_LABELS,
            "import_labels": IMPORT_FORMAT_LABELS,
            "asset_findings": asset_findings,
            "asset_schedules": asset_schedules,
            "due_schedules": sum(1 for sch in schedules if sch.next_due and sch.next_due <= today),
            "transitions": {k: sorted(v) for k, v in services.TRANSITIONS.items()},
            "report_kinds": _report_kinds(),
            "auth_default_expiry": e.window_end or (today + timedelta(days=90)),
            "has_pci": _has_pci(frameworks),
            "has_iso": _has_iso(frameworks),
            "ai_enabled": ai_narratives.is_enabled(tenant_id=e.tenant_id),
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
    if not [env for env in environments if env.strip()]:
        return _back(f"/engagements/{eid}", error="Tick at least one environment the client authorizes for testing.",
                     anchor="#scope")
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


@router.post("/engagements/{eid}/targets/{aid}/verify-ownership")
def verify_target_ownership(request: Request, eid: int, aid: int):
    """Check now: one DNS TXT lookup and at most one GET of the well-known file. No scanning."""
    url = f"/engagements/{eid}"
    principal, redirect = _require_login(request, url)
    if redirect:
        return redirect
    if not has_permission(principal.role, "asset.verify_ownership"):
        return _back(url, error="Only a lead or admin can check target ownership.", anchor="#targets")
    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            result = services.verify_asset_ownership(s, eid, aid, actor=principal.actor)
            from attestra.models import Asset

            ident = s.get(Asset, aid).identifier
    except (services.ServiceError, LookupError) as e:
        return _back(url, error=str(e), anchor="#targets")
    except Exception:  # noqa: BLE001 - the check must never end in a 500 page
        msg = "The ownership check could not run just now. Try again in a minute."
        return RedirectResponse(f"{url}?ov={aid}&ovmsg={quote(msg)}#ov-{aid}", status_code=303)
    if result.ok:
        how = {"dns": "the DNS TXT record", "file": "the verification file",
               "owner_confirmed": "the owner's confirmation"}.get(result.method, "an earlier check")
        return _back(url, msg=f"Ownership of {ident} verified using {how}. Scans can now be queued for it.",
                     anchor="#targets")
    msg = "Not verified yet. " + result.message
    return RedirectResponse(f"{url}?ov={aid}&ovmsg={quote(msg)}#ov-{aid}", status_code=303)


@router.post("/engagements/{eid}/targets/{aid}/confirm-ownership")
def confirm_target_ownership(
    request: Request, eid: int, aid: int, confirm: str = Form(""), confirmed_by: str = Form(""),
):
    """Option C: the owner confirms control of a private-network target. No network call, no scan."""
    url = f"/engagements/{eid}"
    principal, redirect = _require_login(request, url)
    if redirect:
        return redirect
    if not has_permission(principal.role, "asset.verify_ownership"):
        return _back(url, error="Only a lead or admin can confirm target ownership.", anchor="#targets")
    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            a = services.confirm_private_ownership(
                s, eid, aid, actor=principal.actor, confirmed=confirm == "yes", confirmed_by=confirmed_by,
            )
            ident = a.identifier
    except LookupError as e:
        return _back(url, error=str(e), anchor="#targets")
    except services.ServiceError as e:
        msg = "Not verified yet. " + str(e)
        return RedirectResponse(f"{url}?ov={aid}&ovmsg={quote(msg)}#ov-{aid}", status_code=303)
    return _back(url, msg=f"Ownership of {ident} confirmed by the owner. Scans can now be queued for it.",
                 anchor="#targets")


@router.post("/engagements/{eid}/imports")
async def import_results(request: Request, eid: int, tool: str = Form(...), file: UploadFile = File(...)):
    data = await file.read()
    who = _actor(request)
    url = f"/engagements/{eid}"
    if not who:
        return _login_redirect(url)
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
    asset_id: str = Form(""),
    tool: str = Form(...),
    profile: str = Form("baseline"),
):
    who = _actor(request)
    url = f"/engagements/{eid}"
    if not who:
        return _login_redirect(url)
    if not asset_id.strip().isdigit():
        return _back(url, error="Add a target in 2. Targets in scope first, then choose it here.", anchor="#scans")
    if tool not in SCAN_TOOLS:
        return _back(url, error=f"Choose a tool from the list ({', '.join(SCAN_TOOLS)}).", anchor="#scans")
    try:
        with db.session() as s:
            run = services.request_scan(s, eid, asset_id=int(asset_id), tool=tool, profile=profile, actor=who)
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
        return _login_redirect(f"/engagements/{eid}")
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
    if tool not in SCAN_TOOLS:
        return _back(f"/engagements/{eid}", error=f"Choose a tool from the list ({', '.join(SCAN_TOOLS)}).",
                     anchor="#schedules")
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
        return _login_redirect(f"/engagements/{eid}")
    try:
        with db.session() as s:
            runs = services.enqueue_due_schedules(s, engagement_id=eid, actor=who)
    except (services.ServiceError, LookupError) as e:
        return _back(f"/engagements/{eid}", error=str(e), anchor="#schedules")
    return _back(f"/engagements/{eid}", msg=f"{len(runs)} due scan(s) enqueued.", anchor="#schedules")


# ---------------------------------------------------------------- C9 / C10: PCI calendar and ISO pages


def _staff_page(request: Request):
    principal, redirect = _require_login(request)
    if redirect:
        return None, redirect
    if principal.role in READ_ONLY_ROLES:
        return None, _back("/portal", error="That page is for the test team. Here is your read-only portal instead.")
    return principal, None


@router.get("/compliance/pci-calendar", response_class=HTMLResponse)
def ui_pci_calendar(request: Request):
    principal, redirect = _staff_page(request)
    if redirect:
        return redirect
    with db.session() as s:
        return _render(request, "pci_calendar.html", {"rows": services.pci_calendar_overview(s, principal)})


@router.get("/engagements/{eid}/pci", response_class=HTMLResponse)
def ui_pci_page(request: Request, eid: int):
    principal, redirect = _staff_page(request)
    if redirect:
        return redirect
    with db.session() as s:
        try:
            e = services.get_engagement(s, eid, principal)
        except LookupError:
            raise HTTPException(404, "engagement not found")
        return _render(request, "pci.html", {
            "e": e,
            "cal": services.pci_scan_calendar(s, eid),
            "asv_scans": services.list_asv_scans(s, eid),
            "segmentation_tests": services.list_segmentation_tests(s, eid),
            "today": date.today(),
            "has_pci": _has_pci(e.frameworks),
        })


@router.post("/engagements/{eid}/asv/import")
async def ui_import_asv(request: Request, eid: int, file: UploadFile = File(...)):
    data = await file.read()
    return _do(
        request, f"/engagements/{eid}/pci", "#asv", "ASV results imported.",
        services.import_asv_results, eid, filename=file.filename or "asv.json", data=data,
    )


@router.post("/engagements/{eid}/pci/segmentation")
def ui_pci_segmentation(
    request: Request,
    eid: int,
    boundary: str = Form(...),
    method: str = Form(""),
    result: str = Form(...),
    tested_on: date = Form(...),
    source_zone: str = Form(""),
    target_zone: str = Form(""),
    tester: str = Form(""),
    notes: str = Form(""),
):
    return _do(
        request, f"/engagements/{eid}/pci", "#segmentation", "Segmentation test recorded.",
        services.add_segmentation_test, eid, boundary=boundary, method=method, result=result, tested_on=tested_on,
        source_zone=source_zone, target_zone=target_zone, tester=tester, notes=notes,
    )


@router.get("/engagements/{eid}/iso", response_class=HTMLResponse)
def ui_iso_page(request: Request, eid: int):
    principal, redirect = _staff_page(request)
    if redirect:
        return redirect
    with db.session() as s:
        try:
            e = services.get_engagement(s, eid, principal)
        except LookupError:
            raise HTTPException(404, "engagement not found")
        return _render(request, "iso.html", {
            "e": e,
            "soa": services.list_soa(s, eid),
            "ncs": services.list_nonconformities(s, eid),
            "samples": services.list_audit_samples(s, eid),
            "soa_impl": services.SOA_IMPLEMENTATION,
            "nc_statuses": services.NC_STATUSES,
            "nc_grades": services.NC_GRADES,
            "has_iso": _has_iso(e.frameworks),
        })


@router.post("/engagements/{eid}/iso/soa/generate")
def ui_soa_generate(request: Request, eid: int):
    return _do(request, f"/engagements/{eid}/iso", "#soa", "SoA updated from the library.", services.generate_soa, eid)


@router.post("/engagements/{eid}/iso/soa/{entry_id}")
def ui_soa_update(
    request: Request,
    eid: int,
    entry_id: int,
    applicable: str = Form(""),
    implementation: str = Form("planned"),
    justification: str = Form(""),
):
    return _do(
        request, f"/engagements/{eid}/iso", "#soa", "SoA entry saved.",
        services.update_soa_entry, eid, entry_id, applicable=bool(applicable),
        implementation=implementation, justification=justification,
    )


@router.post("/engagements/{eid}/iso/nc")
def ui_nc_add(
    request: Request,
    eid: int,
    control_ref: str = Form(...),
    description: str = Form(...),
    grade: str = Form("minor"),
    corrective_action: str = Form(""),
    owner: str = Form(""),
    due: str = Form(""),
):
    try:
        due_d = date.fromisoformat(due) if due else None
    except ValueError:
        return _back(f"/engagements/{eid}/iso", error="The due date isn't valid. Pick it with the date picker (YYYY-MM-DD).", anchor="#nc")
    return _do(
        request, f"/engagements/{eid}/iso", "#nc", "Nonconformity raised.",
        services.add_nonconformity, eid, control_ref=control_ref, description=description, grade=grade,
        corrective_action=corrective_action, owner=owner, due=due_d,
    )


@router.post("/engagements/{eid}/iso/nc/{nc_id}")
def ui_nc_update(
    request: Request,
    eid: int,
    nc_id: int,
    status: str = Form(""),
    root_cause: str = Form(""),
    verified_by: str = Form(""),
):
    return _do(
        request, f"/engagements/{eid}/iso", "#nc", "Nonconformity updated.",
        services.update_nonconformity, eid, nc_id, status=status or None, root_cause=root_cause,
        verified_by=verified_by,
    )


@router.post("/engagements/{eid}/iso/sample")
def ui_iso_sample(
    request: Request,
    eid: int,
    population: str = Form("soa_applicable"),
    sample_size: str = Form(""),
    seed: str = Form(""),
):
    raw = sample_size.strip()
    if raw and not (raw.isdigit() and int(raw) > 0):
        return _back(f"/engagements/{eid}/iso", error="Sample size must be a whole number above 0, or blank for the default.",
                     anchor="#sampling")
    size = int(raw) if raw else None
    return _do(
        request, f"/engagements/{eid}/iso", "#sampling", "Audit sample drawn.",
        services.draw_audit_sample, eid, population=population, sample_size=size, seed=seed,
    )


# ---------------------------------------------------------------- UI audit fixes: edit, finding status, reports


@router.post("/engagements/{eid}/edit")
def edit_engagement(
    request: Request,
    eid: int,
    name: str = Form(...),
    window_start: str = Form(""),
    window_end: str = Form(""),
    frameworks: list[str] = Form([]),
):
    url = f"/engagements/{eid}"
    principal, redirect = _require_login(request, url)
    if redirect:
        return redirect
    if not has_permission(principal.role, "engagement.write"):
        return _back(url, error="Your role can't edit engagements.", anchor="#edit")
    try:
        ws = date.fromisoformat(window_start) if window_start else None
        we = date.fromisoformat(window_end) if window_end else None
    except ValueError:
        return _back(url, error="The test window dates aren't valid. Pick them with the date picker.", anchor="#edit")
    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            services.update_engagement(
                s, eid, name=name, window_start=ws, window_end=we, frameworks=frameworks, actor=principal.actor,
            )
    except (services.ServiceError, LookupError) as e:
        return _back(url, error=str(e), anchor="#edit")
    return _back(url, msg="Engagement updated.")


@router.post("/engagements/{eid}/findings/{fid}/status")
def change_finding_status(request: Request, eid: int, fid: int, to: str = Form(...), note: str = Form("")):
    url = f"/engagements/{eid}"
    principal, redirect = _require_login(request, url)
    if redirect:
        return redirect
    if not has_permission(principal.role, "finding.write"):
        return _back(url, error="Your role can't change finding status.", anchor="#findings")
    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            from attestra.models import Finding

            f = s.get(Finding, fid)
            if not f or f.engagement_id != eid:
                raise LookupError(f"finding F-{fid} is not in this engagement")
            services.transition(s, fid, to=to, note=note, actor=principal.actor)
    except (services.ServiceError, LookupError) as e:
        return _back(url, error=str(e), anchor=f"#f-{fid}")
    return _back(url, msg=f"F-{fid} moved to {label(to).lower()}.", anchor=f"#f-{fid}")


@router.post("/engagements/{eid}/reports/generate")
def ui_generate_report(request: Request, eid: int, kind: str = Form(...), framework: str = Form("")):
    from attestra.reports import generate_report

    url = f"/engagements/{eid}"
    principal, redirect = _require_login(request, url)
    if redirect:
        return redirect
    if not has_permission(principal.role, "report.generate"):
        return _back(url, error="Your role can't generate reports.", anchor="#reports")
    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            r = generate_report(s, eid, kind=kind, framework=framework, actor=principal.actor, user_id=principal.user_id)
            rid = r.id
    except (services.ServiceError, LookupError, ValueError) as e:
        return _back(url, error=str(e), anchor="#reports")
    return _back(url, msg=f"Report #{rid} generated ({label(kind).lower()}). Submit it for QA before signing.", anchor="#reports")
