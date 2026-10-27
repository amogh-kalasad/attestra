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
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from attestra import __version__, ai_narratives, audit, db, services
from attestra.auth.roles import has_permission
from attestra.auth.session import COOKIE_NAME as COOKIE
from attestra.compliance import load_library
from attestra.dedup import detected_by_label
from attestra.importers import PARSERS
from attestra.models import (
    ASSET_KINDS,
    DISPLAY_LABELS,
    ENGAGEMENT_TYPE_LABELS,
    ENVIRONMENTS,
    OPEN_STATUSES,
    TEST_TYPES,
    Engagement,
    ImportRun,
    Report,
    allowed_test_types_for,
    default_tests_for,
    engagement_type_label,
    new_engagement_type_labels,
)

READ_ONLY_ROLES = frozenset({"client_viewer", "auditor"})


def _block_read_only_writes(request: Request) -> None:
    """Step 7.1: client_viewer and auditor sessions may never write through the UI.

    Raises 403 ``read-only role``. The HTML error handler turns that into a
    portal redirect with a clear message (UI audit #6); API clients keep JSON.
    """
    if request.method != "POST" or request.url.path in ("/login", "/logout"):
        return
    principal = _principal(request)
    if principal and principal.role in READ_ONLY_ROLES:
        raise HTTPException(403, "read-only role")


router = APIRouter(include_in_schema=False, dependencies=[Depends(_block_read_only_writes)])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# Tools the scan runner and the scheduler accept (one list for both forms).
SCAN_TOOLS = ("zap", "nuclei", "testssl", "naabu", "webcheck", "trivy", "semgrep", "gitleaks", "checkov")
SCAN_TOOL_LABELS = {
    "zap": "zap: web app scan (DAST), web targets",
    "nuclei": "nuclei: known issues and misconfigurations, web targets",
    "testssl": "testssl: TLS / SSL configuration, https targets",
    "naabu": "naabu: open ports, web or host targets",
    "webcheck": "webcheck: security headers, HSTS, security.txt and DNS records (passive), web targets",
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
    "webcheck": "Attestra webcheck (JSON)",
    "observatory": "Mozilla HTTP Observatory (saved JSON)",
    "ssllabs": "Qualys SSL Labs (saved JSON)",
    "burp": "Burp Suite (Issues XML)",
    "nessus": "Nessus (.nessus XML)",
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
    """snake_case value -> curated or sentence-case display label."""
    if value is None:
        return ""
    key = str(value).strip()
    if key in DISPLAY_LABELS:
        return DISPLAY_LABELS[key]
    if key in TEST_TYPES:
        return TEST_TYPES[key]["label"]
    text = key.replace("_", " ").strip()
    return text[:1].upper() + text[1:] if text else ""


def fw_name(key) -> str:
    try:
        fw = load_library().frameworks.get(key)
    except Exception:  # noqa: BLE001
        fw = None
    return fw["name"] if fw else str(key)


templates.env.filters["dt"] = format_dt
templates.env.filters["label"] = label
templates.env.filters["fw_name"] = fw_name
templates.env.filters["type_label"] = engagement_type_label
templates.env.globals.update(
    type_labels=ENGAGEMENT_TYPE_LABELS,
    role_labels=ROLE_LABELS,
    can=has_permission,
    tz_label=TZ_LABEL,
    detected_by=detected_by_label,
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


def _org_credits_for(principal, s, tenant_id: int | None = None) -> dict | None:
    """Server-sourced organization credit balance for the header and scan UI."""
    if principal is None or not has_permission(principal.role, "credits.read"):
        return None
    tid = tenant_id if tenant_id is not None else principal.tenant_id
    if tid is None:
        return None
    if principal.role != "admin" and principal.tenant_id != tid:
        return None
    from attestra.credits import balance_view

    return balance_view(s, int(tid), actor=getattr(principal, "actor", None) or principal.username)


def _render(request: Request, template: str, ctx: dict, status_code: int = 200) -> HTMLResponse:
    principal = _principal(request)
    base = {
        "version": __version__,
        "actor": principal.username if principal else None,
        "principal": principal,
        "msg": request.query_params.get("msg"),
        "error": request.query_params.get("error"),
        "path": request.url.path,
        "org_credits": ctx.get("org_credits"),
    }
    if base["org_credits"] is None and principal is not None:
        with db.session() as s:
            base["org_credits"] = _org_credits_for(principal, s)
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
    # Preserve any existing query on url (e.g. /settings/alerts?tenant_id=1).
    flash = f"msg={quote(msg)}" if msg else f"error={quote(error)}" if error else ""
    if not flash:
        return RedirectResponse(f"{url}{anchor}", status_code=303)
    sep = "&" if "?" in url else "?"
    return RedirectResponse(f"{url}{sep}{flash}{anchor}", status_code=303)


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
    try:
        fw_names = [v["name"] for v in load_library().frameworks.values()]
    except Exception:  # the sign-in page must render even if the library fails to load
        fw_names = []
    return _render(
        request,
        "login.html",
        {"next_url": _safe_next(next), "login_frameworks": fw_names, "login_formats": list(IMPORT_FORMAT_LABELS.values())},
    )


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


_STATIC_DIR = Path(__file__).parent / "static"
_STATIC_TYPES = {".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8", ".woff2": "font/woff2"}
_STATIC_FILES = {
    "attestra.css": _STATIC_DIR / "attestra.css",
    "attestra.js": _STATIC_DIR / "attestra.js",
    "fonts/Inter.woff2": _STATIC_DIR / "fonts" / "Inter.woff2",
    "fonts/Fraunces.woff2": _STATIC_DIR / "fonts" / "Fraunces.woff2",
    "fonts/JetBrainsMono.woff2": _STATIC_DIR / "fonts" / "JetBrainsMono.woff2",
}


@router.get("/static/{name:path}", include_in_schema=False)
def static_asset(name: str):
    """Serve the UI stylesheet and self-hosted fonts (fixed allow-list, same origin for the CSP)."""
    path = _STATIC_FILES.get(name)
    if path is None or not path.is_file():
        raise HTTPException(status_code=404)
    return FileResponse(path, media_type=_STATIC_TYPES[path.suffix], headers={"Cache-Control": "public, max-age=86400"})


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


@router.get("/sites", response_class=HTMLResponse)
def sites_dashboard(request: Request):
    """All targets for the signed-in tenant: grade, open counts, last scan, trend."""
    # @lat: [[interfaces#Web dashboard#Sites dashboard]]
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if principal.role in READ_ONLY_ROLES:
        return RedirectResponse("/portal", status_code=303)
    sort = (request.query_params.get("sort") or "grade").strip().lower()
    q = (request.query_params.get("q") or "").strip()
    with db.session() as s:
        rows = services.list_tenant_sites(s, principal, sort=sort, q=q)
        return _render(request, "sites.html", {"rows": rows, "sort": sort, "q": q})


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


@router.get("/tuning/false-positives/{tool}", response_class=HTMLResponse)
def false_positive_tool_findings(request: Request, tool: str):
    """Per-tool findings list for the FP rates page (UI audit #87)."""
    from attestra import tuning

    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if principal.role in READ_ONLY_ROLES:
        return RedirectResponse("/portal", status_code=303)
    with db.session() as s:
        tenant_ids = services.tenant_ids_for(s, principal)
        findings = tuning.findings_for_tool(s, tool, tenant_ids)
        fp_n = sum(1 for f in findings if f.status == "false_positive")
        return _render(request, "tuning_fp_tool.html", {
            "tool": tool,
            "findings": findings,
            "false_positive": fp_n,
            "total": len(findings),
            "small_sample": SMALL_SAMPLE,
        })


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
    from attestra.compliance.recommend import catalogues

    cats = catalogues()
    return _render(request, "new_engagement.html", {
        "types": new_engagement_type_labels(),
        "frameworks": {k: v["name"] for k, v in lib.frameworks.items()},
        "industries": cats["industries"],
        "countries": cats["countries"],
        "technical_scopes": cats["technical_scopes"],
        "recommend_disclaimer": cats["disclaimer"],
        "today": date.today(),
    })


@router.post("/engagements/new")
def create_engagement(
    request: Request,
    tenant: str = Form(...),
    industry: str = Form(""),
    country: str = Form(""),
    regulatory_status: str = Form(""),
    technical_scope: list[str] = Form([]),
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
                s,
                tenant=tenant,
                name=name,
                type=type,
                frameworks=frameworks,
                window_start=ws,
                window_end=we,
                industry=industry,
                country=country,
                regulatory_status=regulatory_status,
                technical_scope=technical_scope,
                contact_name=contact_name,
                contact_email=contact_email,
                actor=principal.actor,
                principal=principal,
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
        for key in a.test_types or default_tests_for(a.kind, e.type):
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


def _ct_apexes_for(s, eid: int) -> list[str]:
    """Apex domains that may run CT suggestions (R14: apex itself in signed scope)."""
    from attestra.runner.authorization import AuthorizationError, scope_for_engagement
    from attestra.runner.ct_suggestions import in_scope_apexes

    try:
        return in_scope_apexes(scope_for_engagement(s, eid))
    except AuthorizationError:
        return []


def _engagement_ctx(
    request: Request,
    s,
    principal,
    eid: int,
    framework: str | None = None,
    *,
    ct_suggestions: list | None = None,
    ct_apex: str = "",
) -> dict:
    """Shared context for the engagement page (overview + CT suggestion results)."""
    e = services.get_engagement(s, eid, principal)
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
    return {
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
        "type_label": engagement_type_label(e.type),
        "findings": findings,
        "passed_checks": services.list_passed_checks(s, eid),
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
        "test_types": {
            k: v for k, v in TEST_TYPES.items() if k in allowed_test_types_for(e.type)
        },
        "default_tests": {
            kind: default_tests_for(kind, e.type) for kind in ASSET_KINDS
        },
        "import_formats": sorted(PARSERS),
        "today": date.today(),
        "ct_apexes": _ct_apexes_for(s, eid),
        "ct_suggestions": ct_suggestions or [],
        "ct_apex": ct_apex,
        "org_credits": _org_credits_for(principal, s, e.tenant_id),
    }


@router.get("/engagements/{eid}", response_class=HTMLResponse)
def engagement_page(request: Request, eid: int, framework: str | None = None):
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if principal.role in READ_ONLY_ROLES:
        return RedirectResponse(f"/portal/engagements/{eid}", status_code=303)
    with db.session() as s:
        try:
            ctx = _engagement_ctx(request, s, principal, eid, framework)
        except LookupError:
            raise HTTPException(404, "engagement not found")
        return _render(request, "engagement.html", ctx)


@router.get("/engagements/{eid}/findings/export")
def export_findings_ui(request: Request, eid: int, asset_id: int | None = None):
    """Page button: download findings CSV (same guard and audit as the API)."""
    from attestra.reports.findings_csv import export_findings_csv

    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if not has_permission(principal.role, "finding.read"):
        raise HTTPException(403, "permission denied: finding.read")
    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            if asset_id is not None:
                asset = services.get_asset(s, asset_id, principal)
                if asset.engagement_id != eid:
                    raise LookupError("target not found")
            body = export_findings_csv(s, eid, actor=principal.actor, asset_id=asset_id)
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    name = f"eng{eid}-findings.csv" if asset_id is None else f"eng{eid}-asset{asset_id}-findings.csv"
    return PlainTextResponse(
        body,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.get("/engagements/{eid}/export/{fmt}")
def export_engagement_ui(request: Request, eid: int, fmt: str, framework: str = ""):
    """Page buttons: SARIF, OSCAL, Excel, JSON, or Markdown of consolidated findings."""
    import json

    from fastapi.responses import Response

    from attestra.reports.engagement_export import export_engagement_json
    from attestra.reports.markdown_export import export_engagement_markdown
    from attestra.reports.oscal import assessment_results, poam
    from attestra.reports.sarif import findings_to_sarif
    from attestra.reports.xlsx_export import export_engagement_xlsx

    perms = {
        "sarif": "finding.read",
        "oscal": "report.read",
        "oscal-poam": "report.read",
        "xlsx": "finding.read",
        "json": "finding.read",
        "markdown": "finding.read",
        "md": "finding.read",
    }
    if fmt not in perms:
        raise HTTPException(404, "unknown export format")
    principal, redirect = _require_login(request, f"/engagements/{eid}")
    if redirect:
        return redirect
    if not has_permission(principal.role, perms[fmt]):
        raise HTTPException(403, f"permission denied: {perms[fmt]}")
    try:
        with db.session() as s:
            eng = services.get_engagement(s, eid, principal)
            if fmt == "xlsx":
                data = export_engagement_xlsx(s, eid, actor=principal.actor)
                return Response(
                    data,
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={
                        "Content-Disposition": f'attachment; filename="eng{eid}-export.xlsx"',
                        "Cache-Control": "no-store",
                    },
                )
            if fmt in ("markdown", "md"):
                body = export_engagement_markdown(s, eid, actor=principal.actor)
                return PlainTextResponse(
                    body,
                    media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="eng{eid}-findings.md"'},
                )
            if fmt == "json":
                doc, name = export_engagement_json(s, eid, actor=principal.actor), f"eng{eid}-export.json"
            elif fmt == "sarif":
                doc, name = findings_to_sarif(s, eid), f"eng{eid}-findings.sarif"
                audit.record(
                    s, principal.actor, "engagement.exported", "engagement", eid, format=fmt, framework=framework
                )
            elif fmt == "oscal":
                if framework not in (eng.frameworks or []):
                    raise LookupError("choose one of this engagement's frameworks")
                doc, name = assessment_results(s, eid, framework), f"eng{eid}-{framework}-oscal-ar.json"
                audit.record(
                    s, principal.actor, "engagement.exported", "engagement", eid, format=fmt, framework=framework
                )
            else:
                doc, name = poam(s, eid), f"eng{eid}-oscal-poam.json"
                audit.record(
                    s, principal.actor, "engagement.exported", "engagement", eid, format=fmt, framework=framework
                )
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    return PlainTextResponse(
        json.dumps(doc, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.post("/engagements/{eid}/scope/suggestions")
def fetch_ct_suggestions_ui(request: Request, eid: int, apex: str = Form(...)):
    """Find subdomain suggestions from CT logs (one request). Never changes scope."""
    from attestra.runner.ct_suggestions import suggestions_for_engagement

    principal, redirect = _require_login(request, f"/engagements/{eid}")
    if redirect:
        return redirect
    if not has_permission(principal.role, "asset.write"):
        return _back(f"/engagements/{eid}", error="Only a lead or tester with asset write can fetch suggestions.",
                     anchor="#targets")
    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            result = suggestions_for_engagement(s, eid, apex, actor=principal.actor)
            ctx = _engagement_ctx(
                request, s, principal, eid,
                ct_suggestions=result["suggestions"],
                ct_apex=result["apex"],
            )
            return _render(request, "engagement.html", ctx)
    except LookupError as e:
        return _back(f"/engagements/{eid}", error=str(e), anchor="#targets")
    except services.ServiceError as e:
        return _back(f"/engagements/{eid}", error=str(e), anchor="#targets")


@router.get("/engagements/{eid}/authorizations/{aid}/document")
def ui_download_authorization_document(request: Request, eid: int, aid: int):
    """Super Admin-only download of the signed authorization file."""
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if not has_permission(principal.role, "authorization.document"):
        return _back(f"/engagements/{eid}", error="Only a Super Admin can download signed authorization documents.", anchor="#scope")
    try:
        with db.session() as s:
            a, path = services.open_authorization_document(s, aid, principal=principal)
            if a.engagement_id != eid:
                raise LookupError("authorization not found")
            return FileResponse(
                str(path),
                filename=a.document_name or "authorization",
                media_type="application/octet-stream",
                headers={"Cache-Control": "no-store"},
            )
    except LookupError:
        return _back(f"/engagements/{eid}", error="Authorization document not found.", anchor="#scope")
    except PermissionError:
        return _back(f"/engagements/{eid}", error="Only a Super Admin can download signed authorization documents.", anchor="#scope")


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


@router.get("/engagements/{eid}/targets/{aid}", response_class=HTMLResponse)
def target_page(request: Request, eid: int, aid: int):
    """Target page: site grade breakdown (Phase 1) and C11 scan history."""
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    with db.session() as s:
        try:
            e = services.get_engagement(s, eid, principal)
            asset = services.get_asset(s, aid, principal)
        except LookupError:
            raise HTTPException(404, "target not found")
        if asset.engagement_id != eid:
            raise HTTPException(404, "target not found")
        history = services.asset_scan_history(s, aid, principal)
        site_grade = services.asset_site_grade(s, aid, principal)
        from attestra.cert_expiry import asset_cert_status

        cert_status = asset_cert_status(s, aid)
        return _render(
            request,
            "asset.html",
            {
                "e": e,
                "asset": asset,
                "history": history,
                "site_grade": site_grade,
                "cert_status": cert_status,
            },
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
    principal = _principal(request)
    who = principal.username if principal else None
    url = f"/engagements/{eid}"
    if not who:
        return _login_redirect(url)
    if not asset_id.strip().isdigit():
        return _back(url, error="Add a target in 2. Targets in scope first, then choose it here.", anchor="#scans")
    if tool not in SCAN_TOOLS:
        return _back(url, error=f"Choose a tool from the list ({', '.join(SCAN_TOOLS)}).", anchor="#scans")
    try:
        with db.session() as s:
            run = services.request_scan(
                s,
                eid,
                asset_id=int(asset_id),
                tool=tool,
                profile=profile,
                actor=who,
                user_id=principal.user_id if principal else None,
            )
            if run.status == "refused":
                return _back(url, error=run.refuse_reason or "scan refused", anchor="#scans")
    except (services.ServiceError, LookupError) as e:
        return _back(url, error=str(e), anchor="#scans")
    return _back(url, msg=f"Scan #{run.id} queued ({tool}/{profile}).", anchor="#scans")


@router.get("/engagements/{eid}/scans/{sid}", response_class=HTMLResponse)
def scan_page(request: Request, eid: int, sid: int):
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if principal.role in READ_ONLY_ROLES:
        return RedirectResponse(f"/portal/engagements/{eid}", status_code=303)
    with db.session() as s:
        try:
            e = services.get_engagement(s, eid, principal)
            run = services.get_scan(s, sid)
        except LookupError:
            raise HTTPException(404, "scan not found") from None
        if run.engagement_id != eid:
            raise HTTPException(404, "scan not found")
        return _render(request, "scan.html", {
            "e": e,
            "run": run,
            "can_cancel": run.status in ("queued", "running") and has_permission(principal.role, "scan.start"),
        })


@router.post("/engagements/{eid}/scans/{sid}/cancel")
def ui_cancel_scan(request: Request, eid: int, sid: int):
    url = f"/engagements/{eid}/scans/{sid}"
    principal, redirect = _require_login(request, url)
    if redirect:
        return redirect
    if not has_permission(principal.role, "scan.start"):
        return _back(f"/engagements/{eid}", error="Your role can't cancel scans.", anchor="#scans")
    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            run = services.get_scan(s, sid)
            if run.engagement_id != eid:
                raise LookupError(f"scan {sid} not found")
            services.cancel_scan(s, sid, actor=principal.actor, principal=principal)
    except (services.ServiceError, LookupError) as e:
        return _back(url, error=str(e))
    return _back(url, msg=f"Scan #{sid} cancelled.")


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
    client_name: str = Form(""),
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
                s, eid, name=name, window_start=ws, window_end=we, frameworks=frameworks,
                actor=principal.actor, client_name=client_name or None,
            )
    except (services.ServiceError, LookupError) as e:
        return _back(url, error=str(e), anchor="#edit")
    return _back(url, msg="Engagement updated.")


_TEXT_PREVIEW_KINDS = frozenset({"http_pair", "log", "code", "note", "package", "capture_failure"})
_TEXT_PREVIEW_CAP = 8000


def _evidence_text_previews(evidence_rows: list) -> dict[int, str]:
    """Load small text/json evidence bodies for finding-detail readable preview."""
    out: dict[int, str] = {}
    for ev in evidence_rows:
        if ev.kind not in _TEXT_PREVIEW_KINDS:
            continue
        path = Path(ev.path)
        if not path.is_file():
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if len(raw) > 200_000:
            out[ev.id] = "(preview omitted — file too large; use Download)"
            continue
        text = raw.decode("utf-8", "replace")
        if len(text) > _TEXT_PREVIEW_CAP:
            text = text[:_TEXT_PREVIEW_CAP] + f"\n… truncated ({len(raw)} bytes total)"
        out[ev.id] = text
    return out


@router.get("/engagements/{eid}/findings/{fid}", response_class=HTMLResponse)
def finding_page(request: Request, eid: int, fid: int):
    """Finding detail page (UI audit #55)."""
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if principal.role in READ_ONLY_ROLES:
        return RedirectResponse(f"/portal/engagements/{eid}", status_code=303)
    with db.session() as s:
        try:
            e = services.get_engagement(s, eid, principal)
        except LookupError:
            raise HTTPException(404, "engagement not found") from None
        from attestra.comments import can_add_comment, can_delete_comment, list_comments
        from attestra.evidence.gallery import build_gallery
        from attestra.library import service as lib
        from attestra.models import Finding, ProofReplay

        f = s.get(Finding, fid)
        if not f or f.engagement_id != eid:
            raise HTTPException(404, "finding not found")
        # Touch relationships while the session is open.
        evidence_rows = list(f.evidence)
        _ = f.asset
        observations = sorted(list(f.observations or []), key=lambda o: o.id)
        gallery = build_gallery(evidence_rows)
        text_previews = _evidence_text_previews(evidence_rows)
        replays = list(
            s.scalars(select(ProofReplay).where(ProofReplay.finding_id == fid).order_by(ProofReplay.id.desc()))
        )
        latest_replay: dict[int, ProofReplay] = {}
        for r in replays:
            latest_replay.setdefault(r.evidence_id, r)
        comments = list_comments(s, fid, principal)
        for c in comments:
            c["can_delete"] = can_delete_comment(
                principal.role, author_user_id=c["author_user_id"], actor_user_id=principal.user_id
            )
        return _render(request, "finding.html", {
            "e": e,
            "f": f,
            "observations": observations,
            "siblings": services.list_findings(s, eid),
            "fix": lib.guidance_for_finding(s, f),
            "transitions": {k: sorted(v) for k, v in services.TRANSITIONS.items()},
            "comments": comments,
            "can_add_comment": can_add_comment(principal.role),
            "show_accept_risk": request.query_params.get("accept_risk") == "1",
            "gallery": gallery,
            "latest_replay": latest_replay,
            "text_previews": text_previews,
        })


@router.get("/engagements/{eid}/evidence/{evid}/download")
def ui_download_evidence(request: Request, eid: int, evid: int):
    """Session-auth download of one evidence file (same path checks as the API)."""
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if not has_permission(principal.role, "finding.read"):
        raise HTTPException(403, "not allowed")
    from attestra.models import Evidence, Finding

    with db.session() as s:
        try:
            eng = services.get_engagement(s, eid, principal)
        except LookupError:
            raise HTTPException(404, "evidence not found") from None
        ev = s.get(Evidence, evid)
        if not ev:
            raise HTTPException(404, "evidence not found")
        f = s.get(Finding, ev.finding_id)
        if not f or f.engagement_id != eid:
            raise HTTPException(404, "evidence not found")
        if not services.client_may_download_evidence(principal.role, ev.kind):
            raise HTTPException(403, "client viewers may download only client_upload evidence")
        try:
            path = services.assert_evidence_path_readable(Path(ev.path), eng.tenant_id)
        except LookupError:
            raise HTTPException(404, "evidence not found") from None
        audit.record(s, principal.actor, "evidence.download", "evidence", ev.id, finding_id=f.id)
        return FileResponse(str(path), filename=ev.filename, media_type="application/octet-stream")


@router.post("/engagements/{eid}/findings/{fid}/comments")
async def ui_add_finding_comment(request: Request, eid: int, fid: int, body: str = Form("")):
    detail = f"/engagements/{eid}/findings/{fid}"
    principal, redirect = _require_login(request, detail)
    if redirect:
        return redirect
    from attestra.comments import add_comment, can_add_comment

    if not can_add_comment(principal.role):
        return _back(detail, error="Your role can't add comments.", anchor="#comments")
    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            from attestra.models import Finding

            f = s.get(Finding, fid)
            if not f or f.engagement_id != eid:
                raise LookupError(f"finding F-{fid} is not in this engagement")
            add_comment(s, fid, body=body, principal=principal)
    except (services.ServiceError, LookupError) as e:
        return _back(detail, error=str(e), anchor="#comments")
    return _back(detail, msg="Comment posted.", anchor="#comments")


@router.post("/engagements/{eid}/findings/{fid}/comments/{cid}/delete")
def ui_delete_finding_comment(request: Request, eid: int, fid: int, cid: int):
    detail = f"/engagements/{eid}/findings/{fid}"
    principal, redirect = _require_login(request, detail)
    if redirect:
        return redirect
    from attestra.comments import delete_comment

    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            from attestra.models import Finding

            f = s.get(Finding, fid)
            if not f or f.engagement_id != eid:
                raise LookupError(f"finding F-{fid} is not in this engagement")
            delete_comment(s, fid, cid, principal)
    except (services.ServiceError, LookupError) as e:
        return _back(detail, error=str(e), anchor="#comments")
    return _back(detail, msg="Comment deleted.", anchor="#comments")


@router.post("/engagements/{eid}/findings/{fid}/status")
def change_finding_status(request: Request, eid: int, fid: int, to: str = Form(...), note: str = Form("")):
    detail = f"/engagements/{eid}/findings/{fid}"
    list_url = f"/engagements/{eid}"
    # Prefer returning to the detail page when the form was posted from there.
    referer = request.headers.get("referer") or ""
    url = detail if f"/findings/{fid}" in referer else list_url
    principal, redirect = _require_login(request, url)
    if redirect:
        return redirect
    if not has_permission(principal.role, "finding.write"):
        return _back(url, error="Your role can't change finding status.", anchor="#findings")
    # P0-3: risk acceptance needs owner/expiry/rationale — send the user to that form.
    if to == "risk_accepted":
        from fastapi.responses import RedirectResponse

        return RedirectResponse(
            f"/engagements/{eid}/findings/{fid}?accept_risk=1", status_code=303
        )
    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            from attestra.models import Finding

            f = s.get(Finding, fid)
            if not f or f.engagement_id != eid:
                raise LookupError(f"finding F-{fid} is not in this engagement")
            services.transition(s, fid, to=to, note=note, actor=principal.actor)
    except (services.ServiceError, LookupError) as e:
        return _back(url, error=str(e), anchor=f"#f-{fid}" if url == list_url else "#status")
    return _back(url, msg=f"F-{fid} moved to {label(to).lower()}.",
                 anchor=f"#f-{fid}" if url == list_url else "#status")


@router.post("/engagements/{eid}/findings/{fid}/accept-risk")
def ui_accept_risk(
    request: Request,
    eid: int,
    fid: int,
    expires_on: str = Form(...),
    rationale: str = Form(...),
):
    """P0-3: create RiskAcceptance and move finding to risk_accepted in one step."""
    from datetime import date as date_cls

    url = f"/engagements/{eid}/findings/{fid}"
    principal, redirect = _require_login(request, url)
    if redirect:
        return redirect
    if not has_permission(principal.role, "finding.write"):
        return _back(url, error="Your role can't accept risk.", anchor="#status")
    try:
        exp = date_cls.fromisoformat(expires_on.strip())
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            from attestra.models import Finding

            f = s.get(Finding, fid)
            if not f or f.engagement_id != eid:
                raise LookupError(f"finding F-{fid} is not in this engagement")
            services.accept_risk(
                s,
                fid,
                expires_on=exp,
                rationale=rationale,
                actor=principal.actor,
                owner_user_id=principal.user_id,
            )
    except (services.ServiceError, LookupError, ValueError) as e:
        return _back(url, error=str(e), anchor="#accept-risk")
    return _back(url, msg=f"F-{fid} risk-accepted with record.", anchor="#status")


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
    return _back(
        url,
        msg=f"Report #{rid} generated ({label(kind).lower()}). It is a draft: click Submit for QA in the table, "
        "then a different person must QA it before a lead can sign it.",
        anchor="#reports",
    )


# ---------------------------------------------------------------- report lifecycle: submit, QA, sign

_REPORT_STEP_ERRORS = {
    "four-eyes rule: QA must be a different person from the author": (
        "Someone else must QA this report. You made it, so a different person (a reviewer or another lead) "
        "has to sign in and do the QA."
    ),
    "four-eyes rule: signer must differ from author and QA": (
        "Someone else must sign this report. The signer can't be the person who made it or the person who QA'd it."
    ),
    "only lead or admin may sign a report": "Only a lead or admin can sign a report.",
    "a rejection note is required": "Type a reason before rejecting the report, so the author knows what to fix.",
    "report file changed after generation; regenerate it": (
        "The report file changed after it was made, so it can't go further. Generate a new report."
    ),
}


def _report_step(request: Request, eid: int, rid: int, permission: str, denied: str, ok_msg: str, fn) -> RedirectResponse:
    """Run one report lifecycle step through the reports service; the service enforces status and four-eyes rules."""
    url = f"/engagements/{eid}"
    principal, redirect = _require_login(request, url)
    if redirect:
        return redirect
    if not has_permission(principal.role, permission):
        return _back(url, error=denied, anchor="#reports")
    try:
        with db.session() as s:
            services.get_engagement(s, eid, principal)
            r = s.get(Report, rid)
            if not r or r.engagement_id != eid:
                raise LookupError(f"report #{rid} is not in this engagement")
            fn(s, principal)
    except (services.ServiceError, LookupError, ValueError) as e:
        text = str(e)
        return _back(url, error=_REPORT_STEP_ERRORS.get(text, text), anchor="#reports")
    return _back(url, msg=ok_msg, anchor="#reports")


@router.post("/engagements/{eid}/reports/{rid}/submit")
def ui_submit_report(request: Request, eid: int, rid: int):
    from attestra.reports.render import submit_report

    return _report_step(
        request, eid, rid, "report.submit", "Your role can't submit reports for QA.",
        f"Report #{rid} submitted for QA. A different person must now QA it.",
        lambda s, p: submit_report(s, rid, actor=p.actor, user_id=p.user_id),
    )


@router.post("/engagements/{eid}/reports/{rid}/qa-approve")
def ui_qa_approve_report(request: Request, eid: int, rid: int):
    from attestra.reports.render import qa_approve

    return _report_step(
        request, eid, rid, "report.approve", "Your role can't QA reports.",
        f"Report #{rid} passed QA. A lead who didn't make or QA it can now approve and sign it.",
        lambda s, p: qa_approve(s, rid, actor=p.actor, user_id=p.user_id),
    )


@router.post("/engagements/{eid}/reports/{rid}/qa-reject")
def ui_qa_reject_report(request: Request, eid: int, rid: int, note: str = Form("")):
    from attestra.reports.render import qa_reject

    return _report_step(
        request, eid, rid, "report.approve", "Your role can't QA reports.",
        f"Report #{rid} sent back to the author with your note.",
        lambda s, p: qa_reject(s, rid, actor=p.actor, note=note, user_id=p.user_id),
    )


@router.post("/engagements/{eid}/reports/{rid}/sign")
def ui_sign_report(request: Request, eid: int, rid: int):
    from attestra.reports.render import sign_report

    return _report_step(
        request, eid, rid, "report.sign", "Only a lead or admin can sign a report.",
        f"Report #{rid} approved and signed. Its fingerprint is now sealed with a signature.",
        lambda s, p: sign_report(s, rid, actor=p.actor, user_id=p.user_id, role=p.role),
    )


@router.get("/credits", response_class=HTMLResponse)
def ui_credits_page(request: Request):
    """Organization credit balance and renewal request form."""
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if not has_permission(principal.role, "credits.read"):
        return _back("/", error="Your role cannot view organization credits.")
    from attestra.credits import list_renewal_requests
    from attestra.models import Tenant

    with db.session() as s:
        tenants = []
        if principal.role == "admin":
            tenants = list(s.scalars(select(Tenant).order_by(Tenant.name)))
        elif principal.tenant_id:
            t = s.get(Tenant, principal.tenant_id)
            tenants = [t] if t else []
        tid = principal.tenant_id or (tenants[0].id if tenants else None)
        qtid = request.query_params.get("tenant_id")
        if qtid and qtid.isdigit() and principal.role == "admin":
            tid = int(qtid)
        credits = _org_credits_for(principal, s, tid) if tid else None
        requests = list_renewal_requests(s, tenant_id=tid, status=None) if tid else []
        return _render(
            request,
            "credits.html",
            {
                "tenants": tenants,
                "selected_tenant_id": tid,
                "org_credits": credits,
                "renewal_requests": requests,
                "can_request": has_permission(principal.role, "credits.request"),
                "can_allocate": has_permission(principal.role, "credits.allocate"),
            },
        )


@router.post("/credits/renewal-request")
def ui_credits_renewal_request(
    request: Request,
    tenant_id: int = Form(...),
    credits_requested: int = Form(...),
    note: str = Form(""),
):
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if not has_permission(principal.role, "credits.request"):
        return _back("/credits", error="Your role cannot request additional credits.")
    if principal.role != "admin" and principal.tenant_id != tenant_id:
        return _back("/credits", error="cross-tenant credit access denied")
    from attestra.credits import request_renewal

    try:
        with db.session() as s:
            request_renewal(
                s,
                tenant_id,
                credits_requested=int(credits_requested),
                actor=principal.actor,
                user_id=principal.user_id,
                note=note,
            )
    except (services.ServiceError, ValueError) as e:
        return _back("/credits", error=str(e))
    return _back("/credits", msg="Credit request submitted for Super Admin review.")


@router.post("/credits/allocate")
def ui_credits_allocate(
    request: Request,
    tenant_id: int = Form(...),
    amount: int = Form(...),
    note: str = Form(""),
):
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if not has_permission(principal.role, "credits.allocate"):
        return _back("/credits", error="Only a Super Admin can allocate credits.")
    from attestra.credits import allocate_credits

    try:
        with db.session() as s:
            allocate_credits(
                s,
                tenant_id,
                amount=int(amount),
                actor=principal.actor,
                user_id=principal.user_id,
                note=note,
            )
    except (services.ServiceError, ValueError) as e:
        return _back("/credits", error=str(e))
    return _back(f"/credits?tenant_id={tenant_id}", msg=f"Allocated {amount} credit(s).")


@router.post("/credits/renewal-requests/{rid}/resolve")
def ui_credits_resolve(
    request: Request,
    rid: int,
    approve: str = Form("0"),
    admin_note: str = Form(""),
    allocate_amount: str = Form(""),
):
    principal, redirect = _require_login(request)
    if redirect:
        return redirect
    if not has_permission(principal.role, "credits.allocate"):
        return _back("/credits", error="Only a Super Admin can resolve credit requests.")
    from attestra.credits import resolve_renewal

    amount = int(allocate_amount) if allocate_amount.strip().isdigit() else None
    try:
        with db.session() as s:
            row = resolve_renewal(
                s,
                rid,
                approve=approve in ("1", "true", "yes", "on"),
                actor=principal.actor,
                admin_note=admin_note,
                allocate_amount=amount,
            )
            tid = row.tenant_id
    except (services.ServiceError, LookupError, ValueError) as e:
        return _back("/credits", error=str(e))
    return _back(f"/credits?tenant_id={tid}", msg=f"Renewal request #{rid} updated.")
