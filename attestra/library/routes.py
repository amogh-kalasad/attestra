"""API and UI routes for the findings library and tenant report templates."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

from attestra import db, services
from attestra.auth.keys import Principal
from attestra.auth.roles import has_permission
from attestra.library import service as lib
from attestra.library import templates as rt
from attestra.models import SEVERITIES, Finding, Tenant

PERM_LIBRARY = "finding.write"  # admin, lead, tester
PERM_TEMPLATES = "report.generate"  # admin, lead, tester

api_router = APIRouter(prefix="/api", tags=["library"])
ui_router = APIRouter(include_in_schema=False)


def _require(permission: str):
    from attestra.api import get_principal

    def dep(principal: Principal = Depends(get_principal)) -> Principal:
        if not has_permission(principal.role, permission):
            raise HTTPException(403, f"permission denied: {permission}")
        return principal

    return dep


def resolve_tenant(s, principal, tenant_id: int | None) -> int:
    allowed = services.tenant_ids_for(s, principal)
    if tenant_id is None:
        if principal.tenant_id is not None:
            tenant_id = principal.tenant_id
        elif allowed is not None and len(allowed) == 1:
            tenant_id = next(iter(allowed))
        else:
            raise HTTPException(400, "tenant_id is required")
    if (allowed is not None and tenant_id not in allowed) or s.get(Tenant, tenant_id) is None:
        raise HTTPException(404, "tenant not found")
    return tenant_id


def _run(fn):
    try:
        with db.session() as s:
            return fn(s)
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except services.ServiceError as e:
        raise HTTPException(422, str(e)) from e


def _finding(s, fid: int, principal) -> Finding:
    f = s.get(Finding, fid)
    if f is None:
        raise LookupError(f"finding {fid} not found")
    services.get_engagement(s, f.engagement_id, principal)
    return f


class EntryIn(BaseModel):
    title: str
    description: str = ""
    impact: str = ""
    remediation: str = ""
    references: list[str] = []
    cwe: int | None = None
    default_severity: str = "medium"
    tags: list[str] = []
    rule_ids: list[str] = []
    importance: str = ""
    effort: str = ""
    fix_steps: str = ""
    snippet_nginx: str = ""
    snippet_apache: str = ""
    snippet_iis: str = ""
    snippet_cloudflare: str = ""


class EntryPatch(BaseModel):
    title: str | None = None
    description: str | None = None
    impact: str | None = None
    remediation: str | None = None
    references: list[str] | None = None
    cwe: int | None = None
    default_severity: str | None = None
    tags: list[str] | None = None
    rule_ids: list[str] | None = None
    importance: str | None = None
    effort: str | None = None
    fix_steps: str | None = None
    snippet_nginx: str | None = None
    snippet_apache: str | None = None
    snippet_iis: str | None = None
    snippet_cloudflare: str | None = None


class ApplyIn(BaseModel):
    entry_id: int


class TemplateIn(BaseModel):
    source: str | None = None
    cover_title: str | None = None
    disclaimer: str | None = None
    sections: list[str] | None = None
    enabled: bool | None = None
    clear_logo: bool = False


# ---------------------------------------------------------------- API: library


@api_router.get("/library")
def api_list(q: str = "", tenant_id: int | None = None, principal: Principal = Depends(_require(PERM_LIBRARY))):
    def fn(s):
        tid = resolve_tenant(s, principal, tenant_id)
        return [lib.entry_dict(e) for e in lib.list_entries(s, tid, q)]

    return _run(fn)


@api_router.post("/library", status_code=201)
def api_create(body: EntryIn, tenant_id: int | None = None, principal: Principal = Depends(_require(PERM_LIBRARY))):
    def fn(s):
        tid = resolve_tenant(s, principal, tenant_id)
        return lib.entry_dict(lib.create_entry(s, tid, body.model_dump(), actor=principal.actor))

    return _run(fn)


@api_router.post("/library/seed")
def api_seed(tenant_id: int | None = None, principal: Principal = Depends(_require(PERM_LIBRARY))):
    def fn(s):
        tid = resolve_tenant(s, principal, tenant_id)
        return {"added": lib.seed_defaults(s, tid, actor=principal.actor)}

    return _run(fn)


@api_router.post("/library/import")
async def api_import(
    file: UploadFile = File(...),
    fmt: str | None = Form(None),
    tenant_id: int | None = None,
    principal: Principal = Depends(_require(PERM_LIBRARY)),
):
    """Import onboarding writeups from a JSON or CSV template."""
    data = await file.read()
    name = (file.filename or "").lower()
    kind = (fmt or "").strip().lower() or None
    if not kind:
        if name.endswith(".json"):
            kind = "json"
        elif name.endswith(".csv"):
            kind = "csv"

    def fn(s):
        tid = resolve_tenant(s, principal, tenant_id)
        return lib.import_template_entries(s, tid, data, fmt=kind, actor=principal.actor)

    return _run(fn)


@api_router.get("/library/{entry_id}")
def api_get(entry_id: int, principal: Principal = Depends(_require(PERM_LIBRARY))):
    return _run(lambda s: lib.entry_dict(lib.get_entry(s, entry_id, services.tenant_ids_for(s, principal))))


@api_router.put("/library/{entry_id}")
def api_update(entry_id: int, body: EntryPatch, principal: Principal = Depends(_require(PERM_LIBRARY))):
    def fn(s):
        e = lib.get_entry(s, entry_id, services.tenant_ids_for(s, principal))
        return lib.entry_dict(lib.update_entry(s, e, body.model_dump(exclude_unset=True), actor=principal.actor))

    return _run(fn)


@api_router.delete("/library/{entry_id}", status_code=204)
def api_delete(entry_id: int, principal: Principal = Depends(_require(PERM_LIBRARY))):
    def fn(s):
        lib.delete_entry(s, lib.get_entry(s, entry_id, services.tenant_ids_for(s, principal)), actor=principal.actor)

    _run(fn)


@api_router.get("/findings/{fid}/library-suggestions")
def api_suggest(fid: int, principal: Principal = Depends(_require(PERM_LIBRARY))):
    return _run(lambda s: [lib.entry_dict(e) for e in lib.suggest(s, _finding(s, fid, principal))])


@api_router.get("/engagements/{eid}/library-suggestions")
def api_suggest_engagement(eid: int, principal: Principal = Depends(_require(PERM_LIBRARY))):
    def fn(s):
        services.get_engagement(s, eid, principal)
        return {str(fid): [{"id": e.id, "title": e.title} for e in hits]
                for fid, hits in lib.suggestions_for_engagement(s, eid).items()}

    return _run(fn)


@api_router.post("/findings/{fid}/apply-library")
def api_apply(fid: int, body: ApplyIn, principal: Principal = Depends(_require(PERM_LIBRARY))):
    def fn(s):
        f = _finding(s, fid, principal)
        e = lib.get_entry(s, body.entry_id, services.tenant_ids_for(s, principal))
        return {"finding_id": f.id, "entry_id": e.id, "filled": lib.apply_to_finding(s, f, e, actor=principal.actor)}

    return _run(fn)


# ---------------------------------------------------------------- API: report templates


@api_router.get("/report-templates")
def api_templates(tenant_id: int | None = None, principal: Principal = Depends(_require(PERM_TEMPLATES))):
    def fn(s):
        tid = resolve_tenant(s, principal, tenant_id)
        return {"sections": list(rt.SECTIONS), "default_source": rt.DEFAULT_SOURCE,
                "templates": [rt.template_dict(t) for t in rt.list_templates(s, tid)]}

    return _run(fn)


@api_router.put("/report-templates/{kind}")
def api_template_save(kind: str, body: TemplateIn, tenant_id: int | None = None,
                      principal: Principal = Depends(_require(PERM_TEMPLATES))):
    def fn(s):
        tid = resolve_tenant(s, principal, tenant_id)
        return rt.template_dict(rt.save_template(s, tid, kind, actor=principal.actor, **body.model_dump()))

    return _run(fn)


@api_router.post("/report-templates/{kind}/upload")
async def api_template_upload(kind: str, tenant_id: int | None = None, source: UploadFile | None = File(None),
                              logo: UploadFile | None = File(None),
                              principal: Principal = Depends(_require(PERM_TEMPLATES))):
    src = (await source.read()).decode("utf-8", errors="replace") if source else None
    logo_bytes = await logo.read() if logo else None

    def fn(s):
        tid = resolve_tenant(s, principal, tenant_id)
        return rt.template_dict(rt.save_template(s, tid, kind, actor=principal.actor, source=src, logo=logo_bytes))

    return _run(fn)


@api_router.delete("/report-templates/{kind}", status_code=204)
def api_template_delete(kind: str, tenant_id: int | None = None, principal: Principal = Depends(_require(PERM_TEMPLATES))):
    def fn(s):
        rt.delete_template(s, resolve_tenant(s, principal, tenant_id), kind, actor=principal.actor)

    _run(fn)


# ---------------------------------------------------------------- UI


def _ui_ctx(request: Request):
    from attestra.web import ui

    principal = ui._principal(request)
    if principal is None:
        return None, None, ui._back("/login", error="Sign in to continue.")
    if principal.role in ui.READ_ONLY_ROLES or not has_permission(principal.role, PERM_LIBRARY):
        return None, None, RedirectResponse("/portal", status_code=303)
    return ui, principal, None


def _ui_tenants(s, principal) -> list[Tenant]:
    allowed = services.tenant_ids_for(s, principal)
    rows = s.query(Tenant).order_by(Tenant.name).all()
    return [t for t in rows if allowed is None or t.id in allowed]


def _ui_tenant(s, principal, tenant_id: int | None) -> int | None:
    tenants = _ui_tenants(s, principal)
    if tenant_id is None:
        if principal.tenant_id is not None:
            return principal.tenant_id
        return tenants[0].id if tenants else None
    return tenant_id if any(t.id == tenant_id for t in tenants) else None


def _form_entry(title, description, impact, remediation, references, cwe, default_severity, tags, rule_ids,
                importance="", effort="", fix_steps="", snippet_nginx="", snippet_apache="",
                snippet_iis="", snippet_cloudflare="") -> dict:
    return {"title": title, "description": description, "impact": impact, "remediation": remediation,
            "references": references, "cwe": cwe or None, "default_severity": default_severity,
            "tags": tags, "rule_ids": rule_ids, "importance": importance, "effort": effort,
            "fix_steps": fix_steps, "snippet_nginx": snippet_nginx, "snippet_apache": snippet_apache,
            "snippet_iis": snippet_iis, "snippet_cloudflare": snippet_cloudflare}


@ui_router.get("/library", response_class=HTMLResponse)
def ui_library(request: Request, q: str = "", tenant_id: int | None = Query(None)):
    ui, principal, redirect = _ui_ctx(request)
    if redirect:
        return redirect
    with db.session() as s:
        tid = _ui_tenant(s, principal, tenant_id)
        entries = lib.list_entries(s, tid, q) if tid else []
        return ui._render(request, "library_index.html", {
            "entries": entries, "q": q, "tenant_id": tid, "tenants": _ui_tenants(s, principal), "severities": SEVERITIES,
        })


@ui_router.post("/library")
def ui_create(request: Request, tenant_id: int = Form(...), title: str = Form(...), description: str = Form(""),
              impact: str = Form(""), remediation: str = Form(""), references: str = Form(""), cwe: str = Form(""),
              default_severity: str = Form("medium"), tags: str = Form(""), rule_ids: str = Form(""),
              importance: str = Form(""), effort: str = Form(""), fix_steps: str = Form(""),
              snippet_nginx: str = Form(""), snippet_apache: str = Form(""), snippet_iis: str = Form(""),
              snippet_cloudflare: str = Form("")):
    ui, principal, redirect = _ui_ctx(request)
    if redirect:
        return redirect
    url = f"/library?tenant_id={tenant_id}"
    try:
        with db.session() as s:
            if _ui_tenant(s, principal, tenant_id) is None:
                raise LookupError("tenant not found")
            e = lib.create_entry(
                s, tenant_id,
                _form_entry(
                    title, description, impact, remediation, references, cwe, default_severity, tags, rule_ids,
                    importance, effort, fix_steps, snippet_nginx, snippet_apache, snippet_iis, snippet_cloudflare,
                ),
                actor=principal.actor,
            )
            eid = e.id
    except (services.ServiceError, LookupError) as e:
        return ui._back("/library", error=str(e))
    return ui._back(f"/library/{eid}", msg="Writeup created.") if eid else ui._back(url)


@ui_router.post("/library/seed")
def ui_seed(request: Request, tenant_id: int = Form(...)):
    ui, principal, redirect = _ui_ctx(request)
    if redirect:
        return redirect
    with db.session() as s:
        if _ui_tenant(s, principal, tenant_id) is None:
            return ui._back("/library", error="tenant not found")
        n = lib.seed_defaults(s, tenant_id, actor=principal.actor)
    return RedirectResponse(f"/library?tenant_id={tenant_id}&msg={n}%20starter%20writeups%20added.", status_code=303)


@ui_router.get("/library/templates", response_class=HTMLResponse)
def ui_templates(request: Request, tenant_id: int | None = Query(None), kind: str = "*"):
    ui, principal, redirect = _ui_ctx(request)
    if redirect:
        return redirect
    from attestra.reports.render import KINDS

    with db.session() as s:
        tid = _ui_tenant(s, principal, tenant_id)
        current = rt.get_template(s, tid, kind) if tid else None
        return ui._render(request, "library_templates.html", {
            "tenant_id": tid, "tenants": _ui_tenants(s, principal), "kinds": ("*", *KINDS), "kind": kind,
            "t": current, "templates": rt.list_templates(s, tid) if tid else [], "sections": rt.SECTIONS,
            "default_source": rt.DEFAULT_SOURCE,
        })


@ui_router.post("/library/templates")
async def ui_template_save(request: Request, tenant_id: int = Form(...), kind: str = Form(...), source: str = Form(""),
                           cover_title: str = Form(""), disclaimer: str = Form(""), sections: str = Form(""),
                           enabled: str = Form(""), clear_logo: str = Form(""), action: str = Form("save"),
                           logo: UploadFile | None = File(None), upload: UploadFile | None = File(None)):
    ui, principal, redirect = _ui_ctx(request)
    if redirect:
        return redirect
    url = f"/library/templates?tenant_id={tenant_id}&kind={kind}"
    logo_bytes = await logo.read() if logo and logo.filename else None
    if upload and upload.filename:
        source = (await upload.read()).decode("utf-8", errors="replace")
    try:
        with db.session() as s:
            if _ui_tenant(s, principal, tenant_id) is None:
                raise LookupError("tenant not found")
            if action == "delete":
                rt.delete_template(s, tenant_id, kind, actor=principal.actor)
            else:
                rt.save_template(
                    s, tenant_id, kind, actor=principal.actor, source=source, cover_title=cover_title,
                    disclaimer=disclaimer, sections=sections, enabled=bool(enabled), logo=logo_bytes,
                    clear_logo=bool(clear_logo),
                )
    except (services.ServiceError, LookupError) as e:
        return RedirectResponse(f"{url}&error={_q(str(e))}", status_code=303)
    return RedirectResponse(f"{url}&msg={_q('Template removed.' if action == 'delete' else 'Template saved.')}", status_code=303)


def _q(text: str) -> str:
    from urllib.parse import quote

    return quote(text)


@ui_router.get("/library/{entry_id}", response_class=HTMLResponse)
def ui_entry(request: Request, entry_id: int):
    ui, principal, redirect = _ui_ctx(request)
    if redirect:
        return redirect
    try:
        with db.session() as s:
            e = lib.get_entry(s, entry_id, services.tenant_ids_for(s, principal))
            from attestra.models import Engagement

            recent = (
                s.query(Finding).join(Engagement, Finding.engagement_id == Engagement.id)
                .filter(Engagement.tenant_id == e.tenant_id).order_by(Finding.id.desc()).limit(200).all()
            )
            return ui._render(request, "library_edit.html", {"e": e, "severities": SEVERITIES, "recent_findings": recent})
    except LookupError:
        return ui._back("/library", error="Writeup not found.")


@ui_router.post("/library/{entry_id}")
def ui_update(request: Request, entry_id: int, title: str = Form(...), description: str = Form(""),
              impact: str = Form(""), remediation: str = Form(""), references: str = Form(""), cwe: str = Form(""),
              default_severity: str = Form("medium"), tags: str = Form(""), rule_ids: str = Form(""),
              importance: str = Form(""), effort: str = Form(""), fix_steps: str = Form(""),
              snippet_nginx: str = Form(""), snippet_apache: str = Form(""), snippet_iis: str = Form(""),
              snippet_cloudflare: str = Form(""), action: str = Form("save")):
    ui, principal, redirect = _ui_ctx(request)
    if redirect:
        return redirect
    try:
        with db.session() as s:
            e = lib.get_entry(s, entry_id, services.tenant_ids_for(s, principal))
            if action == "delete":
                tid = e.tenant_id
                lib.delete_entry(s, e, actor=principal.actor)
                return RedirectResponse(f"/library?tenant_id={tid}&msg=Writeup%20deleted.", status_code=303)
            lib.update_entry(
                s, e,
                _form_entry(
                    title, description, impact, remediation, references, cwe, default_severity, tags, rule_ids,
                    importance, effort, fix_steps, snippet_nginx, snippet_apache, snippet_iis, snippet_cloudflare,
                ),
                actor=principal.actor,
            )
    except (services.ServiceError, LookupError) as e:
        return ui._back(f"/library/{entry_id}", error=str(e))
    return ui._back(f"/library/{entry_id}", msg="Saved.")


@ui_router.post("/library/{entry_id}/apply")
def ui_apply(request: Request, entry_id: int, finding_id: int = Form(...)):
    ui, principal, redirect = _ui_ctx(request)
    if redirect:
        return redirect
    try:
        with db.session() as s:
            e = lib.get_entry(s, entry_id, services.tenant_ids_for(s, principal))
            filled = lib.apply_to_finding(s, _finding(s, finding_id, principal), e, actor=principal.actor)
    except (services.ServiceError, LookupError) as e:
        return ui._back(f"/library/{entry_id}", error=str(e))
    msg = f"Filled {', '.join(filled)} on finding {finding_id}." if filled else "Nothing to fill; the tester's text was kept."
    return ui._back(f"/library/{entry_id}", msg=msg)
