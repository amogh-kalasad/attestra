"""Tenant report templates rendered in a Jinja sandbox, with built-in fallback.

A tenant may store, per report kind (or ``*`` for technical and executive
reports), its own Jinja source, a cover title, a logo and a section order. The
source runs in ``jinja2.sandbox.SandboxedEnvironment`` against a plain-data
context (no ORM objects, no session). If anything fails, the caller falls back
to the built-in template.
"""

from __future__ import annotations

import base64
import logging

from jinja2 import DictLoader, TemplateError
from jinja2.sandbox import ImmutableSandboxedEnvironment
from markupsafe import Markup
from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, services
from attestra.models import ReportTemplate, utcnow

log = logging.getLogger(__name__)

SECTIONS = ("cover", "summary", "findings", "compliance", "scope", "appendix")
WILDCARD_KINDS = ("technical", "executive")
MAX_SOURCE = 200_000
MAX_LOGO = 512_000
_LOGO_TYPES = {b"\x89PNG\r\n\x1a\n": "image/png", b"\xff\xd8\xff": "image/jpeg", b"GIF87a": "image/gif", b"GIF89a": "image/gif"}

DEFAULT_SOURCE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{{ cover_title or eng.name }}</title>
<style>
body{font:14px/1.5 -apple-system,"Segoe UI",Roboto,sans-serif;color:#16181d;max-width:900px;margin:0 auto;padding:24px}
.cover{min-height:60vh;display:flex;flex-direction:column;justify-content:center;border-bottom:2px solid #2457d6;margin-bottom:32px}
.cover img{max-height:90px;max-width:260px;margin-bottom:24px}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #e3e5ea;padding:6px;text-align:left;vertical-align:top}
.sev{font-weight:700;text-transform:capitalize}.f{page-break-inside:avoid;margin-bottom:20px}
</style></head><body>
{% for section in sections %}
{% if section == "cover" %}
<section class="cover">
{% if logo %}<img src="{{ logo }}" alt="logo">{% endif %}
<h1>{{ cover_title or (kind|title ~ " report") }}</h1>
<p>{{ tenant }} &middot; {{ eng.name }}</p>
<p>Version {{ version }} &middot; generated {{ generated_at }} by {{ generated_by }}</p>
</section>
{% elif section == "summary" %}
<section><h2>Summary</h2>
<p>{{ open_count }} open findings ({{ open_critical_high }} critical or high).</p>
<table><tr>{% for s in severities %}<th>{{ s|title }}</th>{% endfor %}</tr>
<tr>{% for s in severities %}<td>{{ by_sev.get(s, 0) }}</td>{% endfor %}</tr></table>
</section>
{% elif section == "findings" %}
<section><h2>Findings</h2>
{% for f in findings %}
<div class="f"><h3>{{ loop.index }}. {{ f.title }} <span class="sev">({{ f.severity }})</span></h3>
<p><b>Status:</b> {{ f.status }}{% if f.cwe %} &middot; CWE-{{ f.cwe }}{% endif %}{% if f.location %} &middot; {{ f.location }}{% endif %}</p>
{% if f.description %}<p>{{ f.description }}</p>{% endif %}
{% if f.recommendation %}<p><b>Recommendation:</b> {{ f.recommendation }}</p>{% endif %}
{% if f.importance or f.effort %}<p>Importance: {{ f.importance or "—" }} · Effort: {{ f.effort or "—" }}</p>{% endif %}
{% if f.fix_steps %}<p style="white-space:pre-wrap">{{ f.fix_steps }}</p>{% endif %}
{% for name, text in (f.report_snippets or []) %}<p><b>{{ name }} config.</b></p><pre>{{ text }}</pre>{% endfor %}
</div>
{% else %}<p>No findings.</p>{% endfor %}
</section>
{% elif section == "compliance" and frameworks %}
<section><h2>Compliance</h2><table><tr><th>Framework</th><th>Status counts</th></tr>
{% for key, fw in frameworks.items() %}<tr><td>{{ fw.name }}</td><td>{% for st, n in fw.counts.items() %}{{ st }}: {{ n }} {% endfor %}</td></tr>{% endfor %}
</table></section>
{% elif section == "scope" %}
<section><h2>Scope and sources</h2><ul>{% for i in imports %}<li>{{ i.tool }}: {{ i.filename }}</li>{% endfor %}</ul></section>
{% elif section == "appendix" %}
<section id="appendix"><h2>Appendix</h2>
<p class="meta">Tool imports that contributed evidence.</p>
<table><tr><th>Tool</th><th>File</th><th>SHA-256</th></tr>
{% for i in imports %}<tr><td>{{ i.tool }}</td><td>{{ i.filename }}</td><td class="mono">{{ i.sha256 }}</td></tr>
{% else %}<tr><td colspan="3">No results imported.</td></tr>{% endfor %}
</table>
<p>Attestra {{ version_str }}.</p></section>
{% endif %}
{% endfor %}
{% if disclaimer %}<section id="disclaimer"><h2>Assumptions, limitations and confidentiality</h2><p>{{ disclaimer }}</p></section>{% endif %}
</body></html>
"""


class TemplateErrorOut(services.ServiceError):
    pass


def _env() -> ImmutableSandboxedEnvironment:
    return ImmutableSandboxedEnvironment(
        loader=DictLoader({}), autoescape=True, trim_blocks=True, lstrip_blocks=True
    )


def logo_data_uri(data: bytes) -> str:
    if len(data) > MAX_LOGO:
        raise TemplateErrorOut("logo is larger than 500 KB")
    for magic, mime in _LOGO_TYPES.items():
        if data.startswith(magic):
            return f"data:{mime};base64," + base64.b64encode(data).decode("ascii")
    raise TemplateErrorOut("logo must be PNG, JPEG or GIF")


def clean_sections(sections) -> list[str]:
    if isinstance(sections, str):
        sections = sections.replace("\n", ",").split(",")
    out = []
    for sec in sections or []:
        sec = str(sec).strip().lower()
        if not sec:
            continue
        if sec not in SECTIONS:
            raise TemplateErrorOut(f"unknown section '{sec}'; use {', '.join(SECTIONS)}")
        if sec not in out:
            out.append(sec)
    return out or list(SECTIONS)


def safe_context(ctx: dict) -> dict:
    """Project the report context to plain data only."""
    eng = ctx["eng"]
    fix_by_id = ctx.get("fix_by_id") or {}
    report_snips = ctx.get("report_snippets_by_id") or {}
    findings = []
    for f in ctx.get("findings", []):
        fix = fix_by_id.get(f.id) or {}
        findings.append({
            "id": f.id, "title": f.title, "severity": f.severity, "status": f.status, "cwe": f.cwe,
            "description": f.description, "recommendation": f.recommendation, "location": f.location,
            "risk_score": f.risk_score, "cvss_score": f.cvss_score, "cves": list(f.cves or []),
            "owasp_top10": f.owasp_top10,
            "importance": fix.get("importance", ""),
            "effort": fix.get("effort", ""),
            "fix_steps": fix.get("fix_steps", ""),
            "report_snippets": list(report_snips.get(f.id) or []),
        })
    return {
        "eng": {"id": eng.id, "name": eng.name, "type": eng.type},
        "tenant": ctx.get("tenant", ""),
        "type_label": ctx.get("type_label", eng.type),
        "findings": findings,
        "open_count": len(ctx.get("open_findings", [])),
        "open_critical_high": ctx.get("open_critical_high", 0),
        "by_sev": dict(ctx.get("by_sev", {})),
        "severities": list(ctx.get("severities", ())),
        "frameworks": {k: {"name": v["name"], "counts": dict(v["counts"])} for k, v in ctx.get("frameworks", {}).items()},
        "imports": [{"tool": i.tool, "filename": i.filename} for i in ctx.get("imports", [])],
        "today": str(ctx.get("today", "")),
        "version_str": ctx.get("version_str", ""),
        "kind": ctx.get("kind", ""),
        "version": ctx.get("version", 1),
        "generated_by": ctx.get("generated_by", ""),
        "generated_at": str(ctx.get("generated_at", "")),
        "trend_svg": Markup(ctx.get("trend_svg", "")),
    }


SAMPLE = {
    "eng": {"id": 0, "name": "Sample engagement", "type": "vapt"}, "tenant": "Sample tenant",
    "findings": [{"id": 1, "title": "Sample finding", "severity": "high", "status": "validated", "cwe": 79,
                  "description": "Text", "recommendation": "Fix", "location": "https://example.test/",
                  "risk_score": 1.0, "cvss_score": 7.1, "cves": [], "owasp_top10": "A03",
                  "importance": "", "effort": "", "fix_steps": "", "report_snippets": []}],
    "open_count": 1, "open_critical_high": 1, "by_sev": {"high": 1},
    "severities": ["critical", "high", "medium", "low", "info"], "frameworks": {}, "imports": [],
    "today": "", "version_str": "", "kind": "technical", "version": 1, "generated_by": "", "generated_at": "",
    "trend_svg": "",
}


def render_source(source: str, data: dict) -> str:
    return _env().from_string(source or DEFAULT_SOURCE).render(**data)


def _validate_source(source: str, cover_title: str, logo: str, sections: list[str]) -> None:
    if len(source) > MAX_SOURCE:
        raise TemplateErrorOut("template is larger than 200 KB")
    try:
        render_source(source, {**SAMPLE, "cover_title": cover_title, "logo": logo, "sections": sections})
    except TemplateError as e:
        raise TemplateErrorOut(f"template error: {e}") from e
    except Exception as e:  # sandbox SecurityError is a TemplateError; anything else is still invalid
        raise TemplateErrorOut(f"template error: {e}") from e


def get_template(s: Session, tenant_id: int, kind: str) -> ReportTemplate | None:
    return s.scalars(select(ReportTemplate).where(ReportTemplate.tenant_id == tenant_id, ReportTemplate.kind == kind)).first()


def list_templates(s: Session, tenant_id: int) -> list[ReportTemplate]:
    return list(s.scalars(select(ReportTemplate).where(ReportTemplate.tenant_id == tenant_id).order_by(ReportTemplate.kind)))


def template_dict(t: ReportTemplate) -> dict:
    return {"id": t.id, "tenant_id": t.tenant_id, "kind": t.kind, "source": t.source, "cover_title": t.cover_title,
            "disclaimer": t.disclaimer or "", "has_logo": bool(t.logo), "sections": list(t.sections or []),
            "enabled": t.enabled, "updated_by": t.updated_by, "updated_at": t.updated_at}


def _check_kind(kind: str) -> str:
    from attestra.reports.render import KINDS

    if kind != "*" and kind not in KINDS:
        raise TemplateErrorOut(f"kind must be '*' or one of {KINDS}")
    return kind


def save_template(
    s: Session, tenant_id: int, kind: str, *, actor: str, source: str | None = None, cover_title: str | None = None,
    disclaimer: str | None = None, sections=None, enabled: bool | None = None, logo: bytes | None = None,
    clear_logo: bool = False,
) -> ReportTemplate:
    _check_kind(kind)
    t = get_template(s, tenant_id, kind)
    if t is None:
        t = ReportTemplate(
            tenant_id=tenant_id, kind=kind, source="", cover_title="", disclaimer="", logo="",
            sections=list(SECTIONS), enabled=True,
        )
        s.add(t)
    if source is not None:
        t.source = source.replace("\r\n", "\n").strip()
    if cover_title is not None:
        t.cover_title = cover_title.strip()[:300]
    if disclaimer is not None:
        t.disclaimer = disclaimer.replace("\r\n", "\n").strip()
    if sections is not None:
        t.sections = clean_sections(sections)
    if enabled is not None:
        t.enabled = bool(enabled)
    if logo:
        t.logo = logo_data_uri(logo)
    elif clear_logo:
        t.logo = ""
    _validate_source(t.source, t.cover_title, t.logo, list(t.sections or SECTIONS))
    t.updated_by, t.updated_at = actor, utcnow()
    s.flush()
    audit.record(s, actor, "report_template.save", "report_template", t.id, kind=kind, enabled=t.enabled)
    return t


def delete_template(s: Session, tenant_id: int, kind: str, *, actor: str) -> None:
    t = get_template(s, tenant_id, kind)
    if t is None:
        raise LookupError(f"no template for '{kind}'")
    audit.record(s, actor, "report_template.delete", "report_template", t.id, kind=kind)
    s.delete(t)


def _pick(s: Session, tenant_id: int | None, kind: str) -> ReportTemplate | None:
    if tenant_id is None:
        return None
    t = get_template(s, tenant_id, kind)
    if t is None and kind in WILDCARD_KINDS:
        t = get_template(s, tenant_id, "*")
    return t if t is not None and t.enabled else None


def render_custom(s: Session, tenant_id: int | None, kind: str, ctx: dict) -> str | None:
    """Return HTML from the tenant's Jinja source, or ``None`` to use the built-in kind template.

    Empty ``source`` keeps the built-in layout so cover title, logo and disclaimer from the
    same ReportTemplate still apply via branding context.
    """
    t = _pick(s, tenant_id, kind)
    if t is None or not (t.source or "").strip():
        return None
    data = {
        **safe_context(ctx),
        "cover_title": t.cover_title,
        "logo": t.logo,
        "sections": list(t.sections or SECTIONS),
        "disclaimer": ctx.get("disclaimer", ""),
    }
    try:
        return render_source(t.source, data)
    except Exception as e:  # never block a report: fall back to the built-in template
        log.warning("tenant report template %s failed, using built-in: %s", t.id, e)
        return None
