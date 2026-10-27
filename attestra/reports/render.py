"""Render reports from finding and control data, then freeze them by hash and signature."""
# @lat: [[reports]]
# @lat: [[reports#Template configuration]]

from __future__ import annotations

import base64
import hashlib
import mimetypes
from collections import Counter
from datetime import date
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from attestra import __version__, audit, config, services
from attestra.compliance import load_library, objectives_for
from attestra.dedup import detected_by_label
from attestra.models import (
    DISPLAY_LABELS,
    OPEN_STATUSES,
    SEVERITIES,
    TEST_TYPES,
    Engagement,
    ImportRun,
    Report,
    Retest,
    ScanRun,
    engagement_type_label,
    utcnow,
)
from attestra.reports import signing
from attestra.reports.template_config import (
    cvss_legend,
    disclaimer_text,
    kind_config,
    load_template_config,
    methodology_phases,
)

KINDS = (
    "technical",
    "executive",
    "compliance",
    "iso_soa",
    "ageing",
    "closure_letter",
    "attestation_letter",
    "retest",
    "owasp_top10",
)
_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _trend_svg(current: Counter, previous: Counter | None) -> str:
    """Inline SVG bar chart comparing open findings by severity (shared with C11 target history)."""
    from attestra.history import trend_svg

    return trend_svg(current, previous)


def _previous_open_by_sev(s: Session, eng: Engagement) -> Counter | None:
    prev = s.scalars(
        select(Engagement)
        .where(Engagement.tenant_id == eng.tenant_id, Engagement.id < eng.id)
        .order_by(Engagement.id.desc())
        .limit(1)
    ).first()
    if not prev:
        return None
    findings = services.list_findings(s, prev.id)
    open_f = [f for f in findings if f.status in OPEN_STATUSES]
    return Counter(f.severity for f in open_f)


_HISTORY_CHANGE = {
    "draft": "Draft generated",
    "submitted": "Submitted for QA",
    "qa_approved": "QA approved",
    "signed": "Signed",
    "rejected": "Rejected to draft",
}


def report_change_label(status: str) -> str:
    """Human-readable change column for document-control history rows."""
    return _HISTORY_CHANGE.get(status, (status or "").replace("_", " ").title() or "—")


def _report_history(s: Session, engagement_id: int, kind: str = "", framework: str = "") -> list[dict]:
    """Prior report rows for document-control tables (newest first, capped)."""
    q = select(Report).where(Report.engagement_id == engagement_id)
    if kind:
        q = q.where(Report.kind == kind)
    if framework:
        q = q.where(Report.framework == framework)
    rows = list(s.scalars(q.order_by(Report.id.desc()).limit(20)))
    return [
        {
            "id": r.id,
            "version": r.version,
            "status": r.status,
            "change": report_change_label(r.status),
            "generated_at": r.generated_at,
            "generated_by": r.generated_by,
            "qa_by": r.qa_by,
            "approved_by": r.approved_by,
            "sha256": r.sha256,
        }
        for r in rows
    ]


def _assert_not_before_window(eng: Engagement) -> None:
    """Refuse report generate/submit/sign when today is before the test window start."""
    if eng.window_start is not None and date.today() < eng.window_start:
        raise services.ServiceError(
            f"report date is before the test window start ({eng.window_start.isoformat()}); "
            "wait until the engagement window opens"
        )


def _distribution_list(eng: Engagement) -> list[dict]:
    """Default distribution rows for front matter (client contact + confidentiality note)."""
    rows: list[dict] = []
    name = (eng.tenant.contact_name or "").strip()
    email = (eng.tenant.contact_email or "").strip()
    if name or email:
        rows.append(
            {
                "role": "Client contact",
                "name": name or "—",
                "email": email or "—",
                "copies": "1",
            }
        )
    rows.append(
        {
            "role": "Authorized recipients",
            "name": eng.tenant.name,
            "email": "—",
            "copies": "as authorized",
        }
    )
    return rows


def _test_types_and_standards(eng: Engagement) -> tuple[list[dict], list[str]]:
    """Unique authorized test types and standards across engagement assets."""
    seen: dict[str, dict] = {}
    standards: list[str] = []
    for asset in eng.assets or []:
        for key in asset.test_types or []:
            meta = TEST_TYPES.get(key)
            if not meta or key in seen:
                continue
            seen[key] = {"key": key, "label": meta["label"], "standard": meta.get("standard", "")}
            std = meta.get("standard") or ""
            if std and std not in standards:
                standards.append(std)
    return list(seen.values()), standards


def _retests_for_engagement(s: Session, engagement_id: int, findings: list) -> dict[int, list[Retest]]:
    ids = [f.id for f in findings]
    if not ids:
        return {}
    rows = list(
        s.scalars(select(Retest).where(Retest.finding_id.in_(ids)).order_by(Retest.id.desc()))
    )
    out: dict[int, list[Retest]] = {}
    for row in rows:
        out.setdefault(row.finding_id, []).append(row)
    return out


def _latest_retest(retests_by_finding: dict[int, list[Retest]], finding_id: int) -> Retest | None:
    rows = retests_by_finding.get(finding_id) or []
    return rows[0] if rows else None


def _evidence_source_label(e) -> str:
    from attestra.dedup import tool_display_name

    tool = getattr(e, "source_tool", "") or ""
    return tool_display_name(tool) if tool else ""


def _screenshot_caption(e) -> str:
    """Human caption with role and source attribution for report figures."""
    base = (e.note or "").strip() or e.filename or "screenshot"
    # Strip machine redaction markers from captions.
    lines = [ln for ln in base.splitlines() if not ln.strip().startswith("redaction_status=")]
    base = " ".join(lines).strip() or e.filename or "screenshot"
    role = getattr(e, "role", None) or "original"
    parts = [base]
    if role == "annotated":
        parts.append("annotated derivative")
    src = _evidence_source_label(e)
    if src:
        parts.append(f"source: {src}")
    return " · ".join(parts)


def _evidence_embeds(findings: list) -> dict[int, list[dict]]:
    """Embed screenshot evidence as data URIs when the file is present and hash-matches.

    Prefers annotated derivatives over their originals to avoid repeating the same
    capture. Capture-failure rows are never embedded as images.
    """
    out: dict[int, list[dict]] = {}
    for f in findings:
        screenshots = [
            e
            for e in (f.evidence or [])
            if e.kind == "screenshot" and (getattr(e, "capture_status", None) or "success") == "success"
        ]
        parents_with_annotated = {
            e.parent_evidence_id
            for e in screenshots
            if (getattr(e, "role", None) or "") == "annotated" and e.parent_evidence_id
        }
        embeds: list[dict] = []
        for e in screenshots:
            if e.id in parents_with_annotated:
                # Original has an annotated derivative — show the derivative only.
                continue
            path = Path(e.path)
            role = getattr(e, "role", None) or "original"
            meta = {
                "id": e.id,
                "filename": e.filename,
                "sha256": e.sha256,
                "note": e.note or "",
                "caption": _screenshot_caption(e),
                "role": role,
                "source_tool": getattr(e, "source_tool", "") or "",
                "source_tool_label": _evidence_source_label(e),
                "parent_evidence_id": getattr(e, "parent_evidence_id", None),
                "redaction_status": getattr(e, "redaction_status", "") or "",
                "data_uri": "",
                "missing": True,
            }
            if not path.is_file():
                embeds.append(meta)
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if hashlib.sha256(data).hexdigest() != e.sha256:
                continue
            mime = mimetypes.guess_type(e.filename)[0] or "image/png"
            if not mime.startswith("image/"):
                mime = "image/png"
            meta["data_uri"] = f"data:{mime};base64," + base64.b64encode(data).decode("ascii")
            meta["missing"] = False
            embeds.append(meta)
        if embeds:
            out[f.id] = embeds
    return out


def _evidence_limitations(findings: list) -> dict[int, list[str]]:
    """Per-finding capture-failure / limitation notes for report honesty."""
    out: dict[int, list[str]] = {}
    for f in findings:
        notes: list[str] = []
        for e in f.evidence or []:
            if e.kind == "capture_failure" or (getattr(e, "capture_status", None) or "") in ("failed", "unavailable"):
                reason = (getattr(e, "capture_failure_reason", None) or e.note or "Screenshot capture did not succeed").strip()
                src = _evidence_source_label(e)
                notes.append(f"{reason}" + (f" (source: {src})" if src else ""))
        if notes:
            out[f.id] = notes
    return out


def _observations_by_finding(s: Session, findings: list) -> dict[int, list]:
    """Scanner observations for report attribution (canonical findings only once)."""
    from attestra.models import FindingObservation

    ids = [f.id for f in findings]
    if not ids:
        return {}
    rows = list(
        s.scalars(
            select(FindingObservation)
            .where(FindingObservation.finding_id.in_(ids))
            .order_by(FindingObservation.id)
        )
    )
    out: dict[int, list] = {}
    for o in rows:
        out.setdefault(o.finding_id, []).append(o)
    return out


_HTTP_BODY_CAP = 4096


def _figures_list(evidence_embeds: dict[int, list[dict]]) -> list[dict]:
    """List-of-figures rows from screenshot embeds (caption + finding id)."""
    figures: list[dict] = []
    for fid, embeds in evidence_embeds.items():
        for i, e in enumerate(embeds, 1):
            figures.append(
                {
                    "id": f"F-{fid}-{i}",
                    "caption": e.get("caption") or e.get("note") or e.get("filename") or "screenshot",
                    "finding_id": fid,
                    "role": e.get("role") or "original",
                    "source_tool_label": e.get("source_tool_label") or "",
                }
            )
    return figures


def _trim_http_body(text: str, cap: int = _HTTP_BODY_CAP) -> str:
    text = text or ""
    if len(text) <= cap:
        return text
    return text[:cap] + f"\n… truncated ({len(text)} bytes total)"


def _format_http_pair_display(doc: dict) -> str:
    """Pretty-print a stored http_pair JSON dict for report HTML (already redacted at store)."""
    method = str(doc.get("method") or "GET").upper()
    url = str(doc.get("url") or "")
    status = doc.get("status")
    status_s = str(status) if status not in (None, "") else "—"
    req_body = _trim_http_body(str(doc.get("request_body") or ""))
    resp_body = _trim_http_body(str(doc.get("response_body") or ""))
    req_h = doc.get("request_headers") or {}
    resp_h = doc.get("response_headers") or {}
    req_h_lines = "\n".join(f"{k}: {v}" for k, v in req_h.items()) if isinstance(req_h, dict) else ""
    resp_h_lines = "\n".join(f"{k}: {v}" for k, v in resp_h.items()) if isinstance(resp_h, dict) else ""
    parts = [
        f"{method} {url}",
        f"Status: {status_s}",
        "",
        "— Request —",
        req_h_lines or "(no headers)",
        "",
        req_body or "(empty body)",
        "",
        "— Response —",
        resp_h_lines or "(no headers)",
        "",
        resp_body or "(empty body)",
    ]
    return "\n".join(parts)


def _http_pair_embeds(findings: list) -> dict[int, list[dict]]:
    """Load http_pair evidence (hash-verified), defensive re-mask, for report display."""
    import json

    from attestra.evidence.mask import mask_bytes

    out: dict[int, list[dict]] = {}
    for f in findings:
        pairs: list[dict] = []
        for e in f.evidence or []:
            if e.kind != "http_pair":
                continue
            path = Path(e.path)
            if not path.is_file():
                continue
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            if hashlib.sha256(raw).hexdigest() != e.sha256:
                continue
            masked, _ = mask_bytes(raw, content_type="application/json")
            try:
                doc = json.loads(masked.decode("utf-8", "replace"))
            except (ValueError, UnicodeError):
                continue
            if not isinstance(doc, dict):
                continue
            pairs.append(
                {
                    "id": e.id,
                    "filename": e.filename,
                    "sha256": e.sha256,
                    "note": e.note or "",
                    "display": _format_http_pair_display(doc),
                }
            )
        if pairs:
            out[f.id] = pairs
    return out


def _branding(s: Session, tenant_id: int | None, kind: str) -> dict:
    """Cover title, logo and optional disclaimer from the tenant report template."""
    empty = {"cover_title": "", "logo": "", "disclaimer": ""}
    if tenant_id is None:
        return empty
    from attestra.library.templates import _pick

    t = _pick(s, tenant_id, kind)
    if t is None:
        return empty
    return {
        "cover_title": t.cover_title or "",
        "logo": t.logo or "",
        "disclaimer": (getattr(t, "disclaimer", None) or "").strip(),
    }


def _scan_history(s: Session, engagement_id: int) -> list[ScanRun]:
    return list(
        s.scalars(select(ScanRun).where(ScanRun.engagement_id == engagement_id).order_by(ScanRun.id.desc()).limit(50))
    )


def _auth_web_report_context(s: Session, eng: Engagement) -> dict:
    """WSTG/ASVS checklist (+ optional coverage) for reports; never includes secrets."""
    # @lat: [[reports#Generation]]
    # @lat: [[architecture#Authenticated website testing]]
    from attestra.auth_web.checklists import ensure_checklist, list_checklist

    rows = list_checklist(s, eng.id)
    if not rows and config.AUTH_WEB_ENABLED:
        rows = ensure_checklist(s, eng.id, eng.tenant_id)
    if not rows:
        return {"auth_checklist": [], "auth_coverage": None}

    auth_checklist = [
        {
            "ref": item.ref,
            "title": item.title,
            "status": item.status,
            "notes": item.notes or "",
            "mapping_version": item.mapping_version or "",
            "executed_at": item.executed_at.isoformat() if item.executed_at else None,
        }
        for item in rows
    ]
    try:
        from attestra.auth_web.coverage import coverage_summary

        auth_coverage = coverage_summary(s, eng.id)
    except Exception:
        auth_coverage = None
    return {"auth_checklist": auth_checklist, "auth_coverage": auth_coverage}


def _safe_to_host_context(eng: Engagement, open_critical_high: int) -> dict:
    """Safe-to-Host letter fields for attestation; never claims compliance certification."""
    # @lat: [[reports#Safe-to-Host attestation]]
    auths = list(eng.authorizations or [])
    envs: list[str] = []
    for a in auths:
        for env in a.environments or []:
            if env and env not in envs:
                envs.append(str(env))
    if not envs:
        for asset in eng.assets or []:
            env = getattr(asset, "environment", None)
            if env and env not in envs:
                envs.append(str(env))
    client = eng.tenant.name if eng.tenant else ""
    return {
        "safe_to_host": True,
        "safe_to_host_client": client,
        "safe_to_host_engagement": eng.name,
        "safe_to_host_authorization_present": bool(auths),
        "safe_to_host_environments": envs,
        "safe_to_host_open_critical_high": int(open_critical_high),
    }


def _sebi_timeline_report_context(s: Session, eng: Engagement) -> dict:
    """Optional SEBI CSCRF security-testing timeline summary for report context."""
    # @lat: [[compliance#SEBI security testing timeline]]
    try:
        from attestra.compliance.sebi_timeline import build_timeline

        return {"sebi_timeline": build_timeline(s, eng)}
    except Exception:
        return {"sebi_timeline": None}


def _context(s: Session, engagement_id: int, framework: str = "", *, include_comments: bool = False, kind: str = "") -> dict:
    eng = services.get_engagement(s, engagement_id)
    findings = services.list_findings(s, engagement_id)
    reportable = [f for f in findings if f.status != "false_positive"]
    open_f = [f for f in reportable if f.status in OPEN_STATUSES]
    by_sev = Counter(f.severity for f in open_f)
    prev_by_sev = _previous_open_by_sev(s, eng)
    imports = list(s.scalars(select(ImportRun).where(ImportRun.engagement_id == engagement_id).order_by(ImportRun.id)))
    lib = load_library()
    frameworks = {}
    for fw in ([framework] if framework else eng.frameworks):
        results = services.compliance(s, engagement_id, fw)
        counts = Counter(r.status for r in results)
        frameworks[fw] = {"name": lib.frameworks[fw]["name"], "results": results, "counts": counts}
    site_grades = []
    for asset in eng.assets:
        try:
            site_grades.append(services.asset_site_grade(s, asset.id))
        except Exception:
            continue

    comments_by_finding: dict[int, list] = {}
    if include_comments:
        from attestra.comments import comments_for_findings

        comments_by_finding = comments_for_findings(s, [f.id for f in reportable])

    from attestra.library import service as library_service

    fix_ctx = library_service.fix_context_for_engagement(s, reportable)
    test_types, standards = _test_types_and_standards(eng)
    retests_by_finding = _retests_for_engagement(s, engagement_id, reportable)
    branding = _branding(s, eng.tenant_id, kind or "technical")
    tmpl_cfg = load_template_config()
    embeds = _evidence_embeds(reportable)
    open_critical_high = sum(1 for f in open_f if f.severity in ("critical", "high"))
    return {
        "eng": eng,
        "tenant": eng.tenant.name,
        "type_label": engagement_type_label(eng.type),
        "detected_by": detected_by_label,
        "observations_by_finding": _observations_by_finding(s, reportable),
        "evidence_limitations": _evidence_limitations(reportable),
        "findings": reportable,
        "passed_checks": services.list_passed_checks(s, engagement_id),
        "tls_summaries": services.tls_summaries(s, engagement_id),
        "site_grades": site_grades,
        "open_findings": open_f,
        "by_sev": by_sev,
        "prev_by_sev": prev_by_sev,
        "trend_svg": _trend_svg(by_sev, prev_by_sev),
        "severities": SEVERITIES,
        "status_counts": Counter(f.status for f in reportable),
        "false_positives": sum(1 for f in findings if f.status == "false_positive"),
        "imports": imports,
        "authorizations": eng.authorizations,
        "frameworks": frameworks,
        "objectives_for": lambda f: [
            DISPLAY_LABELS.get(k)
            or (lib.objectives.get(k) or {}).get("name")
            or k.replace("_", " ").strip().title()
            for k in objectives_for(f, lib)
        ],
        "top": sorted(open_f, key=lambda f: -f.risk_score)[:5],
        "kev_open": [f for f in open_f if f.kev],
        "today": date.today(),
        "version_str": __version__,
        "open_critical_high": open_critical_high,
        "feed_catalog": _feed_catalog(),
        "include_comments": include_comments,
        "comments_by_finding": comments_by_finding,
        "fix_by_id": fix_ctx["fix_by_id"],
        "report_snippets_by_id": fix_ctx["report_snippets_by_id"],
        "server_type": fix_ctx["server_type"],
        "test_types": test_types,
        "standards": standards,
        "retests_by_finding": retests_by_finding,
        "latest_retest": lambda fid: _latest_retest(retests_by_finding, fid),
        "evidence_embeds": embeds,
        "figures": _figures_list(embeds),
        "http_pairs": _http_pair_embeds(reportable),
        "cover_title": branding["cover_title"],
        "logo": branding["logo"],
        "cvss_legend": cvss_legend(),
        "methodology_phases": methodology_phases(),
        "disclaimer": branding["disclaimer"] or disclaimer_text(),
        "kind_meta": kind_config(kind) if kind else {},
        "template_config": tmpl_cfg,
        "scan_history": _scan_history(s, engagement_id),
        "contact_name": eng.tenant.contact_name or "",
        "contact_email": eng.tenant.contact_email or "",
        "distribution": _distribution_list(eng),
        **_ai_context(engagement_id, eng.tenant_id),
        **_auth_web_report_context(s, eng),
        **_safe_to_host_context(eng, open_critical_high),
        **_sebi_timeline_report_context(s, eng),
    }


def _ai_context(engagement_id: int, tenant_id: int | None) -> dict:
    """Step 8.5: only tester-approved AI drafts; empty when the feature is off."""
    from attestra.ai_narratives import approved_for_report

    return approved_for_report(engagement_id, tenant_id)


def _feed_catalog() -> dict:
    try:
        from attestra.ops.feeds import load_catalog_meta

        return load_catalog_meta()
    except Exception:
        return {}


def generate_report(
    s: Session,
    engagement_id: int,
    *,
    kind: str,
    actor: str,
    framework: str = "",
    user_id: int | None = None,
    include_comments: bool = False,
) -> Report:
    if kind not in KINDS:
        raise services.ServiceError(f"kind must be one of {KINDS}")
    eng = services.get_engagement(s, engagement_id)
    _assert_not_before_window(eng)
    if kind == "compliance":
        if not framework:
            raise services.ServiceError("framework is required for a compliance report")
        if framework not in load_library().frameworks:
            raise services.ServiceError(f"unknown framework '{framework}'")
    elif kind == "iso_soa":
        framework = framework or "iso_27001_2022"
        if framework not in load_library().frameworks:
            raise services.ServiceError(f"unknown framework '{framework}'")
    else:
        framework = ""

    version = (
        s.scalar(
            select(func.max(Report.version)).where(
                Report.engagement_id == engagement_id, Report.kind == kind, Report.framework == framework
            )
        )
        or 0
    ) + 1
    ctx = _context(s, engagement_id, framework, include_comments=include_comments, kind=kind)
    ctx["report_history"] = _report_history(s, engagement_id, kind=kind, framework=framework)
    if kind == "iso_soa":
        fw = framework or "iso_27001_2022"
        ctx["soa_results"] = services.compliance(s, engagement_id, fw)
        ctx["nonconformities"] = list(eng.nonconformities)
        meta = load_library().frameworks.get(fw) or {}
        ctx["soa_framework"] = (meta.get("name") if isinstance(meta, dict) else None) or fw
    if kind == "ageing":
        ctx["sla_breaches"] = services.sla_breaches(s, engagement_id)
    if kind == "retest":
        flat = [r for rows in ctx["retests_by_finding"].values() for r in rows]
        ctx["all_retests"] = sorted(flat, key=lambda r: r.id, reverse=True)
        ctx["unresolved"] = [
            f for f in ctx["findings"] if f.status in OPEN_STATUSES or f.status in ("validated", "fixed")
        ]
        ctx["findings_by_id"] = {f.id: f for f in ctx["findings"]}
    if kind == "owasp_top10":
        from attestra.compliance.owasp import (
            get_llm_top10,
            get_top10,
            group_findings_by_llm_top10,
            group_findings_by_top10,
            should_show_llm_top10,
        )

        ctx["top10_catalog"] = get_top10()
        ctx["top10_groups"] = group_findings_by_top10(ctx["findings"])
        ctx["show_llm_top10"] = should_show_llm_top10(eng.frameworks, ctx["findings"])
        ctx["llm_top10_catalog"] = get_llm_top10()
        ctx["llm_top10_groups"] = (
            group_findings_by_llm_top10(ctx["findings"]) if ctx["show_llm_top10"] else []
        )
    # Generated files are always draft until the separate sign-off workflow completes.
    ctx.update(kind=kind, version=version, generated_by=actor, generated_at=utcnow(), is_draft=True)
    from attestra.library.templates import render_custom  # tenant template, else built-in

    custom = render_custom(s, eng.tenant_id, kind, ctx)
    html = (custom if custom is not None else _env.get_template(f"{kind}.html.j2").render(**ctx)).encode("utf-8")
    sha = hashlib.sha256(html).hexdigest()

    config.ensure_dirs()
    suffix = f"-{framework}" if framework else ""
    report_dir = config.DATA_DIR / "tenants" / str(eng.tenant_id) / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"eng{eng.id}-{kind}{suffix}-v{version}.html"
    path.write_bytes(html)
    path.chmod(0o444)

    r = Report(
        engagement_id=engagement_id, kind=kind, framework=framework, version=version,
        path=str(path), sha256=sha, generated_by=actor, generated_by_user_id=user_id,
        status="draft",
    )
    s.add(r)
    s.flush()
    audit.record(s, actor, "report.generate", "report", r.id, kind=kind, framework=framework, version=version, sha256=sha)
    return r


def _get_report(s: Session, report_id: int) -> Report:
    r = s.get(Report, report_id)
    if not r:
        raise LookupError(f"report {report_id} not found")
    return r


def _assert_hash(r: Report) -> None:
    current = hashlib.sha256(Path(r.path).read_bytes()).hexdigest()
    if current != r.sha256:
        raise services.ServiceError("report file changed after generation; regenerate it")


def _user_conflict(user_id: int | None, *others: int | None) -> bool:
    if user_id is None:
        return False
    return any(o is not None and o == user_id for o in others)


def submit_report(s: Session, report_id: int, *, actor: str, user_id: int | None = None) -> Report:
    r = _get_report(s, report_id)
    if r.status not in ("draft", "rejected"):
        raise services.ServiceError(f"cannot submit report in status '{r.status}'")
    _assert_not_before_window(services.get_engagement(s, r.engagement_id))
    _assert_hash(r)
    r.status = "submitted"
    r.rejection_note = ""
    audit.record(s, actor, "report.submit", "report", r.id)
    return r


def qa_approve(s: Session, report_id: int, *, actor: str, user_id: int | None = None) -> Report:
    r = _get_report(s, report_id)
    if r.status != "submitted":
        raise services.ServiceError(f"cannot QA-approve report in status '{r.status}'")
    if _user_conflict(user_id, r.generated_by_user_id) or (
        user_id is None and actor.strip().lower() == r.generated_by.strip().lower()
    ):
        raise services.ServiceError("four-eyes rule: QA must be a different person from the author")
    _assert_hash(r)
    r.status = "qa_approved"
    r.qa_by, r.qa_by_user_id = actor, user_id
    audit.record(s, actor, "report.qa_approve", "report", r.id)
    return r


def qa_reject(s: Session, report_id: int, *, actor: str, note: str, user_id: int | None = None) -> Report:
    r = _get_report(s, report_id)
    if r.status != "submitted":
        raise services.ServiceError(f"cannot reject report in status '{r.status}'")
    if not note.strip():
        raise services.ServiceError("a rejection note is required")
    if _user_conflict(user_id, r.generated_by_user_id):
        raise services.ServiceError("four-eyes rule: QA must be a different person from the author")
    r.status = "rejected"
    r.rejection_note = note.strip()
    r.qa_by, r.qa_by_user_id = actor, user_id
    audit.record(s, actor, "report.qa_reject", "report", r.id, note=note.strip())
    return r


def sign_report(
    s: Session,
    report_id: int,
    *,
    actor: str,
    user_id: int | None = None,
    role: str | None = None,
) -> Report:
    """Sign a QA-approved report. Lead (or admin) role required when role is provided."""
    r = _get_report(s, report_id)
    if r.status != "qa_approved":
        raise services.ServiceError(f"cannot sign report in status '{r.status}'; QA approval required")
    if role is not None and role not in ("lead", "admin"):
        raise services.ServiceError("only lead or admin may sign a report")
    if _user_conflict(user_id, r.generated_by_user_id, r.qa_by_user_id) or (
        user_id is None
        and (
            actor.strip().lower() == r.generated_by.strip().lower()
            or (r.qa_by and actor.strip().lower() == r.qa_by.strip().lower())
        )
    ):
        raise services.ServiceError("four-eyes rule: signer must differ from author and QA")
    _assert_not_before_window(services.get_engagement(s, r.engagement_id))
    _assert_hash(r)
    r.signature = signing.sign(r.sha256)
    r.algorithm = signing.algorithm_of(r.signature)
    r.approved_by, r.approved_by_user_id, r.status, r.signed_at = actor, user_id, "signed", utcnow()
    audit.record(s, actor, "report.sign", "report", r.id, sha256=r.sha256, signature=r.signature, algorithm=r.algorithm)
    from attestra.webhooks.service import safe_emit_report

    safe_emit_report(s, r, actor=actor)
    from attestra.integrations.grc import safe_push_grc_report

    safe_push_grc_report(s, r.id, actor=actor)
    return r


def approve_report(s: Session, report_id: int, *, actor: str, user_id: int | None = None) -> Report:
    """Legacy two-step path: draft → signed when author ≠ approver.

    Prefer [[submit_report]] / [[qa_approve]] / [[sign_report]] for the full workflow.
    If the report is already ``qa_approved``, delegates to [[sign_report]].
    """
    r = _get_report(s, report_id)
    if r.status == "signed":
        raise services.ServiceError("report is already signed; generate a new version to change it")
    if r.status == "qa_approved":
        return sign_report(s, report_id, actor=actor, user_id=user_id, role="lead")
    if r.status not in ("draft", "rejected", "submitted"):
        raise services.ServiceError(f"cannot approve report in status '{r.status}'")
    if user_id is not None and r.generated_by_user_id is not None:
        if user_id == r.generated_by_user_id:
            raise services.ServiceError("four-eyes rule: the approver must be a different person from the author")
    elif actor.strip().lower() == r.generated_by.strip().lower():
        raise services.ServiceError("four-eyes rule: the approver must be a different person from the author")
    _assert_hash(r)
    # Legacy fast-path: mark QA as same approver step then sign
    if r.status in ("draft", "rejected"):
        r.status = "submitted"
    r.qa_by, r.qa_by_user_id = actor, user_id
    r.status = "qa_approved"
    r.signature = signing.sign(r.sha256)
    r.algorithm = signing.algorithm_of(r.signature)
    r.approved_by, r.approved_by_user_id, r.status, r.signed_at = actor, user_id, "signed", utcnow()
    audit.record(s, actor, "report.sign", "report", r.id, sha256=r.sha256, signature=r.signature, algorithm=r.algorithm)
    from attestra.webhooks.service import safe_emit_report

    safe_emit_report(s, r, actor=actor)
    from attestra.integrations.grc import safe_push_grc_report

    safe_push_grc_report(s, r.id, actor=actor)
    return r


def verify_report(s: Session, report_id: int) -> dict:
    r = _get_report(s, report_id)
    current = hashlib.sha256(Path(r.path).read_bytes()).hexdigest()
    return {
        "report_id": r.id,
        "status": r.status,
        "hash_matches": current == r.sha256,
        "signature_valid": bool(r.signature) and signing.verify(r.sha256, r.signature),
        "sha256": r.sha256,
        "algorithm": r.algorithm or signing.algorithm_of(r.signature),
    }
