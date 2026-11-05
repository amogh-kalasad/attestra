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
from sqlalchemy.orm import Session

from attestra import __version__, config, services
from attestra.compliance import load_library, objectives_for
from attestra.dedup import detected_by_label
from attestra.finding_validation.statuses import (
    ACCEPTED_RISK,
    FALSE_POSITIVE,
    INFORMATIONAL,
    NOT_REPRODUCIBLE,
)
from attestra.models import (
    ASSET_KINDS,
    DISPLAY_LABELS,
    OPEN_STATUSES,
    SEVERITIES,
    TEST_TYPES,
    Engagement,
    Report,
    Retest,
    ScanRun,
    engagement_type_label,
    utcnow,
)

# Validation classes that are not open confirmed vulnerabilities in summary KPIs.
_NON_VULN_VALIDATION = frozenset(
    {
        INFORMATIONAL,
        NOT_REPRODUCIBLE,
        FALSE_POSITIVE,
        ACCEPTED_RISK,
    }
)


def _validation_status_of(f) -> str:
    return (getattr(f, "validation_status", None) or "unvalidated").strip().lower()


def _counts_as_open_vuln(f) -> bool:
    """Informational / contradicted validation classes are not confirmed vulns."""
    return _validation_status_of(f) not in _NON_VULN_VALIDATION


def _finding_cvss_version(f) -> str:
    """Sibling Phase 5 field; empty when column not merged yet."""
    return str(getattr(f, "cvss_version", None) or "").strip()


def _finding_business_risk(f):
    """Sibling Phase 5 field; None when column not merged yet."""
    return getattr(f, "business_risk", None)
from attestra.reports import signing
from attestra.reports.labels import register_jinja_filters
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
register_jinja_filters(_env)  # @lat: [[reports#Display labels]]


def _trend_svg(current: Counter, previous: Counter | None) -> str:
    """Inline SVG bar chart comparing open findings by severity (shared with C11 target history)."""
    from attestra.history import trend_svg
    from attestra.reports.labels import severity_label

    svg = trend_svg(current, previous)
    # history.trend_svg truncates keys to 4 chars ("medi"); expand to display labels.
    for sev in ("critical", "high", "medium", "low", "info"):
        svg = svg.replace(f">{sev[:4]}</text>", f">{severity_label(sev)}</text>")
    return svg


def _previous_open_by_sev(s: Session, eng: Engagement) -> Counter | None:
    from attestra.persistence.mongo import report_reads

    prev = report_reads.previous_engagement(eng.tenant_id, eng.id)
    if not prev:
        return None
    open_f = [
        f
        for f in services.list_findings(s, prev.id)
        if f.status in OPEN_STATUSES and _counts_as_open_vuln(f)
    ]
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
    from attestra.persistence.mongo import report_reads

    rows = report_reads.reports(engagement_id, kind=kind, framework=framework, newest_first=True, limit=20)
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


def _test_type_label(key: str) -> str:
    """Full display name for a test-type key (e.g. web_dast -> Web application scan)."""
    meta = TEST_TYPES.get(key or "")
    if meta:
        return meta["label"]
    return DISPLAY_LABELS.get(key or "") or (key or "").replace("_", " ").strip().capitalize()


def _asset_kind_label(kind: str) -> str:
    """Human asset type (e.g. web_app -> Web application), without the input hint."""
    label = ASSET_KINDS.get(kind or "")
    if label:
        return label.split(" (", 1)[0].strip()
    return (kind or "").replace("_", " ").strip().capitalize()


# Short cover-scope labels (client-facing); order preserved for stable wording.
_COVER_SCOPE_KIND_LABELS = (
    ("web_app", "Web"),
    ("api", "API"),
    ("mobile_app", "Mobile"),
    ("host", "Network"),
    ("cloud_account", "Cloud"),
    ("repo", "Source"),
    ("image", "Container"),
)


def _cover_client_name(eng: Engagement) -> str:
    """Client-facing cover hero: tenant name, else engagement name (never blank)."""
    tenant = (eng.tenant.name if eng.tenant else "") or ""
    if tenant.strip():
        return tenant.strip()
    return (eng.name or "").strip() or "Client"


def _cover_scope_line(eng: Engagement) -> str:
    """One-line cover scope from engagement type + in-scope asset kinds."""
    from attestra.models import normalize_engagement_type

    label_by = dict(_COVER_SCOPE_KIND_LABELS)
    present = {getattr(a, "kind", None) or "" for a in (eng.assets or [])}
    seen = [label_by[k] for k, _ in _COVER_SCOPE_KIND_LABELS if k in present]
    type_key = normalize_engagement_type(eng.type or "")
    if type_key in ("vapt", "va", "pt"):
        lead = "VAPT testing"
    elif type_key == "retest":
        lead = "Retest"
    elif type_key == "continuous":
        lead = "Continuous security testing"
    else:
        lead = f"{engagement_type_label(eng.type)} testing".strip()
    if not seen:
        return lead
    if len(seen) == 1:
        return f"{lead} for {seen[0]}"
    if len(seen) == 2:
        return f"{lead} for {seen[0]} and {seen[1]}"
    return f"{lead} for {', '.join(seen[:-1])}, and {seen[-1]}"


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
    from attestra.reports.consolidate import member_ids

    owner: dict[int, int] = {}
    for f in findings:
        for mid in member_ids(f):
            owner.setdefault(mid, f.id)
    ids = list(owner)
    if not ids:
        return {}
    from attestra.persistence.mongo import report_reads

    rows = report_reads.retests_for_findings(engagement_id, ids, newest_first=True)
    out: dict[int, list[Retest]] = {}
    for row in rows:
        out.setdefault(owner.get(row.finding_id, row.finding_id), []).append(row)
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


def _is_automated_vapt_evidence(e) -> bool:
    """True for elite automated captures (source_tool set, or legacy elite markers)."""
    if (getattr(e, "source_tool", "") or "") == "automated_vapt":
        return True
    note = getattr(e, "note", None) or ""
    fn = getattr(e, "filename", None) or ""
    if "elite automated" in note.lower():
        return True
    if "elite_http_pair_" in fn:
        return True
    if e.kind == "http_pair" and note.startswith("proof:") and "elite" in note.lower():
        return True
    return False


def _filter_automated_vapt_evidence(finding, items: list) -> list:
    """When a finding has many automated_vapt attachments, keep only those for its location.

    Early T19-T21 runs attached every capture in the execution onto the finding. The
    technical report should show the failing endpoint's proof, not dozens of passed ones.
    Non-automated evidence is always kept. Small attachment sets (<=4) are left alone.
    """
    loc = (getattr(finding, "location", None) or "").strip()
    if not loc or not items:
        return items
    try:
        from urllib.parse import unquote, urlsplit

        needle = unquote(urlsplit(loc).path or loc).rstrip("/")
    except Exception:  # noqa: BLE001
        needle = loc
    if len(needle) < 8:
        return items

    auto: list = []
    other: list = []
    for e in items:
        if _is_automated_vapt_evidence(e):
            auto.append(e)
        else:
            other.append(e)
    if len(auto) <= 4:
        return items

    matching_pair_ids: set[int] = set()
    for e in auto:
        if e.kind == "http_pair" and needle in (e.note or ""):
            matching_pair_ids.add(e.id)
    if not matching_pair_ids:
        # Fall back: keep nothing from the automated flood rather than all of it.
        return other

    kept: list = []
    for e in auto:
        if e.kind == "http_pair" and e.id in matching_pair_ids:
            kept.append(e)
        elif e.kind == "screenshot":
            fn = e.filename or ""
            if any(f"elite_http_pair_{pid}_" in fn for pid in matching_pair_ids):
                kept.append(e)
            elif needle in (e.note or ""):
                kept.append(e)
    return other + kept


def _evidence_embeds(findings: list) -> dict[int, list[dict]]:
    """Embed screenshot evidence as data URIs when the file is present and hash-matches.

    Prefers annotated derivatives over their originals to avoid repeating the same
    capture. Capture-failure rows are never embedded as images.
    """
    out: dict[int, list[dict]] = {}
    for f in findings:
        screenshots = [
            e
            for e in _filter_automated_vapt_evidence(f, list(f.evidence or []))
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
                data = services.read_stored_bytes(path)
            except (OSError, LookupError):
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


def _observations_by_finding(s: Session, findings: list, engagement_id: int | None = None) -> dict[int, list]:
    """Scanner observations for report attribution (canonical findings only once)."""

    from attestra.reports.consolidate import member_ids

    owner: dict[int, int] = {}
    for f in findings:
        for mid in member_ids(f):
            owner.setdefault(mid, f.id)
    ids = list(owner)
    if not ids:
        return {}
    if engagement_id is None:  # callers outside _context: the findings' own engagement
        engagement_id = findings[0].engagement_id
    from attestra.persistence.mongo import report_reads

    rows = report_reads.observations_for_findings(engagement_id, ids)
    out: dict[int, list] = {}
    seen: set[tuple] = set()
    for o in rows:
        key_id = owner.get(o.finding_id, o.finding_id)
        sig = (key_id, (o.tool or "").lower(), o.original_id or "", o.location or "")
        if sig in seen:
            continue  # same scanner rule on the same URL: list it once
        seen.add(sig)
        out.setdefault(key_id, []).append(o)
    return out


_HTTP_BODY_CAP = 4096


def _figures_list(evidence_embeds: dict[int, list[dict]], flabel=None, fnum=None) -> list[dict]:
    """List-of-figures rows from screenshot embeds (caption + finding id).

    ``id`` is the internal anchor (DB id); ``label`` is the displayed report number.
    """
    figures: list[dict] = []
    order = sorted(evidence_embeds, key=lambda k: ((fnum or {}).get(k, 10**9), k))
    for fid in order:
        embeds = evidence_embeds[fid]
        for i, e in enumerate(embeds, 1):
            figures.append(
                {
                    "id": f"F-{fid}-{i}",
                    "label": f"{flabel(fid) if flabel else f'F-{fid}'}-{i}",
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
        for e in _filter_automated_vapt_evidence(f, list(f.evidence or [])):
            if e.kind != "http_pair":
                continue
            path = Path(e.path)
            if not path.is_file():
                continue
            try:
                raw = services.read_stored_bytes(path)
            except (OSError, LookupError):
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
    """Cover title, logo and optional disclaimer from the tenant report template.

    When the tenant template has no logo, fall back to the platform Certification
    Authority brand logo so issuer branding still appears on built-in reports.
    """
    empty = {"cover_title": "", "logo": "", "disclaimer": ""}
    from attestra.certification.service import report_branding as ca_branding

    ca = ca_branding(s)
    if tenant_id is None:
        return {**empty, "logo": ca.get("logo") or ""}
    from attestra.library.templates import _pick

    t = _pick(s, tenant_id, kind)
    if t is None:
        return {**empty, "logo": ca.get("logo") or ""}
    return {
        "cover_title": t.cover_title or "",
        "logo": (t.logo or "") or (ca.get("logo") or ""),
        "disclaimer": (getattr(t, "disclaimer", None) or "").strip(),
    }


def _scan_history(s: Session, engagement_id: int) -> list[ScanRun]:
    from attestra.persistence.mongo import report_reads

    return report_reads.scan_runs(engagement_id, newest_first=True, limit=50)


# Report display only: statuses that appear in the authenticated checklist table.
# not_started / not_tested / not_applicable stay in the DB and show after a later update.
_CHECKLIST_EXECUTED_STATUSES = frozenset({"passed", "pass", "failed", "fail", "blocked"})


def _checklist_status_key(status: str | None) -> str:
    """Normalize checklist status for report filtering (casing / spaces / hyphens)."""
    return (status or "").strip().lower().replace(" ", "_").replace("-", "_")


def _auth_web_report_context(s: Session, eng: Engagement) -> dict:
    """WSTG/ASVS checklist (+ optional coverage) for reports; never includes secrets."""
    # @lat: [[reports#Generation]]
    # @lat: [[architecture#Authenticated website testing]]
    from attestra.auth_web.checklists import ensure_checklist, list_checklist

    rows = list_checklist(s, eng.id)
    if not rows and config.AUTH_WEB_ENABLED:
        rows = ensure_checklist(s, eng.id, eng.tenant_id)
    if not rows:
        return {
            "auth_checklist": [],
            "auth_checklist_section": False,
            "auth_coverage": None,
        }

    # Filter at render time only — never delete or rewrite AuthChecklistItem rows.
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
        if _checklist_status_key(item.status) in _CHECKLIST_EXECUTED_STATUSES
    ]
    try:
        from attestra.auth_web.coverage import coverage_summary

        auth_coverage = coverage_summary(s, eng.id)
    except Exception:
        auth_coverage = None
    return {
        "auth_checklist": auth_checklist,
        "auth_checklist_section": True,
        "auth_coverage": auth_coverage,
    }


def _security_testing_coverage_context(s: Session, eng: Engagement) -> dict:
    """Phase 4 coverage snapshot for technical reports; never folded into vuln counts."""
    # @lat: [[reports#Generation]]
    # @lat: [[architecture#World-class coverage visibility (Phase 4)]]
    try:
        snap = services.engagement_coverage_snapshot(s, eng.id)
    except Exception:
        snap = None
    return {"security_testing_coverage": snap}


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
    from attestra import crossmerge

    all_findings = services.list_findings(s, engagement_id)
    # Read models are read-only; report code annotates findings with transient fields.
    from attestra.persistence.mongo import report_reads

    report_reads.engagement_doc(engagement_id, eng.tenant_id)  # tenant-scoped read guard
    all_findings = report_reads.annotatable(all_findings)
    # Cross-tool merge: one entry per issue; related rows are listed under Sources.
    findings = crossmerge.collapse(s, all_findings)
    # Report-only consolidation (DB untouched): one entry per issue, so per-URL scanner
    # rows and the same issue seen by several tools are not repeated in the report.
    from attestra.reports.consolidate import consolidate, member_ids

    reportable = consolidate(s, [f for f in findings if f.status != "false_positive"])
    open_f = [f for f in reportable if f.status in OPEN_STATUSES]
    # Summary / KPI open-vuln counts exclude informational and contradicted validation classes.
    vuln_open = [f for f in open_f if _counts_as_open_vuln(f)]
    informational_open = sum(1 for f in open_f if not _counts_as_open_vuln(f))
    # Report-only labels: F-1, F-2 ... in the order findings appear in the report. DB ids stay
    # internal (anchors); every merged/member row maps to its report entry's number.
    fnum: dict[int, int] = {}
    for n, rf in enumerate(reportable, 1):
        for mid in member_ids(rf):
            fnum.setdefault(int(mid), n)

    def flabel(ref) -> str:
        rid = ref if isinstance(ref, int) else getattr(ref, "id", ref)
        try:
            n = fnum.get(int(rid))
        except (TypeError, ValueError):
            n = None
        return f"F-{n}" if n else f"#{rid}"

    by_sev = Counter(f.severity for f in vuln_open)
    prev_by_sev = _previous_open_by_sev(s, eng)
    imports = report_reads.import_runs(engagement_id, eng.tenant_id)
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

        owner = {mid: f.id for f in reportable for mid in member_ids(f)}
        raw_comments = comments_for_findings(s, list(owner))
        for mid, rows in raw_comments.items():
            comments_by_finding.setdefault(owner.get(mid, mid), []).extend(rows)

    from attestra.library import service as library_service

    fix_ctx = library_service.fix_context_for_engagement(s, reportable)
    test_types, standards = _test_types_and_standards(eng)
    retests_by_finding = _retests_for_engagement(s, engagement_id, reportable)
    branding = _branding(s, eng.tenant_id, kind or "technical")
    tmpl_cfg = load_template_config()
    embeds = _evidence_embeds(reportable)
    open_critical_high = sum(1 for f in vuln_open if f.severity in ("critical", "high"))
    tls_all = services.tls_summaries(s, engagement_id)
    tls_scanned = [t for t in tls_all if t.get("scanned")]
    return {
        "eng": eng,
        "tenant": eng.tenant.name,
        "cover_client": _cover_client_name(eng),
        "cover_scope": _cover_scope_line(eng),
        "type_label": engagement_type_label(eng.type),
        "detected_by": detected_by_label,
        "observations_by_finding": _observations_by_finding(s, reportable, engagement_id),
        "evidence_limitations": _evidence_limitations(reportable),
        "findings": reportable,
        "passed_checks": services.list_passed_checks(s, engagement_id),
        # Only targets testssl actually scanned; the TLS section is omitted when empty.
        "tls_summaries": tls_scanned,
        "test_type_label": _test_type_label,
        "asset_kind_label": _asset_kind_label,
        "site_grades": site_grades,
        "open_findings": vuln_open,
        "open_findings_all": open_f,
        "by_sev": by_sev,
        "prev_by_sev": prev_by_sev,
        "trend_svg": _trend_svg(by_sev, prev_by_sev),
        "severities": SEVERITIES,
        "status_counts": Counter(f.status for f in reportable),
        "false_positives": sum(1 for f in all_findings if f.status == "false_positive"),
        "informational_open": informational_open,
        "imports": imports,
        "authorizations": eng.authorizations,
        "frameworks": frameworks,
        "objectives_for": lambda f: [
            DISPLAY_LABELS.get(k)
            or (lib.objectives.get(k) or {}).get("name")
            or k.replace("_", " ").strip().title()
            for k in objectives_for(f, lib)
        ],
        "top": sorted(vuln_open, key=lambda f: -(getattr(f, "risk_score", 0) or 0))[:5],
        "kev_open": [f for f in vuln_open if f.kev],
        "today": date.today(),
        "version_str": __version__,
        "open_critical_high": open_critical_high,
        "finding_cvss_version": _finding_cvss_version,
        "finding_business_risk": _finding_business_risk,
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
        "figures": _figures_list(embeds, flabel, fnum),
        "flabel": flabel,
        "finding_numbers": fnum,
        "http_pairs": _http_pair_embeds(reportable),
        "automated_runs": _automated_runs(s, engagement_id),
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
        "ca": _ca_report_context(s),
        **_ai_context(engagement_id, eng.tenant_id),
        **_auth_web_report_context(s, eng),
        **_security_testing_coverage_context(s, eng),
        **_safe_to_host_context(eng, open_critical_high),
        **_sebi_timeline_report_context(s, eng),
    }


def _automated_runs(s: Session, engagement_id: int) -> list[dict]:
    """Automated testing runs with their saved evidence images (empty when none)."""
    try:
        from attestra.automated_vapt.evidence.run_evidence import report_runs

        return report_runs(s, engagement_id)
    except Exception:  # noqa: BLE001 - never break a report over optional evidence
        return []


def _ca_report_context(s: Session) -> dict:
    """Platform Certification Authority fields for report templates (safe when empty)."""
    # @lat: [[reports#Certification Authority branding]]
    from attestra.certification.service import report_branding

    return report_branding(s)


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

    version = _next_version(s, engagement_id, kind, framework)
    html = render_html(
        s, engagement_id, kind=kind, framework=framework, version=version, actor=actor,
        generated_at=utcnow(), include_comments=include_comments, eng=eng,
    )
    sha = hashlib.sha256(html).hexdigest()

    config.ensure_dirs()
    suffix = f"-{framework}" if framework else ""
    report_dir = config.DATA_DIR / "tenants" / str(eng.tenant_id) / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"eng{eng.id}-{kind}{suffix}-v{version}.html"
    path.write_bytes(html)
    path.chmod(0o444)

    from attestra.persistence.mongo import report_store

    try:
        return report_store.create(
            engagement_id=engagement_id, kind=kind, framework=framework, version=version,
            path=str(path), sha256=sha, generated_by=actor, generated_by_user_id=user_id, actor=actor,
            audit_details={"kind": kind, "framework": framework, "version": version, "sha256": sha},
        )
    except report_store.ReportConflict as exc:
        raise services.ServiceError(str(exc)) from exc


def _next_version(s: Session, engagement_id: int, kind: str, framework: str) -> int:
    """Next report version for (engagement, kind, framework)."""
    from attestra.persistence.mongo import report_reads

    return report_reads.max_report_version(engagement_id, kind, framework) + 1


def render_html(
    s: Session,
    engagement_id: int,
    *,
    kind: str,
    framework: str = "",
    version: int = 1,
    actor: str = "",
    generated_at=None,
    include_comments: bool = False,
    eng: Engagement | None = None,
) -> bytes:
    """Render report HTML bytes (no file, no Report row). Deterministic for fixed inputs."""
    eng = eng if eng is not None else services.get_engagement(s, engagement_id)
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
        from attestra.reports.consolidate import member_ids as _mids

        ctx["findings_by_id"] = {mid: f for f in ctx["findings"] for mid in _mids(f)}
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
    ctx.update(kind=kind, version=version, generated_by=actor,
               generated_at=generated_at if generated_at is not None else utcnow(), is_draft=True)
    from attestra.reports import labels as report_labels

    ctx.setdefault("tool_label", report_labels.tool_label)
    ctx.setdefault("status_label", report_labels.status_label)
    ctx.setdefault("severity_label", report_labels.severity_label)
    ctx.setdefault("environment_label", report_labels.environment_label)
    ctx.setdefault("exposure_label", report_labels.exposure_label)
    ctx.setdefault("framework_label", report_labels.framework_label)
    ctx.setdefault("frameworks_label", report_labels.frameworks_label)
    ctx.setdefault("humanize", report_labels.humanize)
    ctx.setdefault("check_label", report_labels.check_label)
    ctx.setdefault("evidence_kind_label", report_labels.evidence_kind_label)
    ctx.setdefault("evidence_note_label", report_labels.evidence_note_label)
    ctx.setdefault("format_date", report_labels.format_date)
    ctx.setdefault("format_datetime", report_labels.format_datetime)
    ctx.setdefault("words_title", report_labels.words_title)
    ctx.setdefault("param_label", report_labels.param_label)
    ctx.setdefault("dedup_label", report_labels.dedup_label)
    ctx.setdefault("consolidate_sentence", report_labels.consolidate_sentence)
    ctx.setdefault("format_detail_sentence", report_labels.format_detail_sentence)
    ctx.setdefault("format_checklist_note", report_labels.format_checklist_note)
    ctx.setdefault("test_name_label", report_labels.test_name_label)
    ctx.setdefault("automated_run_header", report_labels.automated_run_header)
    ctx.setdefault("plural", report_labels.plural)
    ctx.setdefault("recommendation_to_bullets", report_labels.recommendation_to_bullets)
    from attestra.library.templates import render_custom  # tenant template, else built-in

    custom = render_custom(s, eng.tenant_id, kind, ctx)
    return (custom if custom is not None else _env.get_template(f"{kind}.html.j2").render(**ctx)).encode("utf-8")


def _get_report(s: Session, report_id: int) -> Report:
    from attestra.persistence.mongo import report_reads

    r = report_reads.report(report_id)
    if not r:
        raise LookupError(f"report {report_id} not found")
    return r


def get_report(s: Session, report_id: int, tenant_ids=None) -> Report:
    """Public report lookup: read-only Mongo view (write through the workflow functions).

    ``tenant_ids`` (None = unrestricted) hides reports of other tenants as "not found".
    """
    from attestra.persistence.mongo import report_reads

    r = report_reads.report(report_id, tenant_ids=tenant_ids)
    if not r:
        raise LookupError(f"report {report_id} not found")
    return r


def _mongo_transition(r, *, from_status, updates: dict, actor: str, action: str, sha_guard: bool = True, **details):
    from attestra.persistence.mongo import report_store

    try:
        return report_store.transition(
            r.id, from_status=from_status, expected_sha256=r.sha256 if sha_guard else None,
            updates=updates, actor=actor, action=action, audit_details=details,
        )
    except report_store.ReportConflict as exc:
        raise services.ServiceError(str(exc)) from exc


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
    return _mongo_transition(r, from_status=("draft", "rejected"), actor=actor, action="report.submit",
                             updates={"status": "submitted", "rejection_note": ""})


def qa_approve(s: Session, report_id: int, *, actor: str, user_id: int | None = None) -> Report:
    r = _get_report(s, report_id)
    if r.status != "submitted":
        raise services.ServiceError(f"cannot QA-approve report in status '{r.status}'")
    if _user_conflict(user_id, r.generated_by_user_id) or (
        user_id is None and actor.strip().lower() == r.generated_by.strip().lower()
    ):
        raise services.ServiceError("four-eyes rule: QA must be a different person from the author")
    _assert_hash(r)
    return _mongo_transition(r, from_status="submitted", actor=actor, action="report.qa_approve",
                             updates={"status": "qa_approved", "qa_by": actor, "qa_by_user_id": user_id})


def qa_reject(s: Session, report_id: int, *, actor: str, note: str, user_id: int | None = None) -> Report:
    r = _get_report(s, report_id)
    if r.status != "submitted":
        raise services.ServiceError(f"cannot reject report in status '{r.status}'")
    if not note.strip():
        raise services.ServiceError("a rejection note is required")
    if _user_conflict(user_id, r.generated_by_user_id):
        raise services.ServiceError("four-eyes rule: QA must be a different person from the author")
    return _mongo_transition(
        r, from_status="submitted", actor=actor, action="report.qa_reject", sha_guard=False, note=note.strip(),
        updates={"status": "rejected", "rejection_note": note.strip(), "qa_by": actor, "qa_by_user_id": user_id},
    )


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
    return _mongo_sign(s, r, actor=actor, user_id=user_id, from_status="qa_approved")


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
    # Legacy fast-path: QA and sign by the same approver in one guarded write.
    return _mongo_sign(s, r, actor=actor, user_id=user_id, from_status=("draft", "rejected", "submitted"),
                       qa=(actor, user_id))


def _mongo_sign(s: Session, r, *, actor: str, user_id: int | None, from_status, qa=None):
    """Mongo: sign (status+hash guarded) and audit in one transaction, then notify."""
    signature = signing.sign(r.sha256)
    algorithm = signing.algorithm_of(signature)
    updates = {"status": "signed", "signature": signature, "algorithm": algorithm,
               "approved_by": actor, "approved_by_user_id": user_id, "signed_at": utcnow()}
    if qa is not None:
        updates["qa_by"], updates["qa_by_user_id"] = qa
    signed = _mongo_transition(r, from_status=from_status, updates=updates, actor=actor, action="report.sign",
                               sha256=r.sha256, signature=signature, algorithm=algorithm)
    from attestra.webhooks.service import safe_emit_report

    safe_emit_report(s, signed, actor=actor)
    from attestra.integrations.grc import safe_push_grc_report

    safe_push_grc_report(s, signed.id, actor=actor)
    return signed


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
