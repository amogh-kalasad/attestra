"""Render reports from finding and control data, then freeze them by hash and signature."""
# @lat: [[reports]]

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import date
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from attestra import __version__, audit, config, services
from attestra.compliance import load_library, objectives_for
from attestra.models import OPEN_STATUSES, SEVERITIES, Engagement, ImportRun, Report, utcnow
from attestra.reports import signing

KINDS = (
    "technical",
    "executive",
    "compliance",
    "iso_soa",
    "ageing",
    "closure_letter",
    "attestation_letter",
)
_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _trend_svg(current: Counter, previous: Counter | None) -> str:
    """Inline SVG bar chart comparing open findings by severity."""
    sevs = ["critical", "high", "medium", "low", "info"]
    colors = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#15803d", "info": "#475569"}
    width, height, gap = 320, 120, 8
    bar_w = (width - gap * (len(sevs) + 1)) // (len(sevs) * (2 if previous is not None else 1))
    max_v = max([current.get(s, 0) for s in sevs] + ([previous.get(s, 0) for s in sevs] if previous else [1]) + [1])
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height + 24}" '
        f'role="img" aria-label="Open findings by severity trend">'
    ]
    for i, sev in enumerate(sevs):
        x0 = gap + i * ((bar_w * (2 if previous is not None else 1)) + gap)
        h1 = int((current.get(sev, 0) / max_v) * height)
        parts.append(
            f'<rect x="{x0}" y="{height - h1}" width="{bar_w}" height="{h1}" fill="{colors[sev]}" />'
        )
        if previous is not None:
            h0 = int((previous.get(sev, 0) / max_v) * height)
            parts.append(
                f'<rect x="{x0 + bar_w}" y="{height - h0}" width="{bar_w}" height="{h0}" '
                f'fill="{colors[sev]}" opacity="0.35" />'
            )
        parts.append(
            f'<text x="{x0}" y="{height + 14}" font-size="9" fill="#334155">{sev[:4]}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


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


def _context(s: Session, engagement_id: int, framework: str = "") -> dict:
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
    return {
        "eng": eng,
        "tenant": eng.tenant.name,
        "findings": reportable,
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
        "objectives_for": lambda f: objectives_for(f, lib),
        "top": sorted(open_f, key=lambda f: -f.risk_score)[:5],
        "kev_open": [f for f in open_f if f.kev],
        "today": date.today(),
        "version_str": __version__,
        "open_critical_high": sum(1 for f in open_f if f.severity in ("critical", "high")),
        "feed_catalog": _feed_catalog(),
    }


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
) -> Report:
    if kind not in KINDS:
        raise services.ServiceError(f"kind must be one of {KINDS}")
    eng = services.get_engagement(s, engagement_id)
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
    ctx = _context(s, engagement_id, framework)
    if kind == "iso_soa":
        fw = framework or "iso_27001_2022"
        ctx["soa_results"] = services.compliance(s, engagement_id, fw)
        ctx["nonconformities"] = list(eng.nonconformities)
        ctx["soa_framework"] = fw
    if kind == "ageing":
        ctx["sla_breaches"] = services.sla_breaches(s, engagement_id)
    ctx.update(kind=kind, version=version, generated_by=actor, generated_at=utcnow())
    html = _env.get_template(f"{kind}.html.j2").render(**ctx).encode("utf-8")
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
    _assert_hash(r)
    r.signature = signing.sign(r.sha256)
    r.algorithm = signing.algorithm_of(r.signature)
    r.approved_by, r.approved_by_user_id, r.status, r.signed_at = actor, user_id, "signed", utcnow()
    audit.record(s, actor, "report.sign", "report", r.id, sha256=r.sha256, signature=r.signature, algorithm=r.algorithm)
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
