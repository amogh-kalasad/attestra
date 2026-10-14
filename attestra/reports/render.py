"""Render reports from finding and control data, then freeze them by hash and signature."""

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
from attestra.models import OPEN_STATUSES, SEVERITIES, ImportRun, Report, utcnow
from attestra.reports import signing

KINDS = ("technical", "executive", "compliance")
_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _context(s: Session, engagement_id: int, framework: str = "") -> dict:
    eng = services.get_engagement(s, engagement_id)
    findings = services.list_findings(s, engagement_id)
    reportable = [f for f in findings if f.status != "false_positive"]
    open_f = [f for f in reportable if f.status in OPEN_STATUSES]
    by_sev = Counter(f.severity for f in open_f)
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
    }


def generate_report(s: Session, engagement_id: int, *, kind: str, actor: str, framework: str = "") -> Report:
    if kind not in KINDS:
        raise services.ServiceError(f"kind must be one of {KINDS}")
    eng = services.get_engagement(s, engagement_id)
    if kind == "compliance":
        if not framework:
            raise services.ServiceError("framework is required for a compliance report")
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
    ctx.update(kind=kind, version=version, generated_by=actor, generated_at=utcnow())
    html = _env.get_template(f"{kind}.html.j2").render(**ctx).encode("utf-8")
    sha = hashlib.sha256(html).hexdigest()

    config.ensure_dirs()
    suffix = f"-{framework}" if framework else ""
    path = config.DATA_DIR / "reports" / f"eng{eng.id}-{kind}{suffix}-v{version}.html"
    path.write_bytes(html)
    path.chmod(0o444)

    r = Report(
        engagement_id=engagement_id, kind=kind, framework=framework, version=version,
        path=str(path), sha256=sha, generated_by=actor,
    )
    s.add(r)
    s.flush()
    audit.record(s, actor, "report.generate", "report", r.id, kind=kind, framework=framework, version=version, sha256=sha)
    return r


def approve_report(s: Session, report_id: int, *, actor: str) -> Report:
    """Four-eyes: the approver must differ from the author. Approval signs and freezes the report."""
    r = s.get(Report, report_id)
    if not r:
        raise LookupError(f"report {report_id} not found")
    if r.status == "signed":
        raise services.ServiceError("report is already signed; generate a new version to change it")
    if actor.strip().lower() == r.generated_by.strip().lower():
        raise services.ServiceError("four-eyes rule: the approver must be a different person from the author")
    current = hashlib.sha256(Path(r.path).read_bytes()).hexdigest()
    if current != r.sha256:
        raise services.ServiceError("report file changed after generation; regenerate it")
    r.signature = signing.sign(r.sha256)
    r.approved_by, r.status, r.signed_at = actor, "signed", utcnow()
    audit.record(s, actor, "report.sign", "report", r.id, sha256=r.sha256, signature=r.signature)
    return r


def verify_report(s: Session, report_id: int) -> dict:
    r = s.get(Report, report_id)
    if not r:
        raise LookupError(f"report {report_id} not found")
    current = hashlib.sha256(Path(r.path).read_bytes()).hexdigest()
    return {
        "report_id": r.id,
        "status": r.status,
        "hash_matches": current == r.sha256,
        "signature_valid": bool(r.signature) and signing.verify(r.sha256, r.signature),
        "sha256": r.sha256,
    }
