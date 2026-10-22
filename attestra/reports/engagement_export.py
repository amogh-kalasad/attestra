"""Full engagement JSON data export (metadata only for evidence and reports).

Returns a JSON-serializable dict. Evidence bodies, sealed HTML, and secrets are
never included. Audited as engagement.exported with format=json.
"""
# @lat: [[reports#Exports#JSON engagement export]]

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import __version__, audit
from attestra.models import Evidence, Finding, Report, engagement_type_label
from attestra.services import compliance, get_engagement, list_findings

EXPORT_SCHEMA_VERSION = 1


def _json_value(value: object) -> Any:
    """Coerce dates/datetimes (and nested containers) for JSON serialization."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(v) for v in value]
    return str(value)


def _finding_export_dict(f: Finding) -> dict[str, Any]:
    """Finding fields aligned with the API shape (self-contained; no api import)."""
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "status": f.status,
        "risk_score": f.risk_score,
        "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector or "",
        "epss": f.epss,
        "kev": f.kev,
        "cwe": f.cwe,
        "cves": list(f.cves or []),
        "location": f.location or "",
        "impact": f.impact or "",
        "affected_urls": list(f.affected_urls or []),
        "references": list(f.references or []),
        "tools": list(f.tools or []),
        "occurrences": f.occurrences,
        "sla_due": _json_value(f.sla_due),
        "validated_by": f.validated_by or "",
        "asset_id": f.asset_id,
        "owasp_top10": f.owasp_top10 or "",
        "asvs_ref": f.asvs_ref or "",
        "wstg_ref": f.wstg_ref or "",
        "fingerprint": f.fingerprint,
        "first_seen": _json_value(f.first_seen),
        "last_seen": _json_value(f.last_seen),
    }


def _control_export_dict(r) -> dict[str, Any]:
    """One compliance ControlResult as a plain dict."""
    return {
        "ref": r.ref,
        "title": r.title,
        "status": r.status,
        "proposed": r.proposed,
        "confirmed": r.confirmed,
        "assessor": r.assessor,
        "reason": r.reason,
        "objectives": list(r.objectives or []),
        "finding_ids": list(r.finding_ids or []),
        "mapping_strength": r.mapping_strength,
        "mapping_rationale": r.mapping_rationale,
        "mappings": _json_value(list(r.mappings or [])),
    }


def _evidence_export_dict(ev: Evidence) -> dict[str, Any]:
    """Evidence metadata only — never bodies, paths, or secret-bearing keys."""
    return {
        "kind": ev.kind,
        "filename": ev.filename,
        "sha256": ev.sha256,
        "note": ev.note or "",
        "finding_id": ev.finding_id,
    }


def _report_export_dict(r: Report) -> dict[str, Any]:
    """Report metadata — sealed HTML bodies and filesystem paths are omitted."""
    return {
        "id": r.id,
        "kind": r.kind,
        "framework": r.framework or "",
        "version": r.version,
        "status": r.status,
        "sha256": r.sha256,
        "generated_at": _json_value(r.generated_at),
        "generated_by": r.generated_by or "",
    }


def export_engagement_json(s: Session, engagement_id: int, *, actor: str) -> dict[str, Any]:
    """Build a full engagement JSON export and audit engagement.exported (format=json)."""
    eng = get_engagement(s, engagement_id)
    # Ensure tenant name is available without an extra round-trip ambiguity.
    tenant_name = eng.tenant.name if eng.tenant is not None else ""

    findings = list_findings(s, engagement_id)
    finding_ids = [f.id for f in findings]

    controls: dict[str, list[dict[str, Any]]] = {}
    for fw in eng.frameworks or []:
        try:
            results = compliance(s, engagement_id, fw)
        except ValueError:
            # Unknown / unloaded framework key — skip rather than abort the export.
            continue
        controls[fw] = [_control_export_dict(r) for r in results]

    evidence_rows: list[Evidence] = []
    if finding_ids:
        evidence_rows = list(
            s.scalars(select(Evidence).where(Evidence.finding_id.in_(finding_ids)).order_by(Evidence.id))
        )

    reports = list(
        s.scalars(select(Report).where(Report.engagement_id == engagement_id).order_by(Report.id))
    )

    payload: dict[str, Any] = {
        "version": __version__,
        "export_schema_version": EXPORT_SCHEMA_VERSION,
        "engagement": {
            "id": eng.id,
            "name": eng.name,
            "type": eng.type,
            "type_label": engagement_type_label(eng.type),
            "frameworks": list(eng.frameworks or []),
            "window_start": _json_value(eng.window_start),
            "window_end": _json_value(eng.window_end),
            "tenant": tenant_name,
            "status": eng.status,
        },
        "findings": [_finding_export_dict(f) for f in findings],
        "controls": controls,
        "evidence": [_evidence_export_dict(ev) for ev in evidence_rows],
        "reports": [_report_export_dict(r) for r in reports],
    }

    audit.record(
        s,
        actor,
        "engagement.exported",
        "engagement",
        engagement_id,
        format="json",
        finding_count=len(findings),
        evidence_count=len(evidence_rows),
        report_count=len(reports),
    )
    return payload
