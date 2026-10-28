"""Engagement Markdown export of consolidated findings and evidence references.

Uses the same canonical finding list as HTML/PDF/JSON. Evidence bodies and
storage paths are never included; references use authenticated download IDs only.
"""
# @lat: [[reports#Exports#Markdown engagement export]]

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import __version__, audit
from attestra.dedup import detected_by_label, tool_display_name
from attestra.models import Evidence, FindingObservation, engagement_type_label
from attestra.services import get_engagement, list_findings


def _dt(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def export_engagement_markdown(s: Session, engagement_id: int, *, actor: str) -> str:
    """Build a Markdown document for consolidated findings and evidence metadata."""
    eng = get_engagement(s, engagement_id)
    tenant_name = eng.tenant.name if eng.tenant is not None else ""
    findings = [f for f in list_findings(s, engagement_id) if f.status != "false_positive"]
    finding_ids = [f.id for f in findings]

    evidence_rows: list[Evidence] = []
    observations: list[FindingObservation] = []
    if finding_ids:
        evidence_rows = list(
            s.scalars(select(Evidence).where(Evidence.finding_id.in_(finding_ids)).order_by(Evidence.id))
        )
        observations = list(
            s.scalars(
                select(FindingObservation)
                .where(FindingObservation.finding_id.in_(finding_ids))
                .order_by(FindingObservation.id)
            )
        )
    evidence_by_finding: dict[int, list[Evidence]] = {}
    for ev in evidence_rows:
        evidence_by_finding.setdefault(ev.finding_id, []).append(ev)
    obs_by_finding: dict[int, list[FindingObservation]] = {}
    for o in observations:
        obs_by_finding.setdefault(o.finding_id, []).append(o)

    lines: list[str] = [
        f"# {eng.name} — consolidated findings",
        "",
        f"- Engagement ID: {eng.id}",
        f"- Tenant: {tenant_name}",
        f"- Type: {engagement_type_label(eng.type)}",
        f"- Window: {_dt(eng.window_start)} to {_dt(eng.window_end)}",
        f"- Attestra version: {__version__}",
        f"- Findings: {len(findings)} (false positives excluded)",
        "",
        "Evidence files are available through authenticated download in Attestra "
        "(API `GET /api/evidence/{id}/download`). This export does not invent public URLs.",
        "",
    ]

    if not findings:
        lines.append("No reportable findings.")
    for f in findings:
        asset = ""
        if f.asset is not None:
            asset = f.asset.name or f.asset.identifier or ""
        lines.extend(
            [
                f"## F-{f.id}: {f.title}",
                "",
                f"- Severity: {f.severity}",
                f"- Status: {f.status}",
                f"- Risk score: {f.risk_score}",
                f"- Location: {f.location or '-'}",
                f"- Asset: {asset or '-'}",
                f"- Detected by: {detected_by_label(f.tools)}",
            ]
        )
        if f.cwe:
            lines.append(f"- CWE: CWE-{f.cwe}")
        if f.cves:
            lines.append(f"- CVE: {', '.join(f.cves)}")
        if f.owasp_top10:
            lines.append(f"- OWASP Top 10: {f.owasp_top10}")
        if f.asvs_ref:
            lines.append(f"- ASVS: {f.asvs_ref}")
        if f.wstg_ref:
            lines.append(f"- WSTG: {f.wstg_ref}")
        if f.dedup_rationale:
            conf = f" ({f.dedup_confidence:.2f})" if f.dedup_confidence is not None else ""
            lines.append(f"- Dedup: {f.dedup_rationale}{conf}")
        lines.append("")
        if f.description:
            lines.extend(["### Description", "", f.description.strip(), ""])
        if f.impact:
            lines.extend(["### Impact", "", f.impact.strip(), ""])
        if f.recommendation:
            lines.extend(["### Remediation", "", f.recommendation.strip(), ""])
        if f.references:
            lines.append("### References")
            lines.append("")
            for ref in f.references:
                lines.append(f"- {ref}")
            lines.append("")

        obs = obs_by_finding.get(f.id) or []
        if obs:
            lines.append("### Scanner observations")
            lines.append("")
            for o in obs:
                label = tool_display_name(o.tool)
                oid = f" · {o.original_id}" if o.original_id else ""
                loc = f" · `{o.location}`" if o.location else ""
                lines.append(f"- {label}{oid}{loc}")
            lines.append("")

        evs = evidence_by_finding.get(f.id) or []
        if evs:
            lines.append("### Evidence")
            lines.append("")
            for ev in evs:
                role = ev.role or "original"
                src = tool_display_name(ev.source_tool) if ev.source_tool else ""
                bits = [ev.kind, f"id={ev.id}", f"role={role}", f"`{ev.filename}`", f"sha256={ev.sha256}"]
                if src:
                    bits.append(f"source={src}")
                if ev.kind == "capture_failure" or ev.capture_status in ("failed", "unavailable"):
                    bits.append(f"limitation={ev.capture_failure_reason or ev.note or 'capture failed'}")
                elif ev.note:
                    bits.append(ev.note.replace("\n", " ").strip()[:200])
                lines.append("- " + " · ".join(bits))
            lines.append("")

    audit.record(
        s,
        actor,
        "engagement.exported",
        "engagement",
        engagement_id,
        format="markdown",
        finding_count=len(findings),
        evidence_count=len(evidence_rows),
    )
    return "\n".join(lines).rstrip() + "\n"
