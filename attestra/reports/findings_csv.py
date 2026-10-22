"""Findings CSV export with formula-injection guard.

Columns stay limited to triage fields. Evidence bodies, notes and comments
are never included.
"""
# @lat: [[findings#CSV export]]

from __future__ import annotations

import csv
import io
from datetime import date, datetime

from sqlalchemy.orm import Session

from attestra import audit
from attestra.models import Finding
from attestra.services import list_findings

# Excel / LibreOffice treat these prefixes as formulas.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

CSV_COLUMNS = (
    "id",
    "target",
    "title",
    "severity",
    "status",
    "risk score",
    "CVSS",
    "CWE",
    "first seen",
    "last seen",
    "due date",
    "source tools",
    "fingerprint",
)


def csv_cell(value: object) -> str:
    """Stringify a cell and prefix formula-like values with a single quote."""
    if value is None:
        text = ""
    elif isinstance(value, datetime):
        text = value.isoformat()
    elif isinstance(value, date):
        text = value.isoformat()
    elif isinstance(value, float):
        text = f"{value:.2f}".rstrip("0").rstrip(".") if value == value else ""
    else:
        text = str(value)
    if text and text[0] in _FORMULA_PREFIXES:
        return "'" + text
    return text


def findings_to_rows(findings: list[Finding]) -> list[list[str]]:
    """Map finding rows to guarded CSV cells (no evidence / notes / comments)."""
    rows: list[list[str]] = []
    for f in findings:
        # Prefer identifier (URL/host) so the target column is never blank when linked (P1-3).
        target = ""
        if f.asset is not None:
            target = (f.asset.identifier or f.asset.name or "").strip()
        if not target:
            # Unlinked findings (e.g. imported for a URL not in scope): fall back to where it was seen.
            target = (f.location or "").strip()
        tools = ", ".join(str(t) for t in (f.tools or []))
        rows.append(
            [
                csv_cell(f.id),
                csv_cell(target),
                csv_cell(f.title),
                csv_cell(f.severity),
                csv_cell(f.status),
                csv_cell(f.risk_score),
                csv_cell(f.cvss_score if f.cvss_score is not None else ""),
                csv_cell(f"CWE-{f.cwe}" if f.cwe else ""),
                csv_cell(f.first_seen),
                csv_cell(f.last_seen),
                csv_cell(f.sla_due if f.sla_due is not None else ""),
                csv_cell(tools),
                csv_cell(f.fingerprint),
            ]
        )
    return rows


def render_findings_csv(findings: list[Finding]) -> str:
    """Build a CSV document with the fixed column order."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(list(CSV_COLUMNS))
    w.writerows(findings_to_rows(findings))
    return buf.getvalue()


def export_findings_csv(
    s: Session,
    engagement_id: int,
    *,
    actor: str,
    asset_id: int | None = None,
) -> str:
    """Export findings for an engagement (optionally one target) and audit it."""
    findings = list_findings(s, engagement_id)
    if asset_id is not None:
        findings = [f for f in findings if f.asset_id == asset_id]
    body = render_findings_csv(findings)
    audit.record(
        s,
        actor,
        "findings.exported",
        "engagement",
        engagement_id,
        asset_id=asset_id,
        row_count=len(findings),
    )
    return body
