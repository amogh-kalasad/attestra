"""Map Elite validated results into Attestra findings with dedup."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from sqlalchemy import select

from attestra.automated_vapt.validation.severity_calculator import severity_for
from attestra.fingerprint import fingerprint
from attestra.models import Finding
from attestra.scoring import risk_score, sla_due

# @lat: [[architecture#Elite automated security testing#Finding integration]]

TOOL = "automated_vapt"


def create_finding_from_validation(
    s: Session,
    *,
    engagement_id: int,
    asset_id: int | None,
    title: str,
    description: str,
    validation: dict[str, Any],
    cwe: int | None = 639,
    location: str = "",
    actor: str = "automated_vapt",
    recommendation: str = "Enforce object-level authorization and retest.",
) -> Finding | None:
    """Create a finding only for CONFIRMED or POTENTIAL validation statuses."""
    status = (validation.get("status") or "").upper()
    if status not in ("CONFIRMED", "POTENTIAL"):
        return None
    sev = severity_for(cwe=cwe, hints={"protected_data_exposed": status == "CONFIRMED"})
    loc = location or title
    fp = fingerprint(title=title, cwe=cwe, location=loc, cves=[], variant=TOOL)
    existing = s.scalars(
        select(Finding).where(Finding.engagement_id == engagement_id, Finding.fingerprint == fp)
    ).first()
    if existing is not None:
        return existing

    conf = validation.get("confidence") or ""
    reasons = "; ".join(validation.get("reasons") or [])
    desc = description
    if reasons:
        desc = f"{description}\n\nValidation ({status}, confidence={conf}): {reasons}"

    finding = Finding(
        engagement_id=engagement_id,
        asset_id=asset_id,
        fingerprint=fp,
        title=title[:500],
        description=desc,
        recommendation=recommendation,
        tools=[TOOL],
        rule_ids=[f"elite-{status.lower()}"],
        cwe=cwe,
        location=loc[:1000],
        severity=sev,
        owasp_top10="A01:2021-Broken Access Control",
        risk_score=float(risk_score(None, sev)),
        sla_due=sla_due(sev),
    )
    s.add(finding)
    s.flush()
    return finding
