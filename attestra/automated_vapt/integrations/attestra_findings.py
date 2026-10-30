"""Map Elite validated results into Attestra findings with dedup."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra.automated_vapt.validation.severity_calculator import severity_for
from attestra.fingerprint import fingerprint
from attestra.models import Finding
from attestra.proof.pair import HttpPair
from attestra.proof.store import attach_http_pair, attach_screenshot
from attestra.scoring import risk_score, sla_due

# @lat: [[architecture#Elite automated security testing#Finding integration]]

TOOL = "automated_vapt"
log = logging.getLogger(__name__)


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


def _coerce_pair(item: HttpPair | dict[str, Any]) -> HttpPair | None:
    if isinstance(item, HttpPair):
        return item
    if isinstance(item, dict):
        try:
            return HttpPair.from_dict(item)
        except (TypeError, ValueError):
            return None
    return None


def document_finding_evidence(
    s: Session,
    finding_id: int,
    *,
    actor: str,
    http_pairs: list[HttpPair | dict[str, Any]] | None = None,
    screenshots: list[tuple[str, bytes]] | None = None,
    render_two_panel: bool = True,
    source_tool: str = TOOL,
) -> dict[str, Any]:
    """Attach HTTP pairs and image documents as finding evidence for HTML/PDF reports.

    Technical reports embed ``screenshot`` evidence as figures and ``http_pair``
    evidence as pretty-printed request/response blocks. Two-panel HTTP PNGs are
    stored as screenshots so they appear in the generated document itself.
    """
    # @lat: [[architecture#Elite automated security testing#Finding evidence documents]]
    attached: dict[str, Any] = {"http_pair_ids": [], "screenshot_ids": [], "two_panel_ids": []}
    for raw in http_pairs or []:
        pair = _coerce_pair(raw)
        if pair is None:
            continue
        ev = attach_http_pair(
            s,
            finding_id,
            pair,
            actor=actor,
            note="elite automated capture",
        )
        attached["http_pair_ids"].append(ev.id)
        if not render_two_panel:
            continue
        try:
            from attestra.automated_vapt.evidence.request_response_renderer import (
                render_http_pair_png,
            )

            png = render_http_pair_png(pair.redacted())
            shot = attach_screenshot(
                s,
                finding_id,
                filename=f"elite_http_pair_{ev.id}_two_panel.png",
                data=png,
                actor=actor,
                note="Elite two-panel HTTP visual (Attestra-generated)",
                source_tool=source_tool,
            )
            attached["two_panel_ids"].append(shot.id)
            attached["screenshot_ids"].append(shot.id)
        except Exception:  # noqa: BLE001 — never block finding documentation
            log.exception("elite two-panel render failed for finding %s", finding_id)

    for filename, data in screenshots or []:
        if not data:
            continue
        try:
            shot = attach_screenshot(
                s,
                finding_id,
                filename=filename or "elite_screenshot.png",
                data=data,
                actor=actor,
                note="Elite browser screenshot",
                source_tool=source_tool,
            )
            attached["screenshot_ids"].append(shot.id)
        except Exception:  # noqa: BLE001
            log.exception("elite screenshot attach failed for finding %s", finding_id)
    return attached
