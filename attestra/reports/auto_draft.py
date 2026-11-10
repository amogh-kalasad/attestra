"""Auto-create or refresh draft technical reports (CA save + scan complete).

When Certification Authority settings change, Super Admin expects existing
engagements without a generated report (and draft/rejected technical reports)
across all tenants to pick up the new issuer branding. After a worker scan
finishes successfully, the engagement should also have a draft technical report
so QA can start without a manual Generate click.
"""
# @lat: [[reports#Certification Authority branding]]
# @lat: [[reports#Generation]]

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from attestra import services
from attestra.reports.render import generate_report

log = logging.getLogger("attestra.reports.auto_draft")

_REFRESHABLE = frozenset({"draft", "rejected"})
_DEFAULT_KIND = "technical"


def _latest_technical(engagement_id: int):
    from attestra.persistence.mongo import report_reads

    rows = report_reads.reports(
        engagement_id, kind=_DEFAULT_KIND, framework="", newest_first=True, limit=1
    )
    return rows[0] if rows else None


def ensure_draft_technical_report(
    s: Session,
    engagement_id: int,
    *,
    actor: str,
    user_id: int | None = None,
    force_refresh: bool = False,
) -> Any | None:
    """Ensure a draft technical report exists for the engagement.

    - No technical report yet → generate a draft.
    - Latest technical is ``draft`` or ``rejected`` → regenerate a new draft version
      when ``force_refresh`` is True (CA branding refresh) or always after a scan
      so new findings land in the draft.
    - Latest is submitted / qa_approved / signed → leave alone (do not interrupt QA).

    Returns the new Report row, or None when skipped or generation failed.
    Failures are logged and never raised to the caller (CA save / scan complete
    must not fail because one engagement cannot render).
    """
    try:
        latest = _latest_technical(engagement_id)
        if latest is not None and latest.status not in _REFRESHABLE:
            return None
        # regenerate draft/rejected (scan findings or CA branding) or create first draft
        _ = force_refresh  # reserved: callers pass True after CA save
        return generate_report(
            s,
            engagement_id,
            kind=_DEFAULT_KIND,
            actor=actor or "system",
            user_id=user_id,
        )
    except Exception as exc:
        log.warning(
            "auto draft technical report skipped for engagement %s: %s",
            engagement_id,
            exc,
        )
        return None


def refresh_drafts_for_ca(
    s: Session,
    *,
    actor: str,
    user_id: int | None = None,
) -> dict[str, int]:
    """Regenerate draft/non-generated technical reports for every tenant engagement.

    Called after Certification Authority settings are saved. Unrestricted list
    (all tenants). Submitted / signed reports are never rewritten.
    """
    generated = 0
    refreshed = 0
    skipped = 0
    failed = 0
    engagements = services.list_engagements(s, principal=None)
    for eng in engagements:
        try:
            latest = _latest_technical(eng.id)
            if latest is not None and latest.status not in _REFRESHABLE:
                skipped += 1
                continue
            had_draft = latest is not None
            row = ensure_draft_technical_report(
                s,
                eng.id,
                actor=actor,
                user_id=user_id,
                force_refresh=True,
            )
            if row is None:
                failed += 1
            elif had_draft:
                refreshed += 1
            else:
                generated += 1
        except Exception as exc:
            failed += 1
            log.warning("CA draft refresh failed for engagement %s: %s", eng.id, exc)
    return {
        "engagements": len(engagements),
        "generated": generated,
        "refreshed": refreshed,
        "skipped": skipped,
        "failed": failed,
    }
