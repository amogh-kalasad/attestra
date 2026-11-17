"""WSTG/ASVS engagement checklists for authenticated security testing."""
# @lat: [[architecture#Authenticated website testing]]

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra.auth_web import checklist_catalog
from attestra.models import CHECKLIST_STATUSES, AuthChecklistItem, utcnow
from attestra.services import ServiceError

# FND-05: the checklist is sourced from the versioned catalog (WSTG v4.2 + ASVS 4.0.3).
# ``DEFAULT_CHECKLIST`` stays as the backward-compatible ``(ref, title, mapping_version)`` view.
DEFAULT_ITEMS: tuple[tuple[str, str, str], ...] = checklist_catalog.default_items()
DEFAULT_CHECKLIST: tuple[tuple[str, str, str], ...] = DEFAULT_ITEMS


def ensure_checklist(session: Session, engagement_id: int, tenant_id: int) -> list[AuthChecklistItem]:
    """Create missing default checklist rows as not_started. Never marks anything passed."""
    existing = {
        row.ref
        for row in session.scalars(
            select(AuthChecklistItem).where(AuthChecklistItem.engagement_id == engagement_id)
        ).all()
    }
    created: list[AuthChecklistItem] = []
    version = checklist_catalog.catalog_version()
    cat = checklist_catalog.load_catalog()
    for ref, title, mapping_version in DEFAULT_CHECKLIST:
        if ref in existing:
            continue
        ci = cat.item(ref)
        item = AuthChecklistItem(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            ref=ref,
            title=title,
            mapping_version=mapping_version,
            status="not_started",
            notes="",
            evidence_ids=[],
            finding_ids=[],
        )
        if hasattr(item, "catalog_version"):
            item.catalog_version = version
            item.aliases = list(ci.aliases) if ci is not None else []
        session.add(item)
        created.append(item)
    if created:
        session.flush()
    return list_checklist(session, engagement_id)


def list_checklist(session: Session, engagement_id: int) -> list[AuthChecklistItem]:
    """Return checklist items for an engagement ordered by ref."""
    return list(
        session.scalars(
            select(AuthChecklistItem)
            .where(AuthChecklistItem.engagement_id == engagement_id)
            .order_by(AuthChecklistItem.ref)
        ).all()
    )


# Notes that imply the check was skipped, blocked, limited, deferred, or not executed.
# Matched case-insensitively as substrings anywhere in the notes.
INCOMPLETE_COVERAGE_NOTE_MARKERS: tuple[str, ...] = (
    "not covered",
    "not tested",
    "not executed",
    "skipped",
    "limited",
    "forms not covered",
    "blind",
    "deferred",
    "blocked:",
)


def notes_imply_incomplete_coverage(notes: str | None) -> bool:
    """True when notes admit the check was skipped, limited, or not fully executed."""
    text = (notes or "").strip().lower()
    if not text:
        return False
    return any(marker in text for marker in INCOMPLETE_COVERAGE_NOTE_MARKERS)


# Back-compat alias used by older call sites / docs.
def _notes_imply_skipped(notes: str | None) -> bool:
    return notes_imply_incomplete_coverage(notes)


def update_checklist_item(
    session: Session,
    item_id: int,
    *,
    status: str | None = None,
    notes: str | None = None,
    evidence_ids: list | None = None,
    finding_ids: list | None = None,
    actor: str = "",
) -> AuthChecklistItem:
    """Update a checklist row. Rejects passed when notes imply incomplete coverage."""
    item = session.get(AuthChecklistItem, item_id)
    if item is None:
        raise LookupError(f"checklist item {item_id} not found")

    new_status = item.status if status is None else status
    new_notes = item.notes if notes is None else (notes or "")
    new_evidence = item.evidence_ids if evidence_ids is None else list(evidence_ids or [])
    new_findings = item.finding_ids if finding_ids is None else list(finding_ids or [])

    if new_status not in CHECKLIST_STATUSES:
        raise ServiceError(f"invalid checklist status: {new_status}")

    # Honesty: never mark passed when notes say skipped / blocked / limited / deferred / not executed.
    if new_status == "passed":
        if notes_imply_incomplete_coverage(new_notes):
            raise ServiceError(
                "cannot mark checklist item passed when notes indicate incomplete coverage "
                "(skipped, blocked, limited, deferred, blind, not covered, not tested, or not executed)"
            )
        if item.status == "blocked" and not new_evidence:
            raise ServiceError("cannot mark blocked checklist item passed without evidence")

    item.status = new_status
    item.notes = new_notes
    item.evidence_ids = new_evidence
    item.finding_ids = new_findings
    item.updated_by = actor or item.updated_by
    item.updated_at = utcnow()
    if new_status in ("passed", "failed", "not_applicable", "blocked", "not_tested"):
        item.executed_at = item.executed_at or utcnow()
    session.flush()
    return item
