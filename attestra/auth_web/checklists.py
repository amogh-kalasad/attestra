"""WSTG/ASVS engagement checklists for authenticated security testing."""
# @lat: [[architecture#Authenticated website testing]]

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra.models import CHECKLIST_STATUSES, AuthChecklistItem, utcnow
from attestra.services import ServiceError

# Built-in subset — seed only; engagements may extend later via other modules.
DEFAULT_CHECKLIST: tuple[tuple[str, str, str], ...] = (
    ("WSTG-INFO-02", "Fingerprint Web Server", "WSTG-v4.2"),
    ("WSTG-CONF-01", "Test Network Infrastructure Configuration", "WSTG-v4.2"),
    ("WSTG-CONF-12", "Test Content Security Policy Headers", "WSTG-v4.2"),
    ("WSTG-ATHN-01", "Credentials Transported over an Encrypted Channel", "WSTG-v4.2"),
    ("WSTG-ATHN-02", "Default Credentials", "WSTG-v4.2"),
    ("WSTG-ATHN-04", "Bypassing Authentication Schema", "WSTG-v4.2"),
    ("WSTG-ATHN-07", "Weak Password Policy / Account Lockout", "WSTG-v4.2"),
    ("WSTG-ATHZ-01", "Directory Traversal / File Include", "WSTG-v4.2"),
    ("WSTG-ATHZ-02", "Bypassing Authorization Schema", "WSTG-v4.2"),
    ("WSTG-ATHZ-04", "Insecure Direct Object References", "WSTG-v4.2"),
    ("WSTG-SESS-02", "Cookies Attributes", "WSTG-v4.2"),
    ("WSTG-SESS-05", "Cross Site Request Forgery", "WSTG-v4.2"),
    ("WSTG-INPV-01", "Reflected Cross Site Scripting", "WSTG-v4.2"),
    ("WSTG-INPV-05", "SQL Injection", "WSTG-v4.2"),
    ("WSTG-CRYP-01", "Weak Transport Layer Security", "WSTG-v4.2"),
    ("WSTG-BUSL-09", "Server-Side Request Forgery", "WSTG-v4.2"),
    ("ASVS-V2.1.1", "Password Security Requirements", "ASVS-4.0"),
    ("ASVS-V4.1.1", "General Access Control Design", "ASVS-4.0"),
)


def ensure_checklist(session: Session, engagement_id: int, tenant_id: int) -> list[AuthChecklistItem]:
    """Create missing default checklist rows as not_started. Never marks anything passed."""
    existing = {
        row.ref
        for row in session.scalars(
            select(AuthChecklistItem).where(AuthChecklistItem.engagement_id == engagement_id)
        ).all()
    }
    created: list[AuthChecklistItem] = []
    for ref, title, mapping_version in DEFAULT_CHECKLIST:
        if ref in existing:
            continue
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


def _notes_imply_skipped(notes: str | None) -> bool:
    text = (notes or "").strip().lower()
    return text.startswith("skipped")


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
    """Update a checklist row. Rejects passed when the update looks like a skip."""
    item = session.get(AuthChecklistItem, item_id)
    if item is None:
        raise LookupError(f"checklist item {item_id} not found")

    new_status = item.status if status is None else status
    new_notes = item.notes if notes is None else (notes or "")
    new_evidence = item.evidence_ids if evidence_ids is None else list(evidence_ids or [])
    new_findings = item.finding_ids if finding_ids is None else list(finding_ids or [])

    if new_status not in CHECKLIST_STATUSES:
        raise ServiceError(f"invalid checklist status: {new_status}")

    # Do not mark a check passed merely because it was skipped.
    if new_status == "passed":
        if _notes_imply_skipped(new_notes):
            raise ServiceError("cannot mark checklist item passed when notes indicate it was skipped")
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
