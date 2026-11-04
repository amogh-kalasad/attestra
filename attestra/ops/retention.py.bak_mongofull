"""Retention policies and audited purge of expired artifacts."""
# @lat: [[architecture#Evidence integrity]]

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, config
from attestra.models import Engagement, Evidence, Finding, ImportRun, Report, RetentionPolicy

PCI_MIN_DAYS = 365


def ensure_default_policy(s: Session, tenant_id: int, *, days: int = PCI_MIN_DAYS) -> RetentionPolicy:
    """Return the tenant default retention policy, creating PCI-aligned defaults if missing."""
    row = s.scalar(
        select(RetentionPolicy).where(
            RetentionPolicy.tenant_id == tenant_id,
            RetentionPolicy.framework == "",
        )
    )
    if row:
        return row
    days = max(days, PCI_MIN_DAYS)
    row = RetentionPolicy(tenant_id=tenant_id, framework="", days=days, legal_hold=False)
    s.add(row)
    s.flush()
    return row


def retention_days_for(s: Session, tenant_id: int) -> int:
    pol = s.scalar(
        select(RetentionPolicy).where(
            RetentionPolicy.tenant_id == tenant_id,
            RetentionPolicy.framework == "",
        )
    )
    if pol and pol.legal_hold:
        return 10**9  # effectively never
    if pol:
        return max(pol.days, PCI_MIN_DAYS)
    return PCI_MIN_DAYS


def purge_expired(s: Session, *, dry_run: bool = True, actor: str = "cli") -> dict:
    """Delete expired evidence/import/report files and rows; skip legal-hold reports.

    Returns counts of candidates and deletions. Always audits each deletion when not dry_run.
    """
    now = datetime.now(UTC)
    deleted = {"evidence": 0, "imports": 0, "reports": 0, "files": 0}
    candidates = {"evidence": 0, "imports": 0, "reports": 0}

    # Evidence via finding → engagement → tenant
    for ev in list(s.scalars(select(Evidence))):
        f = s.get(Finding, ev.finding_id)
        if not f:
            continue
        eng = s.get(Engagement, f.engagement_id)
        if not eng:
            continue
        days = retention_days_for(s, eng.tenant_id)
        captured = ev.captured_at
        if captured.tzinfo is None:
            captured = captured.replace(tzinfo=UTC)
        if captured + timedelta(days=days) > now:
            continue
        candidates["evidence"] += 1
        if dry_run:
            continue
        _unlink(ev.path)
        deleted["files"] += 1
        audit.record(
            s, actor, "retention.purge", "evidence", ev.id,
            tenant_id=eng.tenant_id, path=ev.path, sha256=ev.sha256,
        )
        s.delete(ev)
        deleted["evidence"] += 1

    for run in list(s.scalars(select(ImportRun))):
        eng = s.get(Engagement, run.engagement_id)
        if not eng:
            continue
        days = retention_days_for(s, eng.tenant_id)
        imported = run.imported_at
        if imported.tzinfo is None:
            imported = imported.replace(tzinfo=UTC)
        if imported + timedelta(days=days) > now:
            continue
        candidates["imports"] += 1
        if dry_run:
            continue
        _unlink(run.raw_path)
        deleted["files"] += 1
        audit.record(
            s, actor, "retention.purge", "import_run", run.id,
            tenant_id=eng.tenant_id, path=run.raw_path, sha256=run.sha256,
        )
        s.delete(run)
        deleted["imports"] += 1

    for r in list(s.scalars(select(Report))):
        if r.legal_hold:
            continue
        eng = s.get(Engagement, r.engagement_id)
        if not eng:
            continue
        days = retention_days_for(s, eng.tenant_id)
        generated = r.generated_at
        if generated.tzinfo is None:
            generated = generated.replace(tzinfo=UTC)
        if generated + timedelta(days=days) > now:
            continue
        candidates["reports"] += 1
        if dry_run:
            continue
        for p in (r.path, r.docx_path, r.pdf_path):
            if p:
                _unlink(p)
                deleted["files"] += 1
        audit.record(
            s, actor, "retention.purge", "report", r.id,
            tenant_id=eng.tenant_id, path=r.path, sha256=r.sha256,
        )
        s.delete(r)
        deleted["reports"] += 1

    return {"dry_run": dry_run, "candidates": candidates, "deleted": deleted}


def _unlink(path: str) -> None:
    if not path:
        return
    p = Path(path)
    if not p.is_absolute():
        p = config.DATA_DIR / path
    try:
        if p.is_file():
            p.chmod(0o666)
            p.unlink()
    except OSError:
        pass
