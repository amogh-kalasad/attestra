"""Mongo-owned report writes (mongofull, reports track).

Used by ``attestra.reports.render`` / ``export`` when reads are cut over to Mongo
(``mongo_reads("domain")``). The ``reports`` collection keeps the SQL column names and
integer ids; every state change is a conditional ``find_one_and_update`` (status + SHA-256
freeze) and its audit event is appended in the same multi-document transaction, so two
concurrent signers can not both win and a failed write leaves no audit trail behind.
Business rules (four-eyes, window checks, hash checks) stay in ``render``.
"""
from __future__ import annotations

from typing import Any

from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo.read_models import DocView
from attestra.persistence.mongo.serialization import ensure_utc, utcnow


class ReportConflict(RuntimeError):
    """The report changed (status or hash) between read and write."""


def _db():
    from attestra.persistence.mongo.adapters import _db as get

    return get()


def _view(doc: dict[str, Any]) -> DocView:
    from attestra.models import Report

    return DocView(Report, doc)


def _next_report_id(db) -> int:
    from attestra.persistence.mongo.sequences import next_id, seed_sequence

    top = db[C.REPORTS].find_one({}, {"_id": 1}, sort=[("_id", -1)])
    if top:  # rows mirrored/imported from SQL keep their ids; never reuse one
        seed_sequence(db, C.REPORTS, int(top["_id"]))
    return next_id(db, C.REPORTS)


def create(
    *,
    engagement_id: int,
    kind: str,
    framework: str,
    version: int,
    path: str,
    sha256: str,
    generated_by: str,
    generated_by_user_id: int | None,
    actor: str,
    audit_details: dict[str, Any] | None = None,
) -> DocView:
    """Insert a draft report and its ``report.generate`` audit event atomically."""
    from attestra.persistence.mongo.repositories.ops import AuditRepository
    from attestra.persistence.mongo.transactions import with_transaction

    db = _db()
    if not db[C.ENGAGEMENTS].find_one({"_id": int(engagement_id)}, {"_id": 1}):
        raise LookupError(f"engagement {engagement_id} not found")
    if db[C.REPORTS].find_one({"engagement_id": int(engagement_id), "kind": kind, "framework": framework,
                               "version": int(version)}, {"_id": 1}):
        raise ReportConflict("report version already exists; regenerate")
    rid = _next_report_id(db)
    now = utcnow()
    doc = {
        "_id": rid,
        "engagement_id": int(engagement_id),
        "kind": kind,
        "framework": framework or "",
        "version": int(version),
        "path": path,
        "sha256": sha256,
        "status": "draft",
        "generated_by": generated_by,
        "generated_by_user_id": generated_by_user_id,
        "generated_at": now,
        "qa_by": "",
        "qa_by_user_id": None,
        "rejection_note": "",
        "approved_by": "",
        "approved_by_user_id": None,
        "algorithm": "",
        "signature": "",
        "signed_at": None,
        "docx_path": "",
        "docx_sha256": "",
        "pdf_path": "",
        "pdf_sha256": "",
        "legal_hold": False,
    }

    def _txn(session):
        db[C.REPORTS].insert_one(doc, session=session)
        AuditRepository(db).append(session, actor, "report.generate", "report", rid, **(audit_details or {}))
        return doc

    return _view(with_transaction(_txn))


def transition(
    report_id: int,
    *,
    from_status: str | tuple[str, ...],
    expected_sha256: str | None,
    updates: dict[str, Any],
    actor: str,
    action: str,
    audit_details: dict[str, Any] | None = None,
) -> DocView:
    """Conditionally update one report (status + hash freeze) and audit it in one transaction."""
    from pymongo import ReturnDocument

    from attestra.persistence.mongo.repositories.ops import AuditRepository
    from attestra.persistence.mongo.transactions import with_transaction

    db = _db()
    statuses = [from_status] if isinstance(from_status, str) else list(from_status)
    flt: dict[str, Any] = {"_id": int(report_id), "status": {"$in": statuses}}
    if expected_sha256 is not None:
        flt["sha256"] = expected_sha256
    fields = {k: (ensure_utc(v) if hasattr(v, "tzinfo") and hasattr(v, "hour") else v) for k, v in updates.items()}

    def _txn(session):
        new = db[C.REPORTS].find_one_and_update(
            flt, {"$set": fields}, return_document=ReturnDocument.AFTER, session=session
        )
        if new is None:
            raise ReportConflict("report changed concurrently; reload and try again")
        AuditRepository(db).append(session, actor, action, "report", int(report_id), **(audit_details or {}))
        return new

    return _view(with_transaction(_txn))


def set_fields(report_id: int, fields: dict[str, Any]) -> None:
    """Non-workflow metadata (export paths/hashes). Never touches status, sha256 or signature."""
    blocked = {"status", "sha256", "signature", "algorithm", "signed_at", "_id", "engagement_id"}
    bad = blocked & set(fields)
    if bad:
        raise ValueError(f"set_fields can not change {sorted(bad)}")
    _db()[C.REPORTS].update_one({"_id": int(report_id)}, {"$set": dict(fields)})