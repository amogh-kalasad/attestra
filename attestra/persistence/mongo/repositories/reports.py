"""Report workflow repository: draft → submitted → qa_approved → signed."""

from __future__ import annotations

from typing import Any

from attestra.persistence.mongo import collections as C
from attestra.persistence.mongo.repositories.base import BaseRepository
from attestra.persistence.mongo.repositories.core import EngagementRepository
from attestra.persistence.mongo.repositories.ops import AuditRepository
from attestra.persistence.mongo.serialization import utcnow, with_id

VALID = {
    "draft": {"submitted", "rejected"},
    "submitted": {"qa_approved", "rejected"},
    "qa_approved": {"signed", "rejected"},
    "rejected": {"draft", "submitted"},
    "signed": set(),
}


class ReportRepository(BaseRepository):
    collection_name = C.REPORTS

    def get(self, report_id: int) -> dict[str, Any] | None:
        doc = self.get_raw(report_id)
        if not doc:
            return None
        EngagementRepository(self.db, tenant_ids=self.tenant_ids).assert_access(doc["engagement_id"])
        return doc

    def create(
        self,
        engagement_id: int,
        kind: str,
        *,
        path: str,
        sha256: str,
        framework: str = "",
        version: int = 1,
        generated_by: str = "",
        generated_by_user_id: int | None = None,
        doc_id: int | None = None,
    ) -> dict[str, Any]:
        EngagementRepository(self.db, tenant_ids=self.tenant_ids).assert_access(engagement_id)
        return self.insert_with_id(
            {
                "engagement_id": int(engagement_id),
                "kind": kind,
                "framework": framework,
                "version": int(version),
                "path": path,
                "sha256": sha256,
                "status": "draft",
                "generated_by": generated_by,
                "generated_by_user_id": generated_by_user_id,
                "qa_by_user_id": None,
                "approved_by_user_id": None,
                "signature": "",
                "created_at": utcnow(),
                "updated_at": utcnow(),
            },
            doc_id=doc_id,
        )

    def transition(
        self,
        report_id: int,
        to_status: str,
        *,
        actor: str,
        actor_user_id: int | None = None,
        author_user_id: int | None = None,
        qa_user_id: int | None = None,
        note: str = "",
        signature: str = "",
        expected_sha256: str | None = None,
    ) -> dict[str, Any]:
        doc = self.get(report_id)
        if not doc:
            raise LookupError(f"report {report_id} not found")
        current = doc.get("status") or "draft"
        allowed = VALID.get(current, set())
        if to_status not in allowed:
            raise ValueError(f"cannot transition report from {current} to {to_status}")
        if expected_sha256 is not None and doc.get("sha256") != expected_sha256:
            raise ValueError("report hash mismatch — refusing workflow transition (SHA freeze)")
        # Four-eyes: fall back to the ids stored on the report so callers cannot skip it.
        if author_user_id is None:
            author_user_id = doc.get("generated_by_user_id")
        if qa_user_id is None:
            qa_user_id = doc.get("qa_by_user_id")
        if to_status in ("qa_approved", "signed") and actor_user_id is None:
            raise ValueError("QA approval and signing need an identified user")
        if to_status == "qa_approved":
            if author_user_id is not None and actor_user_id is not None and author_user_id == actor_user_id:
                raise ValueError("QA approver must differ from report author")
        if to_status == "signed":
            if author_user_id is not None and actor_user_id is not None and author_user_id == actor_user_id:
                raise ValueError("signer must differ from report author")
            if qa_user_id is not None and actor_user_id is not None and qa_user_id == actor_user_id:
                raise ValueError("signer must differ from QA approver")
        from pymongo import ReturnDocument

        updates: dict[str, Any] = {"status": to_status, "updated_at": utcnow()}
        if to_status == "qa_approved":
            updates["qa_by_user_id"] = actor_user_id
        if to_status == "signed":
            updates["approved_by_user_id"] = actor_user_id
            if signature:
                updates["signature"] = signature
        from attestra.persistence.mongo.transactions import with_transaction

        flt: dict[str, Any] = {"_id": int(report_id), "status": current}
        if expected_sha256 is not None:
            flt["sha256"] = expected_sha256

        def _txn(session) -> dict[str, Any]:
            new_doc = self.col.find_one_and_update(
                flt, {"$set": updates}, return_document=ReturnDocument.AFTER, session=session
            )
            if new_doc is None:
                raise ValueError("report changed concurrently - refusing workflow transition")
            AuditRepository(self.db).append(
                session, actor, f"report.{to_status}", "report", int(report_id), note=note, from_status=current
            )
            return new_doc

        return with_id(with_transaction(_txn))
