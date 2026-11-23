"""AASI Phase 4 evidence-ID gate for conclusion citations.

A conclusion may cite only evidence / proof / finding / observation IDs that
exist in the same tenant and engagement, are accessible, and are not
deleted or expired. Lookup is injectable so tests stay offline.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

ALLOWED_KINDS: frozenset[str] = frozenset(
    {"evidence", "proof", "finding", "observation"}
)

CitationLookup = Callable[[str], Mapping[str, Any] | None]


class EvidenceGateError(ValueError):
    """Raised when a conclusion citation fails the evidence-ID gate."""

    def __init__(
        self,
        message: str,
        *,
        reason: str,
        citation_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.citation_id = citation_id


def _truthy(record: Mapping[str, Any], *keys: str) -> bool:
    for key in keys:
        if key in record and record[key]:
            return True
    return False


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def assert_citations_valid(
    tenant_id: int,
    engagement_id: int,
    citations: Sequence[str],
    lookup_fn: CitationLookup,
) -> None:
    """Reject citations that are missing, cross-tenant/engagement, deleted, or expired.

    ``lookup_fn(citation_id)`` returns a mapping for an accessible record or
    ``None`` when the ID does not exist (or is invisible to the caller).
    Recognized record keys: ``tenant_id``, ``engagement_id``, ``kind`` /
    ``type``, ``deleted`` / ``is_deleted``, ``expired`` / ``is_expired``,
    ``accessible`` (defaults to true when omitted).

    Raises:
        EvidenceGateError: first failing citation, with ``reason`` set for audit.
    """
    try:
        tid = int(tenant_id)
        eid = int(engagement_id)
    except (TypeError, ValueError) as exc:
        raise EvidenceGateError(
            "tenant_id and engagement_id must be integers",
            reason="invalid_scope",
        ) from exc

    if tid < 1 or eid < 1:
        raise EvidenceGateError(
            "tenant_id and engagement_id must be positive",
            reason="invalid_scope",
        )

    if citations is None:
        return

    if isinstance(citations, (str, bytes)):
        raise EvidenceGateError(
            "citations must be a sequence of strings, not a bare string",
            reason="invalid_citations",
        )

    for raw in citations:
        if not isinstance(raw, str) or not raw.strip():
            raise EvidenceGateError(
                "citation id must be a non-empty string",
                reason="empty_citation",
                citation_id=str(raw) if raw is not None else None,
            )
        cid = raw.strip()
        record = lookup_fn(cid)
        if record is None:
            raise EvidenceGateError(
                f"citation not found: {cid!r}",
                reason="not_found",
                citation_id=cid,
            )
        if not isinstance(record, Mapping):
            raise EvidenceGateError(
                f"citation lookup returned non-mapping for {cid!r}",
                reason="invalid_record",
                citation_id=cid,
            )

        if "accessible" in record and not record["accessible"]:
            raise EvidenceGateError(
                f"citation not accessible: {cid!r}",
                reason="not_accessible",
                citation_id=cid,
            )

        rec_tenant = _as_int(record.get("tenant_id"))
        if rec_tenant is None or rec_tenant != tid:
            raise EvidenceGateError(
                f"citation tenant mismatch: {cid!r}",
                reason="tenant_mismatch",
                citation_id=cid,
            )

        rec_eng = _as_int(record.get("engagement_id"))
        if rec_eng is None or rec_eng != eid:
            raise EvidenceGateError(
                f"citation engagement mismatch: {cid!r}",
                reason="engagement_mismatch",
                citation_id=cid,
            )

        if _truthy(record, "deleted", "is_deleted"):
            raise EvidenceGateError(
                f"citation deleted: {cid!r}",
                reason="deleted",
                citation_id=cid,
            )

        if _truthy(record, "expired", "is_expired"):
            raise EvidenceGateError(
                f"citation expired: {cid!r}",
                reason="expired",
                citation_id=cid,
            )

        kind = str(record.get("kind") or record.get("type") or "").strip().lower()
        if kind and kind not in ALLOWED_KINDS:
            raise EvidenceGateError(
                f"citation kind not allowed: {cid!r} ({kind!r})",
                reason="invalid_kind",
                citation_id=cid,
            )


def lookup_from_records(
    records: Sequence[Mapping[str, Any]],
    *,
    id_keys: Sequence[str] = ("id", "evidence_id", "proof_id", "finding_id", "observation_id"),
) -> CitationLookup:
    """Build a ``lookup_fn`` from an in-memory list of citation records (tests / stubs)."""
    index: dict[str, Mapping[str, Any]] = {}
    for rec in records:
        if not isinstance(rec, Mapping):
            continue
        for key in id_keys:
            val = rec.get(key)
            if isinstance(val, str) and val.strip():
                index[val.strip()] = rec
            elif isinstance(val, int) and not isinstance(val, bool):
                index[str(val)] = rec
    return lambda cid: index.get((cid or "").strip())


__all__ = [
    "ALLOWED_KINDS",
    "CitationLookup",
    "EvidenceGateError",
    "assert_citations_valid",
    "lookup_from_records",
]
