"""One-time, four-eyes approvals for supervised production safe-mutation (Gap #3).

Independent of the ordinary ``dev``/``demo`` intrusive allowlist. Default-deny:
production mutations require ``ATTESTRA_AUTOMATED_VAPT_PRODUCTION_SAFE_MUTATION``
plus a consumed-once approval that names the exact asset, origin, endpoint,
method, synthetic test record, fields, and cleanup plan.

Never accepts AASI/scanner booleans as approval. Requester cannot approve self.
"""
# @lat: [[run-validity-and-policy#Intrusive policy]]

from __future__ import annotations

import json
import os
import secrets
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

APPROVER_ROLES = frozenset({"lead", "admin", "super_admin"})
REQUESTER_ROLES = frozenset({"tester", "lead", "admin", "super_admin"})
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})
STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_CONSUMED = "consumed"
STATUS_EXPIRED = "expired"
STATUS_REVOKED = "revoked"
STATUS_DENIED = "denied"

DEFAULT_TTL_MINUTES = 60
MAX_MUTATION_REQUESTS = 3


class MutationApprovalError(ValueError):
    """Invalid approval request or transition."""


@dataclass
class MutationApproval:
    id: str
    tenant_id: int
    engagement_id: int
    asset_id: int
    requester: str
    requester_user_id: int | None
    requester_role: str
    target_origin: str
    endpoint_pattern: str
    http_method: str
    test_record_id: str
    approved_fields: list[str]
    approved_values: dict[str, Any] = field(default_factory=dict)
    cleanup_plan: str = ""
    expected_behavior: str = ""
    test_case_id: str = "T22"
    execution_id: int | None = None
    status: str = STATUS_PENDING
    nonce: str = ""
    approver: str = ""
    approver_user_id: int | None = None
    approver_role: str = ""
    created_at: str = ""
    approved_at: str = ""
    expires_at: str = ""
    consumed_at: str = ""
    restore_verified: bool | None = None
    restore_notes: str = ""

    def to_public(self) -> dict[str, Any]:
        """Value-free-ish public view (no secrets; values may be synthetic test data)."""
        d = asdict(self)
        # Cap approved_values size in public views
        vals = d.get("approved_values") or {}
        if isinstance(vals, dict) and len(json.dumps(vals, default=str)) > 2000:
            d["approved_values"] = {"_truncated": True, "keys": sorted(vals.keys())[:40]}
        return d


class ApprovalStore:
    """JSON file store under ``<data>/mutation_approvals`` (no schema migration)."""

    def __init__(self, root: Path | None = None):
        if root is None:
            from attestra.config import DATA_DIR

            root = DATA_DIR / "mutation_approvals"
        self.root = Path(root)
        self._lock = threading.Lock()

    def _file(self, engagement_id: int) -> Path:
        return self.root / f"engagement_{int(engagement_id)}.json"

    def list(self, engagement_id: int) -> list[MutationApproval]:
        f = self._file(engagement_id)
        if not f.exists():
            return []
        rows = json.loads(f.read_text(encoding="utf-8"))
        return [MutationApproval(**r) for r in rows]

    def _save(self, engagement_id: int, rows: list[MutationApproval]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self._file(engagement_id).write_text(
            json.dumps([asdict(r) for r in rows], indent=2, default=str),
            encoding="utf-8",
        )

    def get(self, engagement_id: int, approval_id: str) -> MutationApproval | None:
        for r in self.list(engagement_id):
            if r.id == approval_id:
                return r
        return None

    def add(self, row: MutationApproval) -> MutationApproval:
        with self._lock:
            rows = self.list(row.engagement_id)
            rows.append(row)
            self._save(row.engagement_id, rows)
        return row

    def update(self, engagement_id: int, approval_id: str, **changes: Any) -> MutationApproval:
        with self._lock:
            rows = self.list(engagement_id)
            for r in rows:
                if r.id == approval_id:
                    for k, v in changes.items():
                        setattr(r, k, v)
                    self._save(engagement_id, rows)
                    return r
        raise MutationApprovalError(f"approval {approval_id} not found")


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def _parse_iso(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def production_safe_mutation_enabled() -> bool:
    from attestra import config

    return bool(getattr(config, "AUTOMATED_VAPT_PRODUCTION_SAFE_MUTATION", False))


def normalize_origin(url: str) -> str:
    parts = urlsplit((url or "").strip())
    if not parts.scheme or not parts.netloc:
        raise MutationApprovalError("target_origin must be an absolute http(s) URL")
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def normalize_endpoint(path: str) -> str:
    p = (path or "").strip() or "/"
    if not p.startswith("/"):
        p = "/" + p
    # No query in pattern storage — compare path only
    return p.split("?", 1)[0].split("#", 1)[0]


def request_approval(
    store: ApprovalStore,
    *,
    tenant_id: int,
    engagement_id: int,
    asset_id: int,
    requester: str,
    requester_user_id: int | None,
    requester_role: str,
    target_origin: str,
    endpoint_pattern: str,
    http_method: str,
    test_record_id: str,
    approved_fields: list[str],
    approved_values: dict[str, Any] | None = None,
    cleanup_plan: str,
    expected_behavior: str = "",
    ttl_minutes: int = DEFAULT_TTL_MINUTES,
    test_case_id: str = "T22",
    execution_id: int | None = None,
) -> MutationApproval:
    """Create a pending approval. Does not enable mutation by itself."""
    role = (requester_role or "").strip().lower()
    if role not in REQUESTER_ROLES:
        raise MutationApprovalError("requester role cannot request production safe-mutation")
    method = (http_method or "").strip().upper()
    if method not in WRITE_METHODS:
        raise MutationApprovalError("http_method must be POST, PUT, or PATCH (DELETE forbidden)")
    if method == "DELETE":
        raise MutationApprovalError("DELETE is never allowed")
    fields = [str(f).strip() for f in (approved_fields or []) if str(f).strip()]
    if not fields:
        raise MutationApprovalError("approved_fields required")
    record = str(test_record_id or "").strip()
    if not record:
        raise MutationApprovalError("test_record_id (synthetic disposable record) required")
    plan = (cleanup_plan or "").strip()
    if len(plan) < 8:
        raise MutationApprovalError("cleanup_plan required (restoration steps)")
    origin = normalize_origin(target_origin)
    endpoint = normalize_endpoint(endpoint_pattern)
    now = _now()
    ttl = max(5, min(int(ttl_minutes or DEFAULT_TTL_MINUTES), 24 * 60))
    row = MutationApproval(
        id=secrets.token_hex(8),
        tenant_id=int(tenant_id),
        engagement_id=int(engagement_id),
        asset_id=int(asset_id),
        requester=(requester or "").strip() or "unknown",
        requester_user_id=requester_user_id,
        requester_role=role,
        target_origin=origin,
        endpoint_pattern=endpoint,
        http_method=method,
        test_record_id=record,
        approved_fields=fields,
        approved_values=dict(approved_values or {}),
        cleanup_plan=plan,
        expected_behavior=(expected_behavior or "").strip()[:500],
        test_case_id=(test_case_id or "T22").upper(),
        execution_id=execution_id,
        status=STATUS_PENDING,
        nonce=secrets.token_urlsafe(24),
        created_at=_iso(now),
        expires_at=_iso(now + timedelta(minutes=ttl)),
    )
    return store.add(row)


def approve_approval(
    store: ApprovalStore,
    *,
    engagement_id: int,
    approval_id: str,
    approver: str,
    approver_user_id: int | None,
    approver_role: str,
    tenant_id: int | None = None,
) -> MutationApproval:
    """Four-eyes approve. Requester cannot approve their own request."""
    row = store.get(engagement_id, approval_id)
    if row is None:
        raise MutationApprovalError("approval not found")
    if tenant_id is not None and int(tenant_id) != int(row.tenant_id):
        raise MutationApprovalError("cross-tenant approval access denied")
    if row.status != STATUS_PENDING:
        raise MutationApprovalError(f"approval status is {row.status}")
    if _parse_iso(row.expires_at) <= _now():
        store.update(engagement_id, approval_id, status=STATUS_EXPIRED)
        raise MutationApprovalError("approval expired")
    role = (approver_role or "").strip().lower()
    if role not in APPROVER_ROLES:
        raise MutationApprovalError("approver role cannot approve production safe-mutation")
    # Separation of duties
    if approver_user_id is not None and row.requester_user_id is not None:
        if int(approver_user_id) == int(row.requester_user_id):
            raise MutationApprovalError("requester cannot approve their own production mutation")
    if (approver or "").strip() and (approver or "").strip().lower() == (row.requester or "").strip().lower():
        raise MutationApprovalError("requester cannot approve their own production mutation")
    return store.update(
        engagement_id,
        approval_id,
        status=STATUS_APPROVED,
        approver=(approver or "").strip(),
        approver_user_id=approver_user_id,
        approver_role=role,
        approved_at=_iso(_now()),
    )


def _match_endpoint(pattern: str, path: str) -> bool:
    p = normalize_endpoint(pattern)
    cand = normalize_endpoint(path)
    if p.endswith("*"):
        return cand.startswith(p[:-1])
    return cand == p


def validate_grant_for_execution(
    row: MutationApproval,
    *,
    tenant_id: int,
    engagement_id: int,
    asset_id: int,
    target_origin: str,
    endpoint: str,
    http_method: str,
    test_record_id: str,
    fields: list[str] | None = None,
) -> tuple[bool, str]:
    """Return (ok, reason_code). Does not consume."""
    if not production_safe_mutation_enabled():
        return False, "production_safe_mutation_flag_off"
    if int(row.tenant_id) != int(tenant_id):
        return False, "tenant_mismatch"
    if int(row.engagement_id) != int(engagement_id):
        return False, "engagement_mismatch"
    if int(row.asset_id) != int(asset_id):
        return False, "asset_mismatch"
    if row.status == STATUS_CONSUMED:
        return False, "approval_consumed"
    if row.status == STATUS_EXPIRED or _parse_iso(row.expires_at) <= _now():
        return False, "approval_expired"
    if row.status != STATUS_APPROVED:
        return False, f"approval_status_{row.status}"
    try:
        origin = normalize_origin(target_origin)
    except MutationApprovalError:
        return False, "origin_invalid"
    if origin != row.target_origin:
        return False, "origin_mismatch"
    method = (http_method or "").strip().upper()
    if method == "DELETE":
        return False, "delete_forbidden"
    if method != row.http_method:
        return False, "method_mismatch"
    if not _match_endpoint(row.endpoint_pattern, endpoint):
        return False, "endpoint_mismatch"
    if str(test_record_id or "").strip() != row.test_record_id:
        return False, "record_mismatch"
    if fields:
        allowed = set(row.approved_fields)
        bad = [f for f in fields if f not in allowed]
        if bad:
            return False, "unapproved_fields"
    return True, "allowed"


def consume_approval(
    store: ApprovalStore,
    *,
    engagement_id: int,
    approval_id: str,
    nonce: str,
    tenant_id: int | None = None,
) -> MutationApproval:
    """One-time consume. Replay of the same nonce/id fails after first use."""
    row = store.get(engagement_id, approval_id)
    if row is None:
        raise MutationApprovalError("approval not found")
    if tenant_id is not None and int(tenant_id) != int(row.tenant_id):
        raise MutationApprovalError("cross-tenant approval access denied")
    if row.status == STATUS_CONSUMED:
        raise MutationApprovalError("approval already consumed")
    if _parse_iso(row.expires_at) <= _now():
        store.update(engagement_id, approval_id, status=STATUS_EXPIRED)
        raise MutationApprovalError("approval expired")
    if row.status != STATUS_APPROVED:
        raise MutationApprovalError(f"approval status is {row.status}")
    if not nonce or not secrets.compare_digest(str(nonce), str(row.nonce)):
        raise MutationApprovalError("approval nonce mismatch")
    return store.update(
        engagement_id,
        approval_id,
        status=STATUS_CONSUMED,
        consumed_at=_iso(_now()),
        nonce=secrets.token_urlsafe(24),  # rotate — old nonce cannot replay
    )


def filter_body_to_approved_fields(body: dict[str, Any], approved_fields: list[str]) -> dict[str, Any]:
    """Keep only approved top-level keys (plus nested paths with dotted names)."""
    allowed = set(approved_fields)
    out: dict[str, Any] = {}
    for k, v in (body or {}).items():
        if k in allowed:
            out[k] = v
    return out


def apply_approved_values(
    body: dict[str, Any],
    *,
    approved_fields: list[str],
    approved_values: dict[str, Any],
    test_record_id: str,
) -> dict[str, Any]:
    """Build a mutation body from registered parameters only (no arbitrary injection)."""
    out = filter_body_to_approved_fields(body, approved_fields)
    for k in approved_fields:
        if k in approved_values:
            out[k] = approved_values[k]
    # Bind synthetic record id into common id keys when approved
    for key in ("id", "record_id", "test_record_id"):
        if key in approved_fields:
            out[key] = test_record_id
    return out


def record_restore_result(
    store: ApprovalStore,
    *,
    engagement_id: int,
    approval_id: str,
    verified: bool,
    notes: str = "",
) -> MutationApproval:
    """Persist restoration verification. Failed restore must stop further mutations (caller)."""
    note = (notes or "").strip()[:1000]
    if not verified:
        note = (note or "restoration verification failed").strip()
    return store.update(
        engagement_id,
        approval_id,
        restore_verified=bool(verified),
        restore_notes=note,
    )
