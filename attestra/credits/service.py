"""Organization-wide test-run credit ledger and admission checks.

Credits belong to the tenant (organization). Engagement create/edit/view and
report downloads do not consume credits. One credit is consumed when a scan is
successfully admitted in [[attestra/services.py#request_scan]].
"""
# @lat: [[interfaces#Configuration#Organization test-run credits]]

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from attestra import audit, config
from attestra.models import CreditRenewalRequest, CreditTransaction, TenantCreditAccount, utcnow


def _service_error(message: str) -> Exception:
    from attestra.services import ServiceError

    return ServiceError(message)

REASON_INITIAL = "initial_grant"
REASON_SCAN_ADMIT = "scan_admit"
REASON_REFUND_PRE_START = "refund_pre_start"
REASON_REFUND_POST_START = "refund_post_start"
REASON_ADMIN_ALLOCATE = "admin_allocate"
REASON_RENEWAL_APPROVE = "renewal_approve"


def ensure_account(s: Session, tenant_id: int, *, actor: str = "system") -> TenantCreditAccount:
    """Return the tenant credit account, creating it with the configured initial grant if missing."""
    from attestra.persistence.mongo.adapters import mongo_credit_account

    doc = mongo_credit_account(tenant_id)
    return TenantCreditAccount(tenant_id=tenant_id, balance=int(doc["balance"]), grant_total=int(doc.get("grant_total") or 0))


def get_balance(s: Session, tenant_id: int, *, actor: str = "system") -> TenantCreditAccount:
    """Ensure and return the organization credit account."""
    return ensure_account(s, tenant_id, actor=actor)


def balance_view(s: Session, tenant_id: int, *, actor: str = "system") -> dict:
    """Server-sourced balance payload for UI/API (tenant-scoped)."""
    acct = ensure_account(s, tenant_id, actor=actor)
    enforcing = config.subscription_enforcement_enabled()
    return {
        "tenant_id": tenant_id,
        "balance": acct.balance,
        "grant_total": acct.grant_total,
        "enforcement": enforcing,
        "label": (
            f"Organization Credits: {acct.balance} / {acct.grant_total} remaining"
            if enforcing
            else f"Organization Credits: {acct.balance} / {acct.grant_total} (informational — subscription enforcement off)"
        ),
        "exhausted": enforcing and acct.balance < 1,
        "can_run_tests": (not enforcing) or acct.balance >= 1,
    }


def consume_for_scan_admit(
    s: Session,
    tenant_id: int,
    *,
    actor: str,
    engagement_id: int,
    user_id: int | None = None,
    idempotency_key: str | None = None,
) -> CreditTransaction | None:
    """Atomically consume one credit for a successfully gated scan admission.

    Returns ``None`` when ``SUBSCRIPTION_SERVICE=OFF`` (no charge). Raises
    [[attestra/services.py#ServiceError]] when enforcement is on and the balance
    is exhausted. Repeated calls with the same idempotency key return the prior
    ledger row without a second debit.
    """
    from attestra.persistence.mongo.adapters import mongo_consume_credit

    doc = mongo_consume_credit(
        tenant_id,
        actor=actor,
        engagement_id=engagement_id,
        user_id=user_id,
        idempotency_key=idempotency_key,
    )
    if doc is None:
        return None
    tx = CreditTransaction(
        tenant_id=tenant_id,
        amount=doc["amount"],
        balance_after=doc["balance_after"],
        reason=doc["reason"],
        actor=actor,
        user_id=user_id,
        engagement_id=engagement_id,
        idempotency_key=idempotency_key,
    )
    tx.id = doc["id"]
    return tx


def attach_scan_run(s: Session, tx: CreditTransaction | None, scan_run_id: int) -> None:
    """Link a debit ledger row to the admitted scan run id."""
    if tx is None:
        return
    from attestra.persistence.mongo.adapters import mongo_attach_credit_scan_run

    mongo_attach_credit_scan_run(tx.id, scan_run_id)
    tx.scan_run_id = scan_run_id


def refund_for_scan(
    s: Session,
    tenant_id: int,
    *,
    actor: str,
    scan_run_id: int | None,
    engagement_id: int | None = None,
    debit_tx: CreditTransaction | None = None,
    post_start: bool = False,
    note: str = "",
) -> CreditTransaction | None:
    """Refund one credit per documented pre-start or post-start policy."""
    if debit_tx is None:
        return None
    if not config.subscription_enforcement_enabled():
        return None
    if post_start and not config.CREDIT_REFUND_ON_POST_START_FAILURE:
        return None
    if (not post_start) and not config.CREDIT_REFUND_ON_PRE_START_FAILURE:
        return None
    reason = REASON_REFUND_POST_START if post_start else REASON_REFUND_PRE_START
    from attestra.persistence.mongo.adapters import mongo_refund_credit

    doc = mongo_refund_credit(
        tenant_id, actor=actor, debit_tx_id=debit_tx.id, reason=reason,
        scan_run_id=scan_run_id, engagement_id=engagement_id, note=note,
    )
    if doc is None:
        return None
    rtx = CreditTransaction(
        tenant_id=tenant_id, amount=doc["amount"], balance_after=doc["balance_after"], reason=reason,
        actor=actor, engagement_id=engagement_id, idempotency_key=doc.get("idempotency_key"),
    )
    rtx.id = doc["id"]
    return rtx


def allocate_credits(
    s: Session,
    tenant_id: int,
    *,
    amount: int,
    actor: str,
    note: str = "",
    user_id: int | None = None,
    renewal_request_id: int | None = None,
    reason: str = REASON_ADMIN_ALLOCATE,
    idempotency_key: str | None = None,
) -> CreditTransaction:
    """Admin grant of credits to an organization (audited)."""
    if amount < 1:
        raise _service_error("allocation amount must be at least 1")
    from attestra.persistence.mongo.adapters import mongo_allocate_credits

    doc = mongo_allocate_credits(
        tenant_id, amount, actor=actor, note=note, user_id=user_id,
        renewal_request_id=renewal_request_id, reason=reason, idempotency_key=idempotency_key,
    )
    atx = CreditTransaction(
        tenant_id=tenant_id, amount=doc["amount"], balance_after=doc["balance_after"], reason=reason,
        actor=actor, user_id=user_id, idempotency_key=idempotency_key,
    )
    atx.id = doc["id"]
    return atx


def request_renewal(
    s: Session,
    tenant_id: int,
    *,
    credits_requested: int,
    actor: str,
    user_id: int | None = None,
    note: str = "",
    idempotency_key: str | None = None,
) -> CreditRenewalRequest:
    """Open a renewal/additional-credit request (no payment simulation)."""
    if credits_requested < 1:
        raise _service_error("credits_requested must be at least 1")
    if idempotency_key:
        existing = s.scalar(
            select(CreditRenewalRequest).where(CreditRenewalRequest.idempotency_key == idempotency_key)
        )
        if existing is not None:
            return existing
    ensure_account(s, tenant_id, actor=actor)
    row = CreditRenewalRequest(
        tenant_id=tenant_id,
        requested_by=actor,
        requested_by_user_id=user_id,
        credits_requested=credits_requested,
        status="pending",
        note=note or "",
        created_at=utcnow(),
        idempotency_key=idempotency_key,
    )
    s.add(row)
    s.flush()
    audit.record(
        s,
        actor,
        "credits.renewal_request",
        "credit_renewal_request",
        row.id,
        tenant_id=tenant_id,
        credits_requested=credits_requested,
    )
    return row


def resolve_renewal(
    s: Session,
    request_id: int,
    *,
    approve: bool,
    actor: str,
    admin_note: str = "",
    allocate_amount: int | None = None,
) -> CreditRenewalRequest:
    """Super Admin approves (allocates) or rejects a renewal request."""
    row = s.get(CreditRenewalRequest, request_id)
    if row is None:
        raise LookupError(f"renewal request {request_id} not found")
    if row.status != "pending":
        raise _service_error(f"renewal request is already {row.status}")
    row.resolved_by = actor
    row.resolved_at = utcnow()
    row.admin_note = admin_note or ""
    if approve:
        amount = allocate_amount if allocate_amount is not None else row.credits_requested
        allocate_credits(
            s,
            row.tenant_id,
            amount=amount,
            actor=actor,
            note=admin_note or f"Approved renewal request #{row.id}",
            renewal_request_id=row.id,
            reason=REASON_RENEWAL_APPROVE,
            idempotency_key=f"renewal_approve:{row.id}",
        )
        row.status = "approved"
    else:
        row.status = "rejected"
    s.flush()
    audit.record(
        s,
        actor,
        "credits.renewal_resolve",
        "credit_renewal_request",
        row.id,
        tenant_id=row.tenant_id,
        status=row.status,
        approve=approve,
    )
    return row


def list_renewal_requests(
    s: Session,
    *,
    tenant_id: int | None = None,
    status: str | None = "pending",
) -> list[CreditRenewalRequest]:
    """List renewal requests, optionally filtered by tenant and status."""
    q = select(CreditRenewalRequest).order_by(CreditRenewalRequest.id.desc())
    if tenant_id is not None:
        q = q.where(CreditRenewalRequest.tenant_id == tenant_id)
    if status:
        q = q.where(CreditRenewalRequest.status == status)
    return list(s.scalars(q))
