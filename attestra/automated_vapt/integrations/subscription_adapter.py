"""One test-run credit per Elite automated execution (not per screenshot/HTTP call)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from attestra import config
from attestra.credits.service import balance_view, consume_for_scan_admit
from attestra.models import CreditTransaction
from attestra.services import ServiceError

# @lat: [[architecture#Elite automated security testing#Subscription credits]]


def ensure_credit_for_execution(
    s: Session,
    *,
    tenant_id: int,
    engagement_id: int,
    execution_id: int,
    actor: str,
    user_id: int | None = None,
) -> CreditTransaction | None:
    """Consume one credit when SUBSCRIPTION_SERVICE=ON; no-op when OFF."""
    if not config.subscription_enforcement_enabled():
        return None
    if balance_view(s, tenant_id, actor=actor)["exhausted"]:
        raise ServiceError(
            "The organization has exhausted its available test-run credits. "
            "Request additional credits or ask a Super Admin to allocate more."
        )
    return consume_for_scan_admit(
        s,
        tenant_id,
        actor=actor,
        engagement_id=engagement_id,
        user_id=user_id,
        idempotency_key=f"elite-exec:{execution_id}",
    )
