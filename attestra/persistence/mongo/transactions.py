"""MongoDB session / transaction helpers with retry classification."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TypeVar

from pymongo.client_session import ClientSession
from pymongo.errors import ConnectionFailure, OperationFailure

from attestra.persistence.mongo.client import get_client

log = logging.getLogger("attestra.persistence.mongo")

T = TypeVar("T")

# Transient labels commonly used by MongoDB for retryable writes / transactions.
_RETRYABLE_CODES = {6, 7, 89, 91, 189, 262, 9001, 10107, 11600, 11602, 13435, 13436, 13388, 13340}


def is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, ConnectionFailure):
        return True
    if isinstance(exc, OperationFailure):
        if getattr(exc, "has_error_label", None) and (
            exc.has_error_label("TransientTransactionError") or exc.has_error_label("UnknownTransactionCommitResult")
        ):
            return True
        return int(getattr(exc, "code", 0) or 0) in _RETRYABLE_CODES
    return False


def with_transaction(fn: Callable[[ClientSession], T], *, retries: int = 5) -> T:
    """Run ``fn(session)`` inside a multi-document transaction with retries."""
    client = get_client()
    last: BaseException | None = None
    for attempt in range(1, retries + 1):
        try:
            with client.start_session() as session:
                return session.with_transaction(fn)
        except Exception as exc:  # noqa: BLE001 — classify then re-raise
            last = exc
            if attempt < retries and is_retryable(exc):
                log.warning("mongo_txn_retry attempt=%s error=%s", attempt, type(exc).__name__)
                continue
            raise
    assert last is not None
    raise last
