"""Status transitions for Elite automated test executions."""

from __future__ import annotations

from attestra.automated_vapt import STATUSES
from attestra.models import AutomatedTestExecution, utcnow
from attestra.services import ServiceError

# @lat: [[architecture#Elite automated security testing#Execution status]]

_TRANSITIONS: dict[str, frozenset[str]] = {
    "QUEUED": frozenset({"RUNNING", "CANCELLED"}),
    "RUNNING": frozenset({"COMPLETED", "FAILED", "CANCELLED"}),
    "COMPLETED": frozenset(),
    "FAILED": frozenset(),
    "CANCELLED": frozenset(),
}


def assert_status(status: str) -> str:
    s = (status or "").strip().upper()
    if s not in STATUSES:
        raise ServiceError(f"invalid execution status: {status!r}")
    return s


def transition(ex: AutomatedTestExecution, to: str, *, error: str = "") -> AutomatedTestExecution:
    cur = assert_status(ex.status)
    nxt = assert_status(to)
    allowed = _TRANSITIONS.get(cur, frozenset())
    if nxt not in allowed:
        raise ServiceError(f"cannot move execution from {cur} to {nxt}")
    ex.status = nxt
    if nxt == "RUNNING" and ex.started_at is None:
        ex.started_at = utcnow()
    if nxt in ("COMPLETED", "FAILED", "CANCELLED"):
        ex.ended_at = utcnow()
    if error:
        ex.error = error[:2000]
    elif nxt in ("COMPLETED", "CANCELLED"):
        ex.error = ""
    return ex
