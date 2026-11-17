"""Guided business-flow plan templates (D-05).

Business-logic flaws (price tampering, workflow skipping, approval bypass, coupon
replay) depend on application semantics that automation cannot infer safely. These
templates give a tester a step list, the evidence to capture, and the checklist
references the result maps to. They are **evidence-only**: this module never sends
a request, and a plan's result is only what the tester records (status from the
standard vocabulary plus evidence ids). Off by default: nothing calls this module
until the INT/UI wiring in ``WIRING_WP1.md`` lands.
"""

# @lat: [[run-validity-and-policy#Guided business-flow plans]]

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

PLAN_VERSION = "guided-1"
RESULT_STATUSES = ("PASSED", "FINDING", "BLOCKED", "INCONCLUSIVE", "NOT_TESTED")


@dataclass(frozen=True)
class Step:
    action: str
    evidence: str
    destructive: bool = False


@dataclass(frozen=True)
class Plan:
    plan_id: str
    title: str
    checklist_refs: tuple[str, ...]
    preconditions: tuple[str, ...]
    steps: tuple[Step, ...]
    pass_criteria: str
    finding_criteria: str
    needs_two_identities: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        d["version"] = PLAN_VERSION
        d["has_destructive_steps"] = any(s.destructive for s in self.steps)
        return d


PLANS: tuple[Plan, ...] = (
    Plan(
        "BF-WORKFLOW-SKIP",
        "Workflow step skipping",
        ("WSTG-BUSL-06",),
        ("A multi-step flow exists (checkout, onboarding, approval)", "Test account on a dev/demo environment"),
        (
            Step("Complete the flow once normally; note each step's request", "HAR or request list (tokens redacted)"),
            Step("Replay only the final step's request without the intermediate steps", "Final-step response status/body excerpt"),
            Step("Confirm whether server state advanced (order created, status changed)", "Screenshot or API read of resulting state", True),
        ),
        "Server rejects the out-of-order request or state is unchanged",
        "Final step succeeds and state advances without prior steps",
        tags=("workflow",),
    ),
    Plan(
        "BF-PARAM-TAMPER",
        "Client-controlled price / quantity / role parameters",
        ("WSTG-BUSL-01", "WSTG-BUSL-02"),
        ("A request carries a price, quantity, discount or role field", "Test account on a dev/demo environment"),
        (
            Step("Identify server-trusted fields in the request body", "Field names only"),
            Step("Change one field to an implausible value (negative quantity, 0 price)", "Request diff (field names/values, no tokens)", True),
            Step("Read back the resulting object as the same user", "Response excerpt showing the stored value"),
        ),
        "Server recomputes or rejects the tampered value",
        "Tampered value is stored or honoured",
        tags=("integrity",),
    ),
    Plan(
        "BF-REPLAY-LIMIT",
        "Single-use action replay (coupon, invite, reset link)",
        ("WSTG-BUSL-05", "WSTG-BUSL-07"),
        ("A single-use token or once-per-user action exists",),
        (
            Step("Perform the action once", "Response status"),
            Step("Repeat the identical request (max 3 times, spaced)", "Response statuses", True),
        ),
        "Repeat attempts are refused",
        "The action applies more than once",
        tags=("replay",),
    ),
    Plan(
        "BF-APPROVAL-BYPASS",
        "Approval / maker-checker bypass across roles",
        ("WSTG-ATHZ-02", "WSTG-BUSL-06"),
        ("Two authorized test identities with different roles",),
        (
            Step("As the requester, create an item needing approval", "Item id (no personal data)"),
            Step("As the requester, call the approve endpoint for that item", "Response status/body excerpt", True),
            Step("As the approver, confirm the item's state", "Response excerpt"),
        ),
        "Requester cannot approve their own item",
        "Requester's approve call changes state",
        needs_two_identities=True,
        tags=("authorization",),
    ),
    Plan(
        "BF-OBJECT-OWNERSHIP",
        "Cross-identity object access in a business flow",
        ("WSTG-ATHZ-04",),
        ("Two authorized test identities in different tenants or owners",),
        (
            Step("As identity A, create or locate an object; note its id", "Object id"),
            Step("As identity B, read and then attempt to update that object id", "Response statuses/body excerpts", True),
        ),
        "Identity B is denied (403/404) with an application answer, not a WAF page",
        "Identity B reads or changes identity A's object",
        needs_two_identities=True,
        tags=("authorization",),
    ),
)


def list_plans(*, two_identities_available: bool | None = None) -> list[dict[str, Any]]:
    out = []
    for p in PLANS:
        d = p.to_json()
        if two_identities_available is False and p.needs_two_identities:
            d["available"] = False
            d["unavailable_reason"] = "needs_two_identities"
        else:
            d["available"] = True
        out.append(d)
    return out


def get_plan(plan_id: str) -> Plan | None:
    return next((p for p in PLANS if p.plan_id == plan_id), None)


def record_result(plan_id: str, status: str, *, evidence_ids: list[str] | None = None, note: str = "") -> dict[str, Any]:
    """Build the value a tester submits. A FINDING / PASSED needs at least one evidence id."""
    plan = get_plan(plan_id)
    if plan is None:
        raise ValueError(f"unknown guided plan: {plan_id}")
    status = (status or "").upper()
    if status not in RESULT_STATUSES:
        raise ValueError(f"status must be one of {RESULT_STATUSES}")
    ev = [str(e) for e in (evidence_ids or []) if str(e).strip()]
    if status in ("PASSED", "FINDING") and not ev:
        raise ValueError("PASSED/FINDING guided results need evidence")
    return {
        "plan_id": plan_id,
        "version": PLAN_VERSION,
        "status": status,
        "checklist_refs": list(plan.checklist_refs),
        "evidence_ids": ev,
        "note": (note or "")[:2000],
        "source": "guided",
    }
