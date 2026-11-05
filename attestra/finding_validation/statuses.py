# @lat: [[findings#Lifecycle#Validation class vs workflow status]]
"""Validation-class constants for findings (separate from workflow status)."""

from __future__ import annotations

UNVALIDATED = "unvalidated"
CONFIRMED = "confirmed"
NEEDS_MANUAL_VALIDATION = "needs_manual_validation"
POTENTIAL = "potential"
FALSE_POSITIVE = "false_positive"
INFORMATIONAL = "informational"
NOT_REPRODUCIBLE = "not_reproducible"
ACCEPTED_RISK = "accepted_risk"

VALIDATION_STATUSES: frozenset[str] = frozenset(
    {
        UNVALIDATED,
        CONFIRMED,
        NEEDS_MANUAL_VALIDATION,
        POTENTIAL,
        FALSE_POSITIVE,
        INFORMATIONAL,
        NOT_REPRODUCIBLE,
        ACCEPTED_RISK,
    }
)

VALIDATION_STATUS_LABELS: dict[str, str] = {
    UNVALIDATED: "Unvalidated",
    CONFIRMED: "Confirmed",
    NEEDS_MANUAL_VALIDATION: "Needs manual validation",
    POTENTIAL: "Potential",
    FALSE_POSITIVE: "False positive",
    INFORMATIONAL: "Informational",
    NOT_REPRODUCIBLE: "Not reproducible",
    ACCEPTED_RISK: "Accepted risk",
}
