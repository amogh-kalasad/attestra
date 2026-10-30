"""Map validator status to confidence labels."""

from __future__ import annotations

from attestra.automated_vapt.validation.vulnerability_validator import (
    CONFIRMED,
    INCONCLUSIVE,
    NEEDS_MANUAL_REVIEW,
    NOT_VULNERABLE,
    POTENTIAL,
)


def confidence_for(status: str) -> str:
    s = (status or "").upper()
    if s == CONFIRMED:
        return "high"
    if s in (POTENTIAL, NOT_VULNERABLE):
        return "medium"
    if s in (INCONCLUSIVE, NEEDS_MANUAL_REVIEW):
        return "low"
    return "low"
