"""Map CWE / impact hints to Attestra severity labels."""

from __future__ import annotations

from typing import Any

_CWE_SEVERITY = {
    639: "high",  # IDOR
    862: "medium",  # Missing authorization
    863: "high",  # Incorrect authorization
    200: "medium",  # Exposure of sensitive information
    287: "high",  # Improper authentication
}


def severity_for(*, cwe: int | None = None, impact: str = "", hints: dict[str, Any] | None = None) -> str:
    hints = hints or {}
    if hints.get("protected_data_exposed") or hints.get("authorization_bypass"):
        return "high"
    if cwe in _CWE_SEVERITY:
        return _CWE_SEVERITY[cwe]
    impact_l = (impact or "").lower()
    if "critical" in impact_l:
        return "critical"
    if "high" in impact_l:
        return "high"
    if "low" in impact_l:
        return "low"
    if "info" in impact_l:
        return "info"
    return "medium"
