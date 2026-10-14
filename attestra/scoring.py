"""Risk prioritization: CVSS x (1 + EPSS) x KEV x asset criticality x exposure.

The risk score ranks work. Reports still show CVSS as the severity of record.
"""

from __future__ import annotations

from datetime import date, timedelta

from attestra import config

# Used only when a tool gives a severity but no CVSS score.
DEFAULT_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0}


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def asset_weight(criticality: int | None) -> float:
    c = min(max(criticality or 3, 1), 5)
    return 0.6 + (c - 1) * 0.2  # 0.6 .. 1.4


def exposure_weight(exposure: str | None, in_cde: bool = False) -> float:
    return 1.3 if in_cde or exposure == "internet" else 1.0


def risk_score(
    cvss: float | None,
    severity: str,
    epss: float | None = None,
    kev: bool = False,
    criticality: int | None = None,
    exposure: str | None = None,
    in_cde: bool = False,
) -> float:
    base = cvss if cvss is not None else DEFAULT_CVSS.get(severity, 0.0)
    score = base * (1 + (epss or 0.0)) * (1.5 if kev else 1.0) * asset_weight(criticality) * exposure_weight(exposure, in_cde)
    return round(score, 2)


def sla_due(severity: str, from_day: date | None = None) -> date | None:
    days = config.SLA_DAYS.get(severity)
    if days is None:
        return None
    return (from_day or date.today()) + timedelta(days=days)
