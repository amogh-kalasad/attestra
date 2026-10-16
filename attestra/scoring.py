"""Risk prioritization: CVSS x (1 + EPSS) x KEV x asset criticality x exposure.

The risk score ranks work. Reports still show CVSS as the severity of record.
Tenants may override the criticality and exposure weights (Phase 7.4, see
attestra.tuning); without an override the defaults below apply.
"""
# @lat: [[findings#Risk score]]

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta

from attestra import config

# Used only when a tool gives a severity but no CVSS score.
# Info stays 0 for internal assets; internet-facing Info uses INFO_INTERNET_BASE in risk_score.
DEFAULT_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0}
# Small base so Info on internet-facing (or CDE) assets is never risk 0 after exposure weight.
INFO_INTERNET_BASE = 1.0
DEFAULT_EXPOSURE_WEIGHT = 1.3


@dataclass(frozen=True)
class RiskWeights:
    """Per-tenant overrides. Missing criticality levels fall back to the default curve."""

    criticality: dict[int, float] = field(default_factory=dict)
    internet: float = DEFAULT_EXPOSURE_WEIGHT
    cde: float = DEFAULT_EXPOSURE_WEIGHT


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


def asset_weight(criticality: int | None, weights: RiskWeights | None = None) -> float:
    c = min(max(criticality or 3, 1), 5)
    if weights is not None and c in weights.criticality:
        return weights.criticality[c]
    return 0.6 + (c - 1) * 0.2  # 0.6 .. 1.4


def exposure_weight(exposure: str | None, in_cde: bool = False, weights: RiskWeights | None = None) -> float:
    if weights is None:
        return DEFAULT_EXPOSURE_WEIGHT if in_cde or exposure == "internet" else 1.0
    factors = [1.0]
    if exposure == "internet":
        factors.append(weights.internet)
    if in_cde:
        factors.append(weights.cde)
    return max(factors)


def risk_score(
    cvss: float | None,
    severity: str,
    epss: float | None = None,
    kev: bool = False,
    criticality: int | None = None,
    exposure: str | None = None,
    in_cde: bool = False,
    weights: RiskWeights | None = None,
) -> float:
    base = cvss if cvss is not None else DEFAULT_CVSS.get(severity, 0.0)
    # C7: Info on internet-facing or CDE assets gets a small base so risk is never 0.
    if (
        base == 0.0
        and (severity or "").lower() == "info"
        and (exposure == "internet" or in_cde)
    ):
        base = INFO_INTERNET_BASE
    score = (
        base * (1 + (epss or 0.0)) * (1.5 if kev else 1.0)
        * asset_weight(criticality, weights) * exposure_weight(exposure, in_cde, weights)
    )
    return round(score, 2)


def sla_due(severity: str, from_day: date | None = None) -> date | None:
    days = config.SLA_DAYS.get(severity)
    if days is None:
        return None
    return (from_day or date.today()) + timedelta(days=days)
