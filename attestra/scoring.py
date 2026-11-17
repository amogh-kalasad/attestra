"""Risk prioritization: CVSS x (1 + EPSS) x KEV x asset criticality x exposure.

``risk_score`` is **priority / business risk** ranking — not a second CVSS.
Technical severity of record remains ``Finding.severity`` plus ``cvss_score`` /
``cvss_vector``. Tenants may override criticality and exposure weights
(Phase 7.4, see attestra.tuning); without an override the defaults below apply.
"""
# @lat: [[findings#Risk score]]

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, timedelta

from attestra import config

# Soft shape check for CVSS 3.x and 4.0 vectors (empty allowed; garbage rejected).
# CVSS 4.0 vectors are scored by the pure-Python FIRST calculator in attestra.intel.cvss4
# (G-03); CVSS 3.x keeps the scanner-provided score.
# @lat: [[findings#CVSS vector]]
_CVSS_VECTOR_RE = re.compile(r"^CVSS:(3\.\d+|4\.0)/[A-Za-z0-9:./_]+$")
_CVSS_VERSION_RE = re.compile(r"^CVSS:(\d+(?:\.\d+)?)/", re.IGNORECASE)

# Used only when a tool gives a severity but no CVSS score.
# Info stays 0 for internal assets; internet-facing Info uses INFO_INTERNET_BASE in risk_score.
DEFAULT_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0}
# Small base so Info on internet-facing (or CDE) assets is never risk 0 after exposure weight.
INFO_INTERNET_BASE = 1.0
DEFAULT_EXPOSURE_WEIGHT = 1.3
KEV_FACTOR = 1.5

# Priority / business-risk bands on computed ``risk_score`` (not CVSS).
# Same cut-points as severity_from_cvss for familiarity; values can exceed 10
# when EPSS / KEV / asset / exposure multipliers apply.
#   critical: >= 9.0
#   high:     >= 7.0
#   medium:   >= 4.0
#   low:      >  0.0
#   info:     == 0.0
BUSINESS_RISK_BANDS = ("critical", "high", "medium", "low", "info")

# G-04: version of the explanation schema / formula. The numeric ``risk_score`` formula
# is unchanged from the pre-versioned code ("risk-v1"); "risk-v1.1" only adds
# provenance fields (epss_known, kev_known, stale_inputs, cvss calculator version).
# @lat: [[intel-and-reporting#Explainable versioned risk]]
SCORING_VERSION = "risk-v1.1"
SCORING_FORMULA_VERSION = "risk-v1"


def validate_cvss_vector(vector: str) -> str:
    """Return a normalized CVSS 3.x or 4.0 vector, or ``""`` when empty.

    Accepts vectors that start with ``CVSS:3.`` or ``CVSS:4.0`` and contain ``/``
    metrics. Raises ``ValueError`` for garbage (including CVSS 2.x). Callers that
    set the field explicitly (API/UI) should raise; importers should catch and
    clear instead of aborting. CVSS 4.0 vectors can be scored with
    :func:`cvss_score_for_vector` (FIRST reference calculator port).
    """
    v = (vector or "").strip()
    if not v:
        return ""
    if not ("/" in v and _CVSS_VECTOR_RE.match(v)):
        raise ValueError(
            "CVSS vector must be empty or a CVSS 3.x / 4.0 string starting with "
            "'CVSS:3.' or 'CVSS:4.0' and containing '/' metrics "
            "(for example CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H or "
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)"
        )
    return v


def soft_cvss_vector(vector: str | None) -> str:
    """Keep a vector only when valid; otherwise return empty (import path)."""
    try:
        return validate_cvss_vector(vector or "")
    except ValueError:
        return ""


def cvss_version_from_vector(vector: str | None) -> str:
    """Return the CVSS version prefix (e.g. ``3.1``, ``4.0``) or ``""`` when absent."""
    m = _CVSS_VERSION_RE.match((vector or "").strip())
    return m.group(1) if m else ""


def cvss_score_for_vector(vector: str | None, provided_score: float | None = None) -> dict:
    """Return the CVSS score of record for a vector, with how it was obtained.

    * CVSS 4.0: computed by :mod:`attestra.intel.cvss4` (reproducible from vector +
      ``calculator_version``). A malformed 4.0 vector falls back to ``provided_score``.
    * CVSS 3.x / empty: the provided (scanner/tester) score is kept unchanged.

    Returns ``{score, version, source, calculator_version, macro_vector, severity}``.
    """
    # @lat: [[intel-and-reporting#CVSS 4.0 calculator]]
    v = (vector or "").strip()
    version = cvss_version_from_vector(v)
    out = {
        "score": provided_score,
        "version": version,
        "source": "provided" if provided_score is not None else "none",
        "calculator_version": "",
        "macro_vector": "",
        "severity": severity_from_cvss(float(provided_score)) if provided_score is not None else "",
    }
    if version == "4.0":
        from attestra.intel import cvss4

        res = cvss4.try_score(v)
        if res is not None:
            out.update(
                score=res.score,
                source="cvss4_calculator",
                calculator_version=res.calculator_version,
                macro_vector=res.macro_vector,
                severity=res.severity,
            )
        else:
            out["source"] = "provided_invalid_vector" if provided_score is not None else "invalid_vector"
    return out


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


def align_severity_with_cvss(
    finding_or_fields,
    *,
    severity_overridden: bool = False,
) -> str | None:
    """When ``cvss_score`` is set, set severity from CVSS bands unless overridden.

    Accepts a Finding-like object or a ``dict`` with ``cvss_score`` / ``severity``.
    Mutates in place. Returns the aligned severity, or ``None`` when skipped
    (no score, or ``severity_overridden``).
    """
    if severity_overridden:
        return None
    is_mapping = isinstance(finding_or_fields, dict)
    score = (
        finding_or_fields.get("cvss_score")
        if is_mapping
        else getattr(finding_or_fields, "cvss_score", None)
    )
    if score is None:
        return None
    new_sev = severity_from_cvss(float(score))
    if is_mapping:
        finding_or_fields["severity"] = new_sev
    else:
        finding_or_fields.severity = new_sev
    return new_sev


def business_risk_band(risk_score: float | None) -> str:
    """Map priority ``risk_score`` to critical|high|medium|low|info (not a CVSS band)."""
    s = float(risk_score or 0.0)
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
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


def _risk_base(
    cvss: float | None, severity: str, exposure: str | None, in_cde: bool
) -> tuple[float, str]:
    """Return (base, source) used by risk_score / explain_risk_modifiers."""
    if cvss is not None:
        return float(cvss), "cvss_score"
    base = DEFAULT_CVSS.get((severity or "").lower(), 0.0)
    source = "severity_default"
    # C7: Info on internet-facing or CDE assets gets a small base so risk is never 0.
    if (
        base == 0.0
        and (severity or "").lower() == "info"
        and (exposure == "internet" or in_cde)
    ):
        return float(INFO_INTERNET_BASE), "info_internet_base"
    return float(base), source


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
    """Priority / business ranking. Does not replace CVSS technical severity."""
    base, _ = _risk_base(cvss, severity, exposure, in_cde)
    score = (
        base * (1 + (epss or 0.0)) * (KEV_FACTOR if kev else 1.0)
        * asset_weight(criticality, weights) * exposure_weight(exposure, in_cde, weights)
    )
    return round(score, 2)


def explain_risk_modifiers(
    cvss: float | None,
    severity: str,
    epss: float | None = None,
    kev: bool = False,
    criticality: int | None = None,
    exposure: str | None = None,
    in_cde: bool = False,
    weights: RiskWeights | None = None,
    *,
    validation_status: str | None = None,
    informational_capped: bool | None = None,
    epss_known: bool | None = None,
    kev_known: bool | None = None,
    stale_inputs: list[str] | tuple[str, ...] | None = None,
    cvss_vector: str | None = None,
    intel_source_version: str = "",
) -> dict:
    """Cheap, reproducible breakdown of priority/business risk modifiers.

    This explains ``risk_score`` only. CVSS score/vector remain the technical
    severity of record and are never rewritten here.

    G-04: a missing EPSS value is reported as *unknown* (``epss: None``,
    ``epss_known: False``), never as 0 %. The numeric score is unchanged for existing
    inputs (unknown EPSS contributes no uplift, exactly as before). ``kev_known`` is
    False unless the caller says the KEV feed was loaded (or ``kev`` is True).
    ``stale_inputs`` lists feeds (``kev``/``epss``) that were stale or missing.
    """
    capped = (
        bool(informational_capped)
        if informational_capped is not None
        else (validation_status or "").lower() == "informational"
    )
    # Informational observations use the info base so business risk is not inflated.
    score_cvss = None if capped else cvss
    score_sev = "info" if capped else severity
    base, base_source = _risk_base(score_cvss, score_sev, exposure, in_cde)
    epss_is_known = (epss is not None) if epss_known is None else bool(epss_known and epss is not None)
    epss_v = float(epss or 0.0)
    epss_factor = 1.0 + epss_v
    kev_is_known = bool(kev) or bool(kev_known)
    stale = sorted({str(x) for x in (stale_inputs or [])})
    kev_factor = KEV_FACTOR if kev else 1.0
    aw = asset_weight(criticality, weights)
    ew = exposure_weight(exposure, in_cde, weights)
    score = round(base * epss_factor * kev_factor * aw * ew, 2)
    notes: list[str] = [
        "risk_score is priority/business ranking; CVSS remains technical severity of record",
    ]
    if capped:
        notes.append(
            "validation_status=informational: priority uses info base "
            "(not treated as a confirmed vulnerability)"
        )
    if not epss_is_known:
        notes.append("EPSS unknown (no score for these CVEs or feed not loaded): no uplift applied; not treated as 0%")
    if not kev_is_known:
        notes.append("KEV status unknown (feed not confirmed loaded): no KEV uplift applied")
    if stale:
        notes.append(f"stale or missing intel inputs: {', '.join(stale)}")
    cvss_calc = cvss_score_for_vector(cvss_vector, cvss) if cvss_vector else None
    return {
        "scoring_version": SCORING_VERSION,
        "formula_version": SCORING_FORMULA_VERSION,
        "epss_known": epss_is_known,
        "kev_known": kev_is_known,
        "stale_inputs": stale,
        "intel_source_version": intel_source_version or "",
        "cvss_calculation": cvss_calc,
        "base": base,
        "base_source": base_source,
        "cvss_score": cvss,
        "cvss_input": score_cvss,
        "severity": (severity or "").lower() or "info",
        "severity_input": score_sev,
        "epss": epss_v if epss_is_known else None,
        "epss_factor": epss_factor,
        "kev": bool(kev),
        "kev_factor": kev_factor,
        "asset_criticality": min(max(criticality or 3, 1), 5),
        "criticality": min(max(criticality or 3, 1), 5),
        "asset_weight": aw,
        "exposure": exposure or "",
        "in_cde": bool(in_cde),
        "exposure_weight": ew,
        "informational_capped": capped,
        "formula": "base × (1+EPSS) × kev_factor × asset_weight × exposure_weight",
        "risk_score": score,
        "business_risk": business_risk_band(score),
        "notes": notes,
    }


def sla_due(severity: str, from_day: date | None = None) -> date | None:
    days = config.SLA_DAYS.get(severity)
    if days is None:
        return None
    return (from_day or date.today()) + timedelta(days=days)
