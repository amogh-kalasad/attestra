"""Framework recommendation rules over the configured Attestra catalogue.

Recommendations are advisory profile matches. They never invent framework IDs
outside [[attestra/compliance/engine.py#load_library]].
"""
# @lat: [[compliance#Framework recommendations]]

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from attestra.compliance.engine import load_library

DATA = Path(__file__).parent / "data"

RECOMMENDATION_STATUSES = (
    "recommended",
    "applicable",
    "requires_review",
    "not_applicable",
    "user_added",
    "user_excluded",
)

# Prefer stronger / more specific outcomes when multiple rules hit one framework.
_STATUS_RANK = {
    "recommended": 40,
    "applicable": 30,
    "requires_review": 20,
    "not_applicable": 10,
    "user_added": 5,
    "user_excluded": 0,
}


@dataclass(frozen=True)
class Recommendation:
    framework_id: str
    name: str
    status: str
    reason: str
    rule_id: str
    rule_version: str
    reviewed_on: str
    inputs: dict[str, Any] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    confirmation_required: bool = False
    source: str = "recommend_rules"


class RecommendError(ValueError):
    """Invalid recommendation inputs (missing mandatory fields or unknown keys)."""


@lru_cache(maxsize=1)
def load_industries() -> dict[str, dict]:
    raw = yaml.safe_load((DATA / "industries.yaml").read_text(encoding="utf-8")) or {}
    return dict(raw.get("industries") or {})


@lru_cache(maxsize=1)
def load_countries() -> dict[str, str]:
    raw = yaml.safe_load((DATA / "countries.yaml").read_text(encoding="utf-8")) or {}
    return {str(k): str(v) for k, v in (raw.get("countries") or {}).items()}


@lru_cache(maxsize=1)
def load_technical_scopes() -> dict[str, dict]:
    raw = yaml.safe_load((DATA / "technical_scope.yaml").read_text(encoding="utf-8")) or {}
    return dict(raw.get("scopes") or {})


@lru_cache(maxsize=1)
def load_recommend_rules() -> dict[str, Any]:
    return yaml.safe_load((DATA / "recommend_rules.yaml").read_text(encoding="utf-8")) or {}


def country_catalogue_limitation() -> str:
    raw = yaml.safe_load((DATA / "countries.yaml").read_text(encoding="utf-8")) or {}
    return str(raw.get("limitation") or "").strip()


def catalogues() -> dict[str, Any]:
    """Public catalogue payload for UI and API clients."""
    industries = {
        k: {"label": v["label"], "category": v.get("category", "")}
        for k, v in load_industries().items()
    }
    return {
        "industries": industries,
        "countries": load_countries(),
        "technical_scopes": {
            k: {"label": v["label"]} for k, v in load_technical_scopes().items()
        },
        "recommendation_statuses": list(RECOMMENDATION_STATUSES),
        "country_limitation": country_catalogue_limitation(),
        "rules_version": str(load_recommend_rules().get("version") or ""),
        "disclaimer": str(load_recommend_rules().get("disclaimer") or "").strip(),
    }


def _norm_country(value: str) -> str:
    return (value or "").strip().upper()


def _norm_industry(value: str) -> str:
    return (value or "").strip()


def _norm_scopes(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for v in values or []:
        key = (v or "").strip()
        if key and key not in out:
            out.append(key)
    return out


def validate_profile(
    *,
    industry: str,
    country: str,
    technical_scope: list[str] | None = None,
    require_mandatory: bool = True,
) -> tuple[str, str, list[str]]:
    """Validate catalogue keys. Raises RecommendError on bad or missing mandatory fields."""
    ind = _norm_industry(industry)
    cty = _norm_country(country)
    scopes = _norm_scopes(technical_scope)
    missing: list[str] = []
    if require_mandatory:
        if not ind:
            missing.append("industry")
        if not cty:
            missing.append("country")
        if missing:
            raise RecommendError(
                "Industry and Country are required to generate framework recommendations."
            )
    industries = load_industries()
    countries = load_countries()
    known_scopes = load_technical_scopes()
    if ind and ind not in industries:
        raise RecommendError(f"unknown industry {ind!r}; choose from the industry catalogue")
    if cty and cty not in countries:
        raise RecommendError(f"unknown country {cty!r}; choose from the country catalogue")
    bad_scopes = [s for s in scopes if s not in known_scopes]
    if bad_scopes:
        raise RecommendError(
            f"unknown technical scope {bad_scopes}; choose from {sorted(known_scopes)}"
        )
    return ind, cty, scopes


def _rule_matches(rule: dict, *, industry: str, country: str, scopes: list[str], eu_eea: set[str]) -> bool:
    when = rule.get("when") or {}
    if not when:
        return True
    industries_any = when.get("industries_any")
    if industries_any and industry not in industries_any:
        return False
    industries_none = when.get("industries_none_of")
    if industries_none and industry in industries_none:
        return False
    countries_any = when.get("countries_any")
    if countries_any and country not in [str(c).upper() for c in countries_any]:
        return False
    if when.get("countries_eu_eea") and country not in eu_eea:
        return False
    scope_any = when.get("technical_scope_any")
    if scope_any and not any(s in scopes for s in scope_any):
        return False
    return True


def recommend_frameworks(
    *,
    industry: str,
    country: str,
    regulatory_status: str = "",
    technical_scope: list[str] | None = None,
    engagement_type: str = "",
    confirmed_frameworks: list[str] | None = None,
    excluded_frameworks: list[str] | None = None,
) -> list[Recommendation]:
    """Return catalogue-only recommendations for a profile.

    Confirmed/excluded user selections are preserved as user_added / user_excluded
    and are never silently dropped when the profile changes.
    """
    ind, cty, scopes = validate_profile(
        industry=industry, country=country, technical_scope=technical_scope, require_mandatory=True
    )
    lib = load_library()
    catalogue = dict(lib.frameworks)
    rules_doc = load_recommend_rules()
    eu_eea = {str(c).upper() for c in (rules_doc.get("eu_eea_codes") or [])}
    version = str(rules_doc.get("version") or "")
    reviewed_on = str(rules_doc.get("reviewed_on") or "")
    inputs = {
        "industry": ind,
        "country": cty,
        "regulatory_status": (regulatory_status or "").strip(),
        "technical_scope": scopes,
        "engagement_type": (engagement_type or "").strip(),
    }

    best: dict[str, Recommendation] = {}
    for rule in rules_doc.get("rules") or []:
        fw = str(rule.get("framework") or "")
        if fw not in catalogue:
            continue  # never invent; skip stale rule targets
        if not _rule_matches(rule, industry=ind, country=cty, scopes=scopes, eu_eea=eu_eea):
            continue
        status = str(rule.get("status") or "requires_review")
        if status not in RECOMMENDATION_STATUSES:
            status = "requires_review"
        cand = Recommendation(
            framework_id=fw,
            name=str(catalogue[fw].get("name") or fw),
            status=status,
            reason=str(rule.get("reason") or "").strip(),
            rule_id=str(rule.get("id") or ""),
            rule_version=version,
            reviewed_on=reviewed_on,
            inputs=dict(inputs),
            missing=[],
            confirmation_required=status in ("recommended", "requires_review"),
            source="recommend_rules",
        )
        prev = best.get(fw)
        if prev is None or _STATUS_RANK.get(cand.status, 0) > _STATUS_RANK.get(prev.status, 0):
            best[fw] = cand

    confirmed = [f for f in (confirmed_frameworks or []) if f in catalogue]
    excluded = [f for f in (excluded_frameworks or []) if f in catalogue]
    for fw in confirmed:
        if fw in best and best[fw].status in ("recommended", "applicable", "requires_review"):
            continue
        best[fw] = Recommendation(
            framework_id=fw,
            name=str(catalogue[fw].get("name") or fw),
            status="user_added",
            reason="Previously confirmed by an authorized user; kept after profile refresh.",
            rule_id="user.confirmed",
            rule_version=version,
            reviewed_on=reviewed_on,
            inputs=dict(inputs),
            confirmation_required=False,
            source="user",
        )
    for fw in excluded:
        best[fw] = Recommendation(
            framework_id=fw,
            name=str(catalogue[fw].get("name") or fw),
            status="user_excluded",
            reason="Excluded by an authorized user; not re-added automatically.",
            rule_id="user.excluded",
            rule_version=version,
            reviewed_on=reviewed_on,
            inputs=dict(inputs),
            confirmation_required=False,
            source="user",
        )

    order = {"recommended": 0, "applicable": 1, "requires_review": 2, "user_added": 3, "not_applicable": 4, "user_excluded": 5}
    return sorted(best.values(), key=lambda r: (order.get(r.status, 9), r.name.lower()))


def recommendation_to_dict(r: Recommendation) -> dict[str, Any]:
    return {
        "framework_id": r.framework_id,
        "name": r.name,
        "status": r.status,
        "reason": r.reason,
        "rule_id": r.rule_id,
        "rule_version": r.rule_version,
        "reviewed_on": r.reviewed_on,
        "inputs": r.inputs,
        "missing": r.missing,
        "confirmation_required": r.confirmation_required,
        "source": r.source,
    }
