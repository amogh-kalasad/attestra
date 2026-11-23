"""AASI Phase 4 recommendation ranking for planner handoff.

Ranks candidate TestRecommendations; the Attestra planner still decides
execution order. Scoring priority: coverage gap > confirmed finding
adjacency > default.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict
from typing import Any

# Score bands (higher = earlier in the ranked list).
SCORE_COVERAGE_GAP = 300
SCORE_CONFIRMED_ADJACENCY = 200
SCORE_DEFAULT = 100


def _rec_mapping(rec: Any) -> Mapping[str, Any]:
    if isinstance(rec, Mapping):
        return rec
    if hasattr(rec, "__dataclass_fields__"):
        return asdict(rec)
    raise TypeError(f"unsupported recommendation type: {type(rec)!r}")


def _test_id(rec: Mapping[str, Any]) -> str:
    return str(
        rec.get("registered_test_id")
        or rec.get("test_id")
        or ""
    ).strip()


def _test_type(rec: Mapping[str, Any]) -> str:
    return str(
        rec.get("authorized_test_type")
        or rec.get("test_type")
        or ""
    ).strip()


def _asset_id(rec: Mapping[str, Any]) -> int | None:
    raw = rec.get("asset_id")
    if isinstance(raw, bool):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _normalize_gap_tokens(coverage_gaps: Sequence[Any]) -> set[str]:
    out: set[str] = set()
    for gap in coverage_gaps or []:
        if isinstance(gap, Mapping):
            for key in ("id", "test_id", "category", "gap", "name"):
                val = gap.get(key)
                if val is not None and str(val).strip():
                    out.add(str(val).strip().lower())
        elif gap is not None and str(gap).strip():
            out.add(str(gap).strip().lower())
    return out


def _confirmed_asset_ids(findings_meta: Sequence[Any]) -> set[int]:
    """Assets that already have confirmed / validated findings (adjacency signal)."""
    out: set[int] = set()
    for finding in findings_meta or []:
        if not isinstance(finding, Mapping):
            continue
        status = str(
            finding.get("validation")
            or finding.get("status")
            or finding.get("confirmation")
            or ""
        ).strip().lower()
        if status not in {
            "confirmed",
            "validated",
            "true_positive",
            "accepted",
            "demonstrated",
        }:
            continue
        raw = finding.get("asset_id")
        try:
            if raw is not None and not isinstance(raw, bool):
                out.add(int(raw))
        except (TypeError, ValueError):
            continue
    return out


def score_recommendation(
    rec: Any,
    *,
    coverage_gaps: Sequence[Any] = (),
    findings_meta: Sequence[Any] = (),
    confirmed_finding_assets: Sequence[int] | None = None,
) -> int:
    """Return an integer score for one recommendation (higher = higher priority)."""
    data = _rec_mapping(rec)
    gaps = _normalize_gap_tokens(coverage_gaps)
    tid = _test_id(data).lower()
    ttype = _test_type(data).lower()
    asset = _asset_id(data)

    if tid and tid in gaps:
        return SCORE_COVERAGE_GAP
    if ttype and ttype in gaps:
        return SCORE_COVERAGE_GAP

    if confirmed_finding_assets is not None:
        confirmed = {int(a) for a in confirmed_finding_assets}
    else:
        confirmed = _confirmed_asset_ids(findings_meta)

    if asset is not None and asset in confirmed:
        return SCORE_CONFIRMED_ADJACENCY

    return SCORE_DEFAULT


def prioritize_recommendations(
    candidates: Sequence[Any],
    *,
    coverage_gaps: Sequence[Any] = (),
    findings_meta: Sequence[Any] = (),
    confirmed_finding_assets: Sequence[int] | None = None,
) -> list[Any]:
    """Stable rank of candidates: coverage gap, then confirmed adjacency, then default.

    Does not mutate inputs. Planner remains free to reorder or drop items.
    """
    indexed = list(enumerate(candidates))

    def sort_key(item: tuple[int, Any]) -> tuple[int, int]:
        idx, rec = item
        # Negate score so higher scores sort first; idx preserves stability.
        return (-score_recommendation(
            rec,
            coverage_gaps=coverage_gaps,
            findings_meta=findings_meta,
            confirmed_finding_assets=confirmed_finding_assets,
        ), idx)

    indexed.sort(key=sort_key)
    return [rec for _, rec in indexed]


__all__ = [
    "SCORE_CONFIRMED_ADJACENCY",
    "SCORE_COVERAGE_GAP",
    "SCORE_DEFAULT",
    "prioritize_recommendations",
    "score_recommendation",
]
