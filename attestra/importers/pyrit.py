"""PyRIT structured attack-result export importer (JSON / JSONL).

Fixture-driven contract for Phase 1. Worker execution is Phase 5; this module
only parses exported attack results. Empty exports and failed/undetermined
outcomes produce no findings.
"""

from __future__ import annotations

import json
from typing import Any

from attestra.importers.base import NormalizedFinding, norm_severity

_SUCCESS_OUTCOMES = frozenset({"success", "succeeded", "pass", "passed", "true", "yes"})
_FAILURE_OUTCOMES = frozenset(
    {"failure", "failed", "fail", "error", "undetermined", "false", "no", "skip", "skipped"}
)


def _load(raw: bytes) -> Any:
    text = raw.decode("utf-8-sig", errors="replace").strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        try:
            return [json.loads(line) for line in text.splitlines() if line.strip()]
        except json.JSONDecodeError as line_exc:
            raise ValueError(f"malformed PyRIT JSON: {line_exc}") from line_exc


def _items(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if not isinstance(doc, dict):
        raise ValueError("malformed PyRIT export: expected object or array")
    for key in ("attack_results", "results", "records", "attacks"):
        items = doc.get(key)
        if isinstance(items, list):
            return [r for r in items if isinstance(r, dict)]
    # Single attack-result object
    if any(k in doc for k in ("conversation_id", "outcome", "objective", "success", "score")):
        return [doc]
    return []


def _tool_version(doc: Any, rec: dict[str, Any]) -> str:
    for src in (rec, doc if isinstance(doc, dict) else {}):
        if not isinstance(src, dict):
            continue
        for key in ("tool_version", "pyrit_version", "version"):
            val = src.get(key)
            if val not in (None, ""):
                return str(val)
        meta = src.get("metadata") or {}
        if isinstance(meta, dict):
            for key in ("tool_version", "pyrit_version", "version"):
                val = meta.get(key)
                if val not in (None, ""):
                    return str(val)
    return ""


def _score_blob(rec: dict[str, Any]) -> dict[str, Any]:
    for key in ("score", "last_score", "automated_score", "human_score"):
        blob = rec.get(key)
        if isinstance(blob, dict):
            return blob
    return {}


def _score_value(score: dict[str, Any]) -> Any:
    for key in ("value", "score_value", "get_value"):
        if key in score and score[key] is not None:
            return score[key]
    return None


def _truthy_score(score: dict[str, Any]) -> bool | None:
    """Return True/False when the score clearly asserts attack success; else None."""
    if not score:
        return None
    val = _score_value(score)
    stype = str(score.get("score_type") or score.get("type") or "").lower()
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)) and stype in ("true_false", "bool", "boolean"):
        return bool(val)
    if isinstance(val, str):
        low = val.strip().lower()
        if low in ("true", "yes", "1", "success"):
            return True
        if low in ("false", "no", "0", "failure", "fail"):
            return False
    if isinstance(val, (int, float)) and stype in ("float_scale", "float", "likert"):
        # float_scale success is caller-defined; treat >= 0.8 as positive only when
        # an explicit success/outcome flag is absent (handled by caller).
        return None
    return None


def _is_positive(rec: dict[str, Any], score: dict[str, Any]) -> bool:
    if "success" in rec:
        success = rec.get("success")
        if isinstance(success, bool):
            return success
        if isinstance(success, str):
            return success.strip().lower() in _SUCCESS_OUTCOMES
    outcome = str(rec.get("outcome") or "").strip().lower()
    if outcome:
        if outcome in _SUCCESS_OUTCOMES:
            return True
        if outcome in _FAILURE_OUTCOMES:
            return False
    scored = _truthy_score(score)
    if scored is not None:
        return scored
    # Explicit float threshold only when marked success_threshold or score_threshold
    thr = rec.get("success_threshold")
    if thr is None:
        thr = score.get("success_threshold")
    val = _score_value(score)
    if thr is not None and isinstance(val, (int, float)):
        try:
            return float(val) >= float(thr)
        except (TypeError, ValueError):
            return False
    return False


def _severity(rec: dict[str, Any], score: dict[str, Any]) -> str:
    for src in (rec.get("severity"), score.get("severity")):
        if src not in (None, ""):
            mapped = norm_severity(str(src))
            # PyRIT FindingSeverity uses "important" / "moderate"
            aliases = {"important": "high", "moderate": "medium"}
            return aliases.get(str(src).strip().lower(), mapped)
    return "high"


def _categories(score: dict[str, Any], rec: dict[str, Any]) -> list[str]:
    cats: list[str] = []
    for src in (
        score.get("category"),
        score.get("score_category"),
        rec.get("targeted_harm_categories"),
        rec.get("categories"),
    ):
        if isinstance(src, str) and src.strip():
            cats.append(src.strip())
        elif isinstance(src, list):
            for item in src:
                text = str(item).strip()
                if text and text not in cats:
                    cats.append(text)
    return cats


def _to_finding(rec: dict[str, Any], *, doc: Any) -> NormalizedFinding | None:
    score = _score_blob(rec)
    if not _is_positive(rec, score):
        return None

    conversation_id = str(
        rec.get("conversation_id") or rec.get("conversationId") or ""
    ).strip()
    scenario_id = str(
        rec.get("scenario_id") or rec.get("scenarioId") or rec.get("scenario") or ""
    ).strip()
    attack_result_id = str(
        rec.get("attack_result_id") or rec.get("id") or ""
    ).strip()
    objective = str(rec.get("objective") or rec.get("goal") or "").strip()
    attack_type = str(
        rec.get("attack_type")
        or rec.get("attack_strategy")
        or rec.get("technique_name")
        or ((rec.get("metadata") or {}) if isinstance(rec.get("metadata"), dict) else {}).get(
            "technique_name", ""
        )
        or ""
    ).strip()
    outcome = str(rec.get("outcome") or ("success" if rec.get("success") else "")).strip()
    outcome_reason = str(rec.get("outcome_reason") or "").strip()
    rationale = str(
        score.get("rationale") or score.get("score_rationale") or outcome_reason or ""
    ).strip()
    scorer = ""
    raw_scorer = score.get("scorer")
    if isinstance(raw_scorer, str) and raw_scorer.strip():
        scorer = raw_scorer.strip()
    ident = score.get("scorer_class_identifier")
    if not scorer and isinstance(ident, str) and ident.strip():
        scorer = ident.strip()
    elif not scorer and isinstance(ident, dict):
        scorer = str(ident.get("__name__") or ident.get("name") or "").strip()

    score_val = _score_value(score)
    cats = _categories(score, rec)
    target = str(
        rec.get("target") or rec.get("location") or rec.get("endpoint") or ""
    ).strip()
    if not target and isinstance(doc, dict):
        target = str(doc.get("target") or doc.get("endpoint") or "").strip()

    rule_bits = [p for p in (attack_type, scenario_id, conversation_id) if p]
    rule_id = "/".join(rule_bits) if rule_bits else (attack_result_id or "pyrit")
    title_bits = ["PyRIT"]
    if attack_type:
        title_bits.append(attack_type)
    if cats:
        title_bits.append(cats[0])
    elif objective:
        title_bits.append(objective[:80])
    else:
        title_bits.append("successful attack")
    title = " — ".join(title_bits)

    desc_parts = ["PyRIT attack result marked successful."]
    if objective:
        desc_parts.append(f"Objective: {objective}")
    if conversation_id:
        desc_parts.append(f"Conversation ID: {conversation_id}.")
    if scenario_id:
        desc_parts.append(f"Scenario ID: {scenario_id}.")
    if attack_result_id:
        desc_parts.append(f"Attack result ID: {attack_result_id}.")
    if outcome:
        desc_parts.append(f"Outcome: {outcome}.")
    if score_val is not None:
        desc_parts.append(f"Score: {score_val}.")
    if scorer:
        desc_parts.append(f"Scorer: {scorer}.")
    if rationale:
        desc_parts.append(f"Rationale: {rationale}")

    evidence: list[str] = []
    if conversation_id:
        evidence.append(f"conversation_id:{conversation_id}")
    if scenario_id:
        evidence.append(f"scenario_id:{scenario_id}")
    if score_val is not None:
        evidence.append(f"score:{score_val}")
    if outcome:
        evidence.append(f"outcome:{outcome}")

    conf_parts = ["scorer_signal", "validation=potential"]
    if score_val is not None:
        conf_parts.insert(1, f"score={score_val}")
    if outcome:
        conf_parts.insert(1, f"outcome={outcome}")

    location = target or conversation_id or scenario_id or "pyrit"
    return NormalizedFinding(
        tool="pyrit",
        rule_id=rule_id[:500],
        original_id=attack_result_id or conversation_id or scenario_id,
        title=title[:500],
        severity=_severity(rec, score),
        location=str(location),
        description=" ".join(desc_parts),
        recommendation=(
            "Review the conversation transcript, harden model/system prompts and "
            "tool policies against this objective, then re-test."
        ),
        cwe=1427,
        param=attack_type or (cats[0] if cats else ""),
        tool_version=_tool_version(doc, rec),
        confidence="; ".join(conf_parts),
        evidence_refs=evidence,
        variant=outcome or "success",
    )


def parse(raw: bytes) -> list[NormalizedFinding]:
    """Parse a PyRIT attack-result JSON/JSONL export into NormalizedFinding rows.

    Supported shapes: ``{attack_results:[...]}``, ``{results:[...]}``, a bare
    list, JSONL, or a single attack-result object. Only successful outcomes /
    success flags / true scores become findings. Failures, errors, undetermined
    results, and empty files yield an empty list (no false findings).
    """
    doc = _load(raw)
    if doc == []:
        return []
    if not isinstance(doc, (dict, list)):
        raise ValueError("malformed PyRIT export: expected object or array")

    out: list[NormalizedFinding] = []
    for rec in _items(doc):
        nf = _to_finding(rec, doc=doc)
        if nf:
            out.append(nf)
    return out
