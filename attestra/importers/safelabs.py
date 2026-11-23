"""SafeLabs safelabs-eval importer (`--output json` / EvalResult dumps).

Heuristic pattern detectors only — findings stay validation=`potential` at persist
time. NormalizedFinding has no validation field; uncertainty lives in `confidence`.
"""

from __future__ import annotations

import json
from typing import Any

from attestra.importers.base import NormalizedFinding, norm_severity

# SafeLabs ASI-source labels (OWASP-inspired, not official OWASP Agentic Top 10 2026).
_ASI_LABELS: dict[str, str] = {
    "ASI01": "Prompt Injection",
    "ASI02": "Insecure Output Handling",
    "ASI03": "Excessive Agency",
    "ASI04": "Resource Management",
    "ASI05": "Tool Use Safety",
    "ASI06": "Data Privacy & Confidentiality",
    "ASI07": "Trust Boundaries",
    "ASI08": "Behavioral Drift",
    "ASI09": "Scope Violations",
    "ASI10": "Hallucination & Misinformation",
}

_CATEGORY_EVAL_TYPE: dict[str, str] = {
    "ASI01": "prompt_injection",
    "ASI02": "prompt_injection",
    "ASI03": "scope_violation",
    "ASI04": "prompt_injection",
    "ASI05": "prompt_injection",
    "ASI06": "data_leakage",
    "ASI07": "prompt_injection",
    "ASI08": "jailbreak",
    "ASI09": "scope_violation",
    "ASI10": "hallucination",
}

_POSITIVE_VERDICTS = frozenset({"vulnerable", "fail"})

_CWE_BY_EVAL: dict[str, int] = {
    "prompt_injection": 1427,
    "jailbreak": 1427,
    "data_leakage": 200,
    "hallucination": 20,
    "scope_violation": 284,
}


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
            raise ValueError(f"malformed safelabs-eval JSON: {line_exc}") from line_exc


def _records(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, list):
        return [r for r in doc if isinstance(r, dict)]
    if not isinstance(doc, dict):
        raise ValueError("malformed safelabs-eval report: expected object or array")
    for key in ("results", "records"):
        items = doc.get(key)
        if isinstance(items, list):
            return [r for r in items if isinstance(r, dict)]
    # Single EvalRecord-shaped object
    if "verdict" in doc or "scoring_result" in doc or "id" in doc or "prompt_id" in doc:
        return [doc]
    return []


def _tool_version(doc: Any, rec: dict[str, Any]) -> str:
    for src in (rec, doc if isinstance(doc, dict) else {}):
        if not isinstance(src, dict):
            continue
        for key in ("tool_version", "safelabs_version", "version", "safelabs_eval_version"):
            val = src.get(key)
            if val not in (None, ""):
                return str(val)
        meta = src.get("metadata") or {}
        if isinstance(meta, dict):
            for key in ("tool_version", "safelabs_version", "version"):
                val = meta.get(key)
                if val not in (None, ""):
                    return str(val)
    return ""


def _scoring(rec: dict[str, Any]) -> dict[str, Any]:
    nested = rec.get("scoring_result")
    return nested if isinstance(nested, dict) else {}


def _verdict(rec: dict[str, Any], scoring: dict[str, Any]) -> str:
    raw = rec.get("verdict")
    if raw is None:
        raw = scoring.get("verdict")
    if isinstance(raw, dict):
        raw = raw.get("value")
    return str(raw or "").strip().lower()


def _confidence_float(rec: dict[str, Any], scoring: dict[str, Any]) -> float | None:
    raw = rec.get("confidence")
    if raw is None:
        raw = scoring.get("confidence")
    if raw in (None, ""):
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _indicators(rec: dict[str, Any], scoring: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for src in (rec.get("indicators"), scoring.get("indicators")):
        if isinstance(src, list):
            for item in src:
                text = str(item).strip()
                if text and text not in refs:
                    refs.append(text)
    return refs


def _detector(rec: dict[str, Any], scoring: dict[str, Any], category: str) -> str:
    for src in (rec.get("eval_type"), scoring.get("eval_type"), rec.get("detector")):
        if src not in (None, ""):
            return str(src)
    return _CATEGORY_EVAL_TYPE.get(category.upper(), "prompt_injection")


def _severity(rec: dict[str, Any], scoring: dict[str, Any], verdict: str) -> str:
    for src in (rec.get("severity"), scoring.get("severity")):
        if src not in (None, ""):
            return norm_severity(str(src))
    return "high" if verdict == "vulnerable" else "medium"


def _confidence_label(verdict: str, conf: float | None) -> str:
    """Heuristic evidence string; never implies confirmed validation status."""
    parts = [
        "heuristic_detector",
        f"verdict={verdict}",
        "uncertainty=pattern_based",
        "validation=potential",
    ]
    if conf is not None:
        pct = f"{conf:.0%}" if 0.0 <= conf <= 1.0 else str(conf)
        parts.insert(1, f"evidence_score={pct}")
    return "; ".join(parts)


def _to_finding(
    rec: dict[str, Any],
    *,
    doc: Any,
    target: str,
) -> NormalizedFinding | None:
    if rec.get("status") == "missing_infrastructure":
        return None
    if rec.get("error") and "verdict" not in rec and "scoring_result" not in rec:
        return None

    scoring = _scoring(rec)
    verdict = _verdict(rec, scoring)
    if verdict not in _POSITIVE_VERDICTS:
        return None

    prompt_id = str(rec.get("id") or rec.get("prompt_id") or "").strip()
    category = str(rec.get("category") or "").strip().upper()
    if not category and prompt_id:
        category = prompt_id.split("-", 1)[0].upper()
    detector = _detector(rec, scoring, category)
    conf = _confidence_float(rec, scoring)
    indicators = _indicators(rec, scoring)
    reasoning = str(rec.get("reasoning") or scoring.get("reasoning") or "").strip()
    remediation = str(
        rec.get("remediation_hint") or scoring.get("remediation_hint") or ""
    ).strip()
    asi_name = _ASI_LABELS.get(category, category or "ASI")
    title = f"[SafeLabs ASI-source {category or 'ASI'}] {asi_name}"
    if prompt_id:
        title = f"{title} ({prompt_id})"

    desc_parts = [
        f"SafeLabs safelabs-eval heuristic verdict={verdict}.",
        "Taxonomy source: SafeLabs ASI-source (OWASP-inspired; not official OWASP Agentic Top 10 2026).",
        f"Detector: {detector}.",
    ]
    if reasoning:
        desc_parts.append(f"Reasoning: {reasoning}")
    if indicators:
        desc_parts.append("Indicators: " + "; ".join(indicators[:20]))

    location = target or prompt_id or category or "safelabs"
    return NormalizedFinding(
        tool="safelabs",
        rule_id=prompt_id or f"{category}:{detector}",
        original_id=prompt_id or "",
        title=title[:500],
        severity=_severity(rec, scoring, verdict),
        location=str(location),
        description=" ".join(desc_parts),
        recommendation=remediation,
        cwe=_CWE_BY_EVAL.get(detector),
        param=detector,
        tool_version=_tool_version(doc, rec),
        confidence=_confidence_label(verdict, conf),
        evidence_refs=indicators[:50],
        variant=verdict,
    )


def parse(raw: bytes) -> list[NormalizedFinding]:
    """Parse safelabs-eval JSON / JSONL into NormalizedFinding rows.

    Only ``vulnerable`` and ``fail`` verdicts become findings. ``pass``,
    ``uncertain``, errors, and missing_infrastructure rows are skipped.
    Heuristic confidence is recorded on ``confidence``; callers must keep
    persisted validation status at ``potential``.
    """
    doc = _load(raw)
    if doc == []:
        return []
    if not isinstance(doc, (dict, list)):
        raise ValueError("malformed safelabs-eval report: expected object or array")

    target = ""
    if isinstance(doc, dict):
        target = str(doc.get("target") or doc.get("endpoint") or "").strip()

    out: list[NormalizedFinding] = []
    for rec in _records(doc):
        nf = _to_finding(rec, doc=doc, target=target)
        if nf:
            out.append(nf)
    return out
