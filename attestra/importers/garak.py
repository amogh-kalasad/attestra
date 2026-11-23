"""Garak JSONL importer (report.jsonl and hitlog.jsonl).

Native Garak report rows use ``entry_type`` values such as ``init``, ``attempt``,
``eval``, ``probe_summary``, and ``digest``. Detector hits live on completed
attempts (``status == 2``) under ``detector_results`` (detector name → list of
float scores). Garak's default ``ThresholdEvaluator`` treats score >= 0.5 as a
hit (fail). Only those qualifying hits become findings — probe execution or
eval summaries alone do not.
"""

from __future__ import annotations

import json
from typing import Any

from attestra.importers.base import NormalizedFinding, norm_severity, parse_cwe

# Matches garak.evaluators.ThresholdEvaluator default (pass when score < threshold).
HIT_THRESHOLD = 0.5
ATTEMPT_COMPLETE = 2


def _prompt_text(prompt: Any) -> str:
    if prompt is None:
        return ""
    if isinstance(prompt, str):
        return prompt.strip()
    if not isinstance(prompt, dict):
        return str(prompt).strip()
    # Message-shaped
    text = prompt.get("text")
    if isinstance(text, str) and text.strip():
        return text.strip()
    # Conversation-shaped: turns[].content.text
    turns = prompt.get("turns")
    if isinstance(turns, list):
        parts: list[str] = []
        for turn in turns:
            if not isinstance(turn, dict):
                continue
            content = turn.get("content")
            if isinstance(content, dict) and content.get("text"):
                parts.append(str(content["text"]).strip())
            elif isinstance(content, str) and content.strip():
                parts.append(content.strip())
        if parts:
            return " | ".join(parts)
    return ""


def _output_text(outputs: Any, idx: int | None = None) -> str:
    if not outputs:
        return ""
    if isinstance(outputs, str):
        return outputs.strip()
    if not isinstance(outputs, list):
        return str(outputs).strip()
    items = outputs if idx is None else ([outputs[idx]] if 0 <= idx < len(outputs) else [])
    parts: list[str] = []
    for item in items:
        if item is None:
            continue
        if isinstance(item, str):
            parts.append(item.strip())
        elif isinstance(item, dict):
            t = item.get("text")
            if t:
                parts.append(str(t).strip())
        else:
            parts.append(str(item).strip())
    return " | ".join(p for p in parts if p)


def _max_hit_score(scores: Any) -> float | None:
    """Return max score that meets HIT_THRESHOLD, or None if no qualifying hit."""
    if not isinstance(scores, list) or not scores:
        return None
    best: float | None = None
    for raw in scores:
        if raw is None:
            continue
        try:
            score = float(raw)
        except (TypeError, ValueError):
            continue
        if score >= HIT_THRESHOLD and (best is None or score > best):
            best = score
    return best


def _severity_from_score(score: float) -> str:
    # Conservative: strong detector agreement → high; threshold hit → medium.
    if score >= 0.85:
        return norm_severity("high")
    return norm_severity("medium")


def _rule_id(probe: str, detector: str) -> str:
    return f"{probe}:{detector}" if probe and detector else (probe or detector or "garak")


def _evidence_refs(
    *,
    prompt: str,
    output: str,
    score: float,
    attempt_id: str,
    goal: str = "",
) -> list[str]:
    refs: list[str] = []
    if attempt_id:
        refs.append(f"attempt:{attempt_id}")
    refs.append(f"score:{score:.4f}")
    if goal:
        refs.append(f"goal:{goal[:200]}")
    if prompt:
        refs.append(f"prompt:{prompt[:400]}")
    if output:
        refs.append(f"output:{output[:400]}")
    return refs


def _finding_from_hit(
    *,
    probe: str,
    detector: str,
    score: float,
    attempt_id: str,
    prompt: str,
    output: str,
    goal: str,
    location: str,
    tool_version: str,
    seq: Any = None,
    attempt_idx: Any = None,
) -> NormalizedFinding:
    rid = _rule_id(probe, detector)
    orig_parts = [attempt_id or "", detector]
    if seq is not None and str(seq) != "":
        orig_parts.append(f"seq{seq}")
    if attempt_idx is not None and str(attempt_idx) != "":
        orig_parts.append(f"idx{attempt_idx}")
    original_id = ":".join(p for p in orig_parts if p) or rid
    title_probe = probe or "unknown probe"
    title_det = detector or "unknown detector"
    desc_bits = [
        f"Garak detector hit for probe `{title_probe}` via detector `{title_det}` "
        f"(score {score:.4f}, threshold {HIT_THRESHOLD})."
    ]
    if goal:
        desc_bits.append(f"Goal: {goal}")
    if prompt:
        desc_bits.append(f"Prompt: {prompt[:500]}")
    if output:
        desc_bits.append(f"Model output: {output[:500]}")
    return NormalizedFinding(
        tool="garak",
        rule_id=rid,
        original_id=original_id,
        variant=detector,
        tool_version=tool_version,
        title=f"Garak: {title_probe} / {title_det}",
        severity=_severity_from_score(score),
        location=location or probe or "",
        description="\n".join(desc_bits),
        recommendation=(
            "Review the prompt and model response, harden system instructions / "
            "guardrails for this probe class, and re-run garak after mitigation."
        ),
        cwe=parse_cwe(None),  # never invent CWE
        confidence=f"{score:.4f}",
        evidence_refs=_evidence_refs(
            prompt=prompt,
            output=output,
            score=score,
            attempt_id=attempt_id,
            goal=goal,
        ),
    )


def _parse_records(raw: bytes) -> list[dict]:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    try:
        if text.startswith("["):
            data = json.loads(text)
            if not isinstance(data, list):
                raise ValueError("garak JSON array root must be a list")
            records = data
        else:
            records = []
            for lineno, line in enumerate(text.splitlines(), start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"garak JSONL line {lineno} is not valid JSON: {exc}"
                    ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"garak input is not valid JSON/JSONL: {exc}") from exc

    if not records:
        return []
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            raise ValueError(
                f"garak record {i} must be a JSON object, got {type(rec).__name__}"
            )
    return records


def _is_hitlog_record(rec: dict) -> bool:
    """Standalone hitlog rows have probe/detector/score (and usually attempt_id)."""
    if rec.get("entry_type"):
        return False
    return (
        "detector" in rec
        and "score" in rec
        and ("probe" in rec or "attempt_id" in rec)
    )


def parse(raw: bytes) -> list[NormalizedFinding]:
    """Parse Garak report.jsonl or hitlog.jsonl bytes into NormalizedFinding list."""
    records = _parse_records(raw)
    if not records:
        return []

    tool_version = ""
    location = ""
    out: list[NormalizedFinding] = []
    seen_attempt_hits: set[tuple[str, str]] = set()

    # First pass: metadata from init / start_run setup
    for rec in records:
        et = rec.get("entry_type")
        if et == "init":
            tool_version = str(rec.get("garak_version") or tool_version or "")
        elif et == "start_run setup":
            plugins = rec.get("plugins") if isinstance(rec.get("plugins"), dict) else {}
            target_type = str(plugins.get("target_type") or rec.get("plugins.target_type") or "")
            target_name = str(plugins.get("target_name") or rec.get("plugins.target_name") or "")
            if target_type or target_name:
                location = f"{target_type} {target_name}".strip()
            ver = rec.get("_config.version") or rec.get("version")
            if ver and not tool_version:
                tool_version = str(ver)

    for rec in records:
        et = rec.get("entry_type")

        if et in (
            "init",
            "start_run setup",
            "eval",
            "probe_summary",
            "digest",
            "payload_init",
            "plugin_cache",
            "config",
            "tree_data",
        ):
            # Recognized non-finding (or aggregate) rows — do not emit findings.
            continue

        if et == "attempt":
            status = rec.get("status")
            try:
                status_i = int(status) if status is not None else -1
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"garak attempt status must be an int, got {status!r}"
                ) from exc
            if status_i != ATTEMPT_COMPLETE:
                continue

            detector_results = rec.get("detector_results")
            if detector_results is None:
                continue
            if not isinstance(detector_results, dict):
                raise ValueError(
                    "garak attempt detector_results must be an object "
                    f"mapping detector → scores, got {type(detector_results).__name__}"
                )

            probe = str(rec.get("probe_classname") or rec.get("probe") or "")
            attempt_id = str(rec.get("uuid") or "")
            goal = str(rec.get("goal") or "")
            prompt = _prompt_text(rec.get("prompt"))
            outputs = rec.get("outputs")
            seq = rec.get("seq")

            for detector, scores in detector_results.items():
                if scores is not None and not isinstance(scores, list):
                    raise ValueError(
                        f"garak detector_results[{detector!r}] must be a list of scores"
                    )
                hit_score = _max_hit_score(scores)
                if hit_score is None:
                    continue
                det = str(detector)
                key = (attempt_id or prompt, det)
                seen_attempt_hits.add(key)
                # Prefer the generation index of the max hit for evidence.
                hit_idx = None
                if isinstance(scores, list):
                    for i, raw_s in enumerate(scores):
                        try:
                            if raw_s is not None and float(raw_s) == hit_score:
                                hit_idx = i
                                break
                        except (TypeError, ValueError):
                            continue
                out.append(
                    _finding_from_hit(
                        probe=probe,
                        detector=det,
                        score=hit_score,
                        attempt_id=attempt_id,
                        prompt=prompt,
                        output=_output_text(outputs, hit_idx),
                        goal=goal,
                        location=location,
                        tool_version=tool_version,
                        seq=seq,
                        attempt_idx=hit_idx,
                    )
                )
            continue

        if _is_hitlog_record(rec):
            try:
                score = float(rec["score"])
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"garak hitlog score must be numeric, got {rec.get('score')!r}"
                ) from exc
            if score < HIT_THRESHOLD:
                continue
            probe = str(rec.get("probe") or "")
            detector = str(rec.get("detector") or "")
            attempt_id = str(rec.get("attempt_id") or "")
            key = (attempt_id or _prompt_text(rec.get("prompt")), detector)
            if key in seen_attempt_hits:
                continue
            gen = str(rec.get("generator") or "").strip()
            out.append(
                _finding_from_hit(
                    probe=probe,
                    detector=detector,
                    score=score,
                    attempt_id=attempt_id,
                    prompt=_prompt_text(rec.get("prompt")),
                    output=_output_text(
                        [rec["output"]] if "output" in rec else [],
                        0 if "output" in rec else None,
                    ),
                    goal=str(rec.get("goal") or ""),
                    location=gen or location,
                    tool_version=tool_version,
                    seq=rec.get("attempt_seq"),
                    attempt_idx=rec.get("attempt_idx"),
                )
            )
            continue

        if et is None and not _is_hitlog_record(rec):
            # Unknown object without entry_type and not a hitlog row.
            raise ValueError(
                "garak record missing entry_type and is not a hitlog row "
                f"(keys: {sorted(rec.keys())[:12]})"
            )

        if et is not None:
            # Unknown entry_type — quarantine rather than silently invent findings.
            raise ValueError(f"unsupported garak entry_type {et!r}")

    return out
