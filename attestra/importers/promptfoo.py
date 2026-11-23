"""Promptfoo `eval -o results.json` / `redteam run -o results.json` importer.

Failed assertions (``success: false``, assertion failure) become
[[attestra/importers/base.py#NormalizedFinding]] with ``tool="promptfoo"``.
Passed tests produce no findings. Provider/runtime errors (``failureReason`` 2)
are skipped. CWE is set only when the source supplies one.
"""
# @lat: [[import-pipeline#Promptfoo importer]]

from __future__ import annotations

import json
from typing import Any

from attestra.importers.base import NormalizedFinding, norm_severity, parse_cwe

# promptfoo ResultFailureReason.ERROR — provider/runtime failure, not a vuln.
_FAILURE_ERROR = 2

_SUPPORTED_VERSIONS = frozenset({2, 3})


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _tool_version(doc: dict[str, Any]) -> str:
    meta = _as_dict(doc.get("metadata"))
    for key in ("promptfooVersion", "version", "toolVersion"):
        v = _as_str(meta.get(key))
        if v:
            return v
    return ""


def _unwrap_summary(doc: dict[str, Any]) -> tuple[dict[str, Any], list[Any]]:
    """Return (summary_dict, results_list) from a wrapped or bare export."""
    # Wrapped export: { evalId, results: EvaluateSummaryV3, config, metadata }
    nested = doc.get("results")
    if isinstance(nested, dict) and isinstance(nested.get("results"), list):
        version = nested.get("version")
        if version is not None and version not in _SUPPORTED_VERSIONS:
            raise ValueError(f"Unsupported promptfoo results version: {version!r}")
        return nested, nested["results"]

    # Bare EvaluateSummaryV3: { version, results: [...], prompts, stats, ... }
    if isinstance(doc.get("results"), list):
        version = doc.get("version")
        if version is not None and version not in _SUPPORTED_VERSIONS:
            raise ValueError(f"Unsupported promptfoo results version: {version!r}")
        return doc, doc["results"]

    raise ValueError(
        "Unsupported promptfoo structure: expected results.results[] "
        "or top-level results[] (EvaluateSummary v2/v3)"
    )


def _meta_for(row: dict[str, Any]) -> dict[str, Any]:
    """Merge row metadata with testCase.metadata (row wins on conflict)."""
    test_case = _as_dict(row.get("testCase"))
    merged = dict(_as_dict(test_case.get("metadata")))
    merged.update(_as_dict(row.get("metadata")))
    return merged


def _plugin_id(meta: dict[str, Any], grading: dict[str, Any]) -> str:
    for source in (meta, _as_dict(grading.get("metadata"))):
        for key in ("pluginId", "plugin"):
            v = _as_str(source.get(key))
            if v:
                return v
    return ""


def _strategy_id(meta: dict[str, Any], grading: dict[str, Any]) -> str:
    for source in (meta, _as_dict(grading.get("metadata"))):
        for key in ("strategyId", "strategy"):
            v = _as_str(source.get(key))
            if v:
                return v
    return ""


def _source_cwe(meta: dict[str, Any], grading: dict[str, Any]) -> int | None:
    for source in (meta, _as_dict(grading.get("metadata"))):
        for key in ("cwe", "cweId", "cwe_id"):
            if key in source and source[key] not in (None, ""):
                return parse_cwe(source[key])
    return None


def _provider_location(row: dict[str, Any]) -> str:
    provider = row.get("provider")
    if isinstance(provider, dict):
        label = _as_str(provider.get("label"))
        pid = _as_str(provider.get("id"))
        if label and pid and label != pid:
            return f"{label} ({pid})"
        return label or pid
    return _as_str(provider)


def _title(plugin: str, strategy: str, meta: dict[str, Any], grading: dict[str, Any]) -> str:
    harm = _as_str(meta.get("harmCategory") or meta.get("harm_category"))
    if harm and plugin:
        base = f"{harm} ({plugin})"
    elif plugin:
        base = f"Promptfoo red-team: {plugin}"
    else:
        assertion = _as_dict(grading.get("assertion"))
        atype = _as_str(assertion.get("type")) or "assertion"
        base = f"Promptfoo failed assertion: {atype}"
    if strategy:
        base = f"{base} [{strategy}]"
    return base[:500]


def _description(row: dict[str, Any], meta: dict[str, Any], grading: dict[str, Any]) -> str:
    parts: list[str] = []
    reason = _as_str(grading.get("reason") or row.get("error"))
    if reason:
        parts.append(reason)
    goal = _as_str(meta.get("goal"))
    if goal:
        parts.append(f"Goal: {goal}")
    test_case = _as_dict(row.get("testCase"))
    desc = _as_str(test_case.get("description") or row.get("description"))
    if desc:
        parts.append(f"Test: {desc}")
    response = _as_dict(row.get("response"))
    output = _as_str(response.get("output"))
    if output:
        parts.append(f"Output (truncated): {output[:400]}")
    return "\n".join(parts)


def _is_assertion_failure(row: dict[str, Any]) -> bool:
    if row.get("success") is True:
        return False
    failure_reason = row.get("failureReason")
    if failure_reason == _FAILURE_ERROR:
        return False
    # success false, or explicit gradingResult.pass false
    grading = _as_dict(row.get("gradingResult"))
    if grading and grading.get("pass") is False:
        return True
    if row.get("success") is False:
        return True
    return False


def _finding_from_row(
    row: dict[str, Any],
    *,
    tool_version: str,
) -> NormalizedFinding | None:
    if not _is_assertion_failure(row):
        return None

    grading = _as_dict(row.get("gradingResult"))
    meta = _meta_for(row)
    plugin = _plugin_id(meta, grading)
    strategy = _strategy_id(meta, grading)
    test_idx = row.get("testIdx")
    row_id = _as_str(row.get("id"))

    rule_id = plugin or _as_str(_as_dict(grading.get("assertion")).get("type")) or "promptfoo-assert"
    # Keep plugin and strategy discoverable on rule_id / original_id.
    if plugin and strategy:
        original_id = f"{plugin}/{strategy}"
        if test_idx is not None:
            original_id = f"{original_id}#{test_idx}"
    elif plugin:
        original_id = f"{plugin}#{test_idx}" if test_idx is not None else plugin
    elif strategy:
        original_id = f"{strategy}#{test_idx}" if test_idx is not None else strategy
    else:
        original_id = row_id or (f"test#{test_idx}" if test_idx is not None else rule_id)

    severity_raw = meta.get("severity")
    severity = norm_severity(_as_str(severity_raw)) if severity_raw not in (None, "") else "medium"

    return NormalizedFinding(
        tool="promptfoo",
        rule_id=rule_id,
        title=_title(plugin, strategy, meta, grading),
        severity=severity,
        location=_provider_location(row),
        description=_description(row, meta, grading),
        recommendation="",
        cwe=_source_cwe(meta, grading),
        tool_version=tool_version,
        original_id=original_id,
        variant=strategy,
        param=_as_str(test_idx) if test_idx is not None else "",
        evidence_refs=[row_id] if row_id else [],
    )


def parse(raw: bytes) -> list[NormalizedFinding]:
    """Parse promptfoo JSON export bytes into normalized findings."""
    text = raw.decode("utf-8-sig", errors="replace").strip()
    if not text:
        return []
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid promptfoo JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise ValueError("Unsupported promptfoo structure: top-level value must be an object")

    _summary, rows = _unwrap_summary(doc)
    tool_version = _tool_version(doc)

    out: list[NormalizedFinding] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        finding = _finding_from_row(row, tool_version=tool_version)
        if finding is not None:
            out.append(finding)
    return out
