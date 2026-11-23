"""Bounded, redacted, trust-labelled context assembly for an AASI run.

External target content is marked ``untrusted``. Raw evidence bodies, credentials,
and source code are never included. Output is a serializable ``ContextPacket``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from attestra import ai_narratives

__all__ = [
    "ContextPacket",
    "TRUSTED",
    "UNTRUSTED",
    "build_context_packet",
    "labelled",
]

TRUSTED = "trusted"
UNTRUSTED = "untrusted"

# Ledger statuses that represent incomplete / gap coverage.
_GAP_STATUSES = frozenset({"SKIPPED", "DEFERRED", "FAILED", "NOT_TESTED"})

# Adapter names treated as AI-security tools for available_test_ids.
_AI_ADAPTERS = frozenset({"garak", "promptfoo", "safelabs", "pyrit"})

# Asset fields allowed in metadata (never tokens, seeds, or raw notes bodies).
_ASSET_SAFE_KEYS = (
    "id",
    "kind",
    "name",
    "environment",
    "test_types",
    "intrusive_allowed",
    "criticality",
    "exposure",
    "in_cde",
    "owner",
)


def labelled(trust: str, value: Any) -> dict[str, Any]:
    """Wrap a value with a trust label for prompt assembly."""
    label = TRUSTED if trust == TRUSTED else UNTRUSTED
    return {"trust": label, "value": value}


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _redact_text(value: Any) -> str:
    return ai_narratives.redact(str(value or ""))


@dataclass
class ContextPacket:
    """Bounded context for one AASI recommend-only run (prompt-safe)."""

    engagement_id: int
    tenant_id: int | None = None
    objective: dict[str, Any] = field(default_factory=lambda: labelled(UNTRUSTED, ""))
    assets: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    coverage_gaps: list[dict[str, Any]] = field(default_factory=list)
    previous_summaries: list[dict[str, Any]] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)
    available_test_ids: list[str] = field(default_factory=list)
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable dict suitable for prompts / decision records."""
        return asdict(self)


def _prefer_ai_app(assets: Sequence[Any]) -> list[Any]:
    ai_first: list[Any] = []
    rest: list[Any] = []
    for a in assets:
        kind = str(_attr(a, "kind", "") or "").strip().lower()
        (ai_first if kind == "ai_app" else rest).append(a)
    return ai_first + rest


def _asset_entry(asset: Any) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    for key in _ASSET_SAFE_KEYS:
        val = _attr(asset, key, None)
        if val in (None, "", []):
            continue
        if key in ("name", "owner"):
            meta[key] = _redact_text(val)
        else:
            meta[key] = val
    # Identifier / notes are external target content — redacted + untrusted.
    identifier = _attr(asset, "identifier", None)
    if identifier not in (None, ""):
        meta["identifier"] = labelled(UNTRUSTED, _redact_text(identifier))
    notes = _attr(asset, "notes", None)
    if notes not in (None, ""):
        meta["notes"] = labelled(UNTRUSTED, _redact_text(notes))
    return labelled(TRUSTED, meta)


def _finding_ref(finding: Any) -> dict[str, Any]:
    fid = _attr(finding, "id", None)
    title = _redact_text(_attr(finding, "title", ""))
    severity = _attr(finding, "severity", None)
    status = _attr(finding, "status", None)
    ref: dict[str, Any] = {"id": fid, "title": title}
    if severity not in (None, ""):
        ref["severity"] = severity
    if status not in (None, ""):
        ref["status"] = status
    # Never attach description, recommendation, location, evidence, or credentials.
    return labelled(TRUSTED, ref)


def _gap_entry(row: Any) -> dict[str, Any] | None:
    status = str(_attr(row, "execution_status", _attr(row, "status", "")) or "").upper()
    if status and status not in _GAP_STATUSES:
        return None
    test_id = str(_attr(row, "test_id", "") or "").strip()
    category = str(_attr(row, "category", "") or "").strip()
    limitation = _redact_text(_attr(row, "limitation", _attr(row, "block_or_fail_reason", "")))
    endpoint = _attr(row, "target_endpoint", None)
    gap: dict[str, Any] = {
        "test_id": test_id,
        "category": category,
        "status": status or "SKIPPED",
    }
    if limitation:
        gap["limitation"] = limitation
    asset_id = _attr(row, "asset_id", None)
    if asset_id is not None:
        gap["asset_id"] = asset_id
    origin = _attr(row, "origin", None)
    if origin not in (None, ""):
        gap["origin"] = str(origin)
    if endpoint not in (None, ""):
        gap["target_endpoint"] = labelled(UNTRUSTED, _redact_text(endpoint))
    return labelled(TRUSTED, gap)


def _observation_id(obs: Any) -> str | None:
    if obs is None:
        return None
    if isinstance(obs, (int, str)):
        s = str(obs).strip()
        return s or None
    oid = _attr(obs, "id", None)
    if oid is None:
        return None
    s = str(oid).strip()
    return s or None


def _collect_available_test_ids(*, include_registry: bool, include_adapters: bool) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()

    def add(tid: str) -> None:
        t = str(tid or "").strip()
        if not t or t in seen:
            return
        seen.add(t)
        ids.append(t)

    if include_registry:
        try:
            from attestra.automated_vapt.core import test_registry

            for case in test_registry.list_test_cases():
                add(case.id)
        except Exception:  # noqa: BLE001 — context assembly must not fail closed on catalogue import
            pass
    if include_adapters:
        try:
            from attestra.runner.scanners.registry import list_adapters

            for name in list_adapters():
                if name in _AI_ADAPTERS:
                    add(name)
        except Exception:  # noqa: BLE001
            pass
    return ids


def build_context_packet(
    *,
    engagement_id: int,
    tenant_id: int | None = None,
    objective: str = "",
    assets: Sequence[Any] = (),
    findings: Sequence[Any] = (),
    coverage_ledger: Sequence[Any] = (),
    previous_summaries: Sequence[Any] = (),
    observations: Sequence[Any] = (),
    available_test_ids: Sequence[str] | None = None,
    include_test_registry: bool = True,
    include_adapters: bool = True,
    max_assets: int = 30,
    max_findings: int = 50,
    max_gaps: int = 40,
    max_summaries: int = 10,
    max_observations: int = 100,
) -> ContextPacket:
    """Assemble a bounded ``ContextPacket`` from run inputs (no DB I/O).

    ``objective``, asset identifiers/notes, and coverage endpoints are treated as
    untrusted external content. Finding refs carry redacted titles only.
    """
    ordered_assets = _prefer_ai_app(list(assets))[: max(0, int(max_assets))]
    asset_rows = [_asset_entry(a) for a in ordered_assets]

    finding_rows = [_finding_ref(f) for f in list(findings)[: max(0, int(max_findings))]]

    gaps: list[dict[str, Any]] = []
    for row in coverage_ledger:
        entry = _gap_entry(row)
        if entry is None:
            continue
        gaps.append(entry)
        if len(gaps) >= max(0, int(max_gaps)):
            break

    summaries: list[dict[str, Any]] = []
    for item in list(previous_summaries)[: max(0, int(max_summaries))]:
        if isinstance(item, dict) and "trust" in item:
            summaries.append(item)
        else:
            summaries.append(labelled(UNTRUSTED, _redact_text(item)))

    obs_ids: list[str] = []
    for obs in observations:
        oid = _observation_id(obs)
        if oid is None or oid in obs_ids:
            continue
        obs_ids.append(oid)
        if len(obs_ids) >= max(0, int(max_observations)):
            break

    if available_test_ids is not None:
        test_ids = [str(t).strip() for t in available_test_ids if str(t).strip()]
    else:
        test_ids = _collect_available_test_ids(
            include_registry=include_test_registry,
            include_adapters=include_adapters,
        )

    return ContextPacket(
        engagement_id=int(engagement_id),
        tenant_id=tenant_id,
        objective=labelled(UNTRUSTED, _redact_text(objective)),
        assets=asset_rows,
        findings=finding_rows,
        coverage_gaps=gaps,
        previous_summaries=summaries,
        observation_ids=obs_ids,
        available_test_ids=test_ids,
    )
