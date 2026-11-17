"""subfinder importer (``-json``): passive subdomain names → discovery observations (A-02).

Discovery output is never a finding: :func:`parse` validates the file and returns ``[]``
so ``services.import_results`` creates nothing, while :func:`parse_observations` turns
each row into an :class:`~attestra.discovery.candidates.Observation` for the candidate
pipeline. Shared JSON-lines helpers for the dnsx and httpx-probe importers live here.
"""
# @lat: [[attack-surface-and-platform#Discovery adapters]]

from __future__ import annotations

import json

from attestra.importers.base import NormalizedFinding

MAX_ROWS = 50_000


class DiscoveryParseError(ValueError):
    pass


def json_rows(raw: bytes, tool: str) -> list[dict]:
    """JSON Lines (or one JSON array). Tolerates one truncated *last* line (tool killed
    mid-write); any other bad line, or a file with no valid row, raises."""
    text = raw.decode("utf-8-sig", errors="replace").strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DiscoveryParseError(f"{tool}: invalid JSON array") from exc
        rows = [r for r in doc if isinstance(r, dict)]
        if doc and not rows:
            raise DiscoveryParseError(f"{tool}: no JSON objects")
        return rows[:MAX_ROWS]
    lines = [ln for ln in text.splitlines() if ln.strip()]
    rows: list[dict] = []
    for i, line in enumerate(lines):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            if i == len(lines) - 1 and rows:
                break  # partial last line
            raise DiscoveryParseError(f"{tool}: line {i + 1} is not JSON") from exc
        if not isinstance(obj, dict):
            raise DiscoveryParseError(f"{tool}: line {i + 1} is not a JSON object")
        rows.append(obj)
        if len(rows) >= MAX_ROWS:
            break
    if lines and not rows:
        raise DiscoveryParseError(f"{tool}: no valid rows")
    return rows


def _seen(row: dict) -> str:
    return str(row.get("timestamp") or "")[:40]


def parse_observations(raw: bytes) -> list:
    from attestra.discovery.candidates import Observation

    out = []
    seen: set[str] = set()
    for row in json_rows(raw, "subfinder"):
        host = str(row.get("host") or "").strip().lower()
        if not host:
            raise DiscoveryParseError("subfinder: row without host")
        key = f"{host}|{row.get('source') or ''}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Observation(
                name=host,
                source="subfinder",
                seen_at=_seen(row),
                detail={"via": str(row.get("source") or "")[:60], "input": str(row.get("input") or "")[:253]},
            )
        )
    return out


def parse(raw: bytes) -> list[NormalizedFinding]:
    parse_observations(raw)  # validate; discovery never yields findings
    return []
