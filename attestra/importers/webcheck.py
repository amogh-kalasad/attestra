"""Importer for attestra webcheck JSON reports."""

from __future__ import annotations

import json

from attestra.importers.base import NormalizedFinding, norm_severity, parse_cwe


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
    items = doc.get("findings") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        return []
    out: list[NormalizedFinding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        fid = str(item.get("id") or "").strip()
        if not fid:
            continue
        out.append(
            NormalizedFinding(
                tool="webcheck",
                rule_id=f"webcheck/{fid}",
                variant=fid,
                title=str(item.get("title") or fid),
                severity=norm_severity(str(item.get("severity") or "info")),
                location=str(item.get("location") or ""),
                description=str(item.get("description") or ""),
                recommendation=str(item.get("recommendation") or ""),
                cwe=parse_cwe(item.get("cwe")),
            )
        )
    return out
