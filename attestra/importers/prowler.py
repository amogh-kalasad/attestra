"""Prowler importer: JSON-OCSF output (v4+) and the legacy JSON list (v3)."""

from __future__ import annotations

from attestra.importers._jsonutil import load_json_or_lines
from attestra.importers.base import NormalizedFinding, norm_severity


def _ocsf(item: dict) -> NormalizedFinding | None:
    if str(item.get("status_code", "")).upper() != "FAIL":
        return None
    info = item.get("finding_info") or {}
    meta = item.get("metadata") or {}
    resources = item.get("resources") or [{}]
    res = resources[0] or {}
    location = res.get("uid") or res.get("name") or (item.get("cloud") or {}).get("account", {}).get("uid", "")
    remediation = item.get("remediation") or {}
    return NormalizedFinding(
        tool="prowler",
        rule_id=meta.get("event_code") or info.get("uid", ""),
        title=info.get("title") or meta.get("event_code") or "Prowler check failed",
        severity=norm_severity(item.get("severity")),
        location=str(location),
        description=item.get("status_detail") or info.get("desc", "") or "",
        recommendation=remediation.get("desc", "") or "",
        cwe=16,
        param=meta.get("event_code", "") or "",
    )


def _legacy(item: dict) -> NormalizedFinding | None:
    if str(item.get("Status", "")).upper() != "FAIL":
        return None
    rec = ((item.get("Remediation") or {}).get("Recommendation") or {}).get("Text", "")
    return NormalizedFinding(
        tool="prowler",
        rule_id=item.get("CheckID", ""),
        title=item.get("CheckTitle") or item.get("CheckID") or "Prowler check failed",
        severity=norm_severity(item.get("Severity")),
        location=str(item.get("ResourceArn") or item.get("ResourceId") or item.get("AccountId") or ""),
        description=item.get("StatusExtended", "") or item.get("Description", "") or "",
        recommendation=rec or "",
        cwe=16,
        param=item.get("CheckID", "") or "",
    )


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = load_json_or_lines(raw)
    items = doc if isinstance(doc, list) else [doc]
    out: list[NormalizedFinding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        nf = _ocsf(item) if "status_code" in item or "finding_info" in item else _legacy(item)
        if nf:
            out.append(nf)
    return out
