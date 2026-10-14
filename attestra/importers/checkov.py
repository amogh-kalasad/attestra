"""Checkov importer (`-o json`): failed IaC checks. Accepts one report or a list of them."""

from __future__ import annotations

from attestra.importers._jsonutil import load_json_or_lines
from attestra.importers.base import NormalizedFinding, norm_severity


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = load_json_or_lines(raw)
    reports = doc if isinstance(doc, list) else [doc]
    out: list[NormalizedFinding] = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        for c in (report.get("results") or {}).get("failed_checks") or []:
            lines = c.get("file_line_range") or []
            start = lines[0] if lines else ""
            path = (c.get("repo_file_path") or c.get("file_path") or "").lstrip("/")
            check_id = c.get("check_id", "")
            out.append(
                NormalizedFinding(
                    tool="checkov",
                    rule_id=check_id,
                    title=c.get("check_name") or check_id or "Checkov check failed",
                    severity=norm_severity(c.get("severity")) if c.get("severity") else "medium",
                    location=f"{path}:{start}" if start != "" else path,
                    description=f"{report.get('check_type', '')} resource {c.get('resource', '')}".strip(),
                    recommendation=c.get("guideline", "") or "",
                    cwe=16,
                    param=f"{check_id}:{c.get('resource', '')}",
                )
            )
    return out
