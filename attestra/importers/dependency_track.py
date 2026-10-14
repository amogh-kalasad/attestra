"""OWASP Dependency-Track findings export (``GET /api/v1/finding/project/{uuid}``,
or the FPF ``{"project":..., "findings":[...]}`` file). Suppressed findings are skipped."""

from __future__ import annotations

import json

from attestra.importers.base import NormalizedFinding, norm_severity, parse_cwe


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = json.loads(raw)
    project = ""
    if isinstance(doc, dict):
        project = (doc.get("project") or {}).get("name", "")
        items = doc.get("findings", []) or []
    else:
        items = doc
    out: list[NormalizedFinding] = []
    for it in items:
        if (it.get("analysis") or {}).get("isSuppressed"):
            continue
        comp = it.get("component") or {}
        vuln = it.get("vulnerability") or {}
        vid = vuln.get("vulnId", "")
        cproj = comp.get("project")
        proj = project or (cproj.get("name", "") if isinstance(cproj, dict) else cproj or "") or "dependency-track"
        score = vuln.get("cvssV3BaseScore") or vuln.get("cvssV2BaseScore")
        cwe = parse_cwe([c.get("cweId") for c in vuln.get("cwes", []) or []] or vuln.get("cweId"))
        out.append(
            NormalizedFinding(
                tool="dependency_track",
                rule_id=vid,
                title=vuln.get("title") or f"{vid} in {comp.get('name')}",
                severity=norm_severity(vuln.get("severity")),
                location=f"{proj}::{comp.get('purl') or comp.get('name', '')}",
                description=vuln.get("description", "") or "",
                recommendation=vuln.get("recommendation", "") or "Upgrade the affected component to a fixed version.",
                cwe=cwe,
                cves=[vid] if vid.upper().startswith("CVE-") else [],
                cvss_score=float(score) if score is not None else None,
                cvss_vector=vuln.get("cvssV3Vector", "") or "",
                package=f"{comp.get('name')}@{comp.get('version', '')}",
            )
        )
    return out
