"""Trivy JSON importer (`--format json`): vulnerable packages and misconfigurations."""

from __future__ import annotations

import json

from attestra.importers.base import NormalizedFinding, norm_severity, parse_cwe


def _cvss(v: dict) -> tuple[float | None, str]:
    for source in ("nvd", "ghsa", "redhat"):
        entry = (v.get("CVSS") or {}).get(source)
        if entry:
            if entry.get("V3Score") is not None:
                return float(entry["V3Score"]), entry.get("V3Vector", "")
            if entry.get("V40Score") is not None:
                return float(entry["V40Score"]), entry.get("V40Vector", "")
    return None, ""


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = json.loads(raw)
    artifact = doc.get("ArtifactName", "")
    out: list[NormalizedFinding] = []
    for result in doc.get("Results", []) or []:
        target = result.get("Target", artifact)
        for v in result.get("Vulnerabilities", []) or []:
            score, vector = _cvss(v)
            fixed = v.get("FixedVersion") or ""
            rec = f"Upgrade {v.get('PkgName')} to {fixed} or later." if fixed else "No fixed version published; apply vendor mitigation or replace the component."
            vid = v.get("VulnerabilityID", "")
            out.append(
                NormalizedFinding(
                    tool="trivy",
                    rule_id=vid,
                    title=v.get("Title") or f"{vid} in {v.get('PkgName')}",
                    severity=norm_severity(v.get("Severity")),
                    location=f"{artifact or target}::{target}",
                    description=v.get("Description", "") or "",
                    recommendation=rec,
                    cwe=parse_cwe(v.get("CweIDs")),
                    cves=[vid] if vid.upper().startswith("CVE-") else [],
                    cvss_score=score,
                    cvss_vector=vector,
                    package=f"{v.get('PkgName')}@{v.get('InstalledVersion')}",
                )
            )
        for m in result.get("Misconfigurations", []) or []:
            if m.get("Status") == "PASS":
                continue
            out.append(
                NormalizedFinding(
                    tool="trivy",
                    rule_id=m.get("ID", ""),
                    title=m.get("Title", "Misconfiguration"),
                    severity=norm_severity(m.get("Severity")),
                    location=f"{target}",
                    description=m.get("Description", "") or "",
                    recommendation=m.get("Resolution", "") or "",
                    cwe=16,  # CWE-16 Configuration
                    param=m.get("ID", ""),
                )
            )
    return out
