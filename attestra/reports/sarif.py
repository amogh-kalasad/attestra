"""Export findings as SARIF 2.1.0."""
# @lat: [[reports#Exports]]

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from attestra import services


def findings_to_sarif(s: Session, engagement_id: int) -> dict[str, Any]:
    """Produce a SARIF 2.1.0 log for engagement findings."""
    findings = services.list_findings(s, engagement_id)
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rule_id = f"CWE-{f.cwe}" if f.cwe else (f.rule_ids[0] if f.rule_ids else f"finding-{f.id}")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title[:80],
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": (f.description or f.title)[:2000]},
                "defaultConfiguration": {"level": _level(f.severity)},
                "properties": {"cwe": f"CWE-{f.cwe}" if f.cwe else "", "owasp": f.owasp_top10 or ""},
            }
        results.append(
            {
                "ruleId": rule_id,
                "level": _level(f.severity),
                "message": {"text": f.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.location or f"finding/{f.id}"},
                        }
                    }
                ],
                "properties": {
                    "findingId": f.id,
                    "status": f.status,
                    "riskScore": f.risk_score,
                    "cves": f.cves or [],
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Attestra",
                        "informationUri": "https://github.com/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def check_sarif_structure(doc: dict[str, Any]) -> list[str]:
    """Return a list of structural problems (empty if ok)."""
    errors = []
    if doc.get("version") != "2.1.0":
        errors.append("version must be 2.1.0")
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        errors.append("runs missing")
        return errors
    run = runs[0]
    if "tool" not in run or "driver" not in run.get("tool", {}):
        errors.append("tool.driver missing")
    if not isinstance(run.get("results"), list):
        errors.append("results missing")
    return errors


def _level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}.get(
        severity, "warning"
    )
