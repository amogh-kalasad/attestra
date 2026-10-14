"""SARIF 2.1.0 importer (Semgrep, CodeQL, Checkov, Gitleaks, Trivy --format sarif, and others)."""

from __future__ import annotations

import json

from attestra.importers.base import NormalizedFinding, norm_severity, parse_cwe
from attestra.scoring import severity_from_cvss

LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def _rule_cwe(rule: dict) -> int | None:
    props = rule.get("properties", {}) or {}
    for key in ("cwe", "CWE"):
        if key in props:
            return parse_cwe(props[key])
    return parse_cwe(props.get("tags", []))


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = json.loads(raw)
    out: list[NormalizedFinding] = []
    for run in doc.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool = (driver.get("name") or "sarif").lower()
        rules = {r.get("id"): r for r in driver.get("rules", []) or []}
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or ""
            rule = rules.get(rule_id, {})
            props = rule.get("properties", {}) or {}
            cvss = None
            if props.get("security-severity"):
                try:
                    cvss = float(props["security-severity"])
                except ValueError:
                    cvss = None
            if cvss is not None:
                severity = severity_from_cvss(cvss)
            else:
                severity = norm_severity(LEVEL_TO_SEVERITY.get(res.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")))
            loc = ""
            for l in res.get("locations", []) or []:
                pl = l.get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "")
                line = pl.get("region", {}).get("startLine")
                loc = f"{uri}:{line}" if line else uri
                break
            title = (rule.get("shortDescription", {}) or {}).get("text") or rule.get("name") or rule_id
            out.append(
                NormalizedFinding(
                    tool=tool,
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    location=loc,
                    description=(res.get("message", {}) or {}).get("text", ""),
                    recommendation=(rule.get("help", {}) or {}).get("text", ""),
                    cwe=_rule_cwe(rule),
                    cvss_score=cvss,
                )
            )
    return out
