"""Gitleaks importer (`--report-format json`). The secret value itself is never kept."""

from __future__ import annotations

from attestra.importers._jsonutil import load_json_or_lines
from attestra.importers.base import NormalizedFinding


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = load_json_or_lines(raw)
    items = doc if isinstance(doc, list) else []
    out: list[NormalizedFinding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        rule = item.get("RuleID", "") or "secret"
        file = item.get("File", "")
        line = item.get("StartLine", "")
        commit = (item.get("Commit") or "")[:12]
        desc = item.get("Description") or f"Hard-coded secret ({rule})"
        out.append(
            NormalizedFinding(
                tool="gitleaks",
                rule_id=rule,
                title=f"Hard-coded secret: {desc}"[:500],
                severity="high",
                location=f"{file}:{line}" if line != "" else file,
                description=f"Gitleaks rule {rule} matched" + (f" in commit {commit}." if commit else "."),
                recommendation="Revoke and rotate the credential, remove it from history, and load it from a secret store.",
                cwe=798,
                param=rule,
            )
        )
    return out
