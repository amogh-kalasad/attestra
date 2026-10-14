"""kube-bench importer (`kube-bench run --json`): failed and warned CIS checks."""

from __future__ import annotations

from attestra.importers._jsonutil import load_json_or_lines
from attestra.importers.base import NormalizedFinding


def _controls(doc) -> list[dict]:
    if isinstance(doc, list):
        return [c for c in doc if isinstance(c, dict)]
    if isinstance(doc, dict):
        if "Controls" in doc:
            return list(doc.get("Controls") or [])
        return [doc]
    return []


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = load_json_or_lines(raw)
    out: list[NormalizedFinding] = []
    for control in _controls(doc):
        node = control.get("node_type") or control.get("id") or "node"
        for group in control.get("tests") or []:
            for r in group.get("results") or []:
                status = str(r.get("status", "")).upper()
                if status not in ("FAIL", "WARN"):
                    continue
                # Scored failures are real benchmark failures; warnings need a manual check.
                severity = "medium" if status == "FAIL" and r.get("scored", True) else "low"
                number = str(r.get("test_number", ""))
                out.append(
                    NormalizedFinding(
                        tool="kube_bench",
                        rule_id=f"CIS-{number}" if number else "CIS",
                        title=r.get("test_desc") or f"CIS Kubernetes {number}",
                        severity=severity,
                        location=f"k8s:{node}",
                        description=f"{status}: {r.get('reason', '') or r.get('audit', '') or ''}".strip(),
                        recommendation=r.get("remediation", "") or "",
                        cwe=16,
                        param=number,
                    )
                )
    return out
