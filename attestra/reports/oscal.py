"""OSCAL Assessment Results / POA&M JSON export (simplified, structure-validated)."""
# @lat: [[reports#Exports]]

from __future__ import annotations

import json
from datetime import date
from typing import Any

from sqlalchemy.orm import Session

from attestra import __version__, services
from attestra.models import OPEN_STATUSES


def assessment_results(s: Session, engagement_id: int, framework: str) -> dict[str, Any]:
    eng = services.get_engagement(s, engagement_id)
    results = services.compliance(s, engagement_id, framework)
    return {
        "assessment-results": {
            "uuid": f"attestra-eng-{eng.id}-{framework}",
            "metadata": {
                "title": f"{eng.name} — {framework}",
                "last-modified": date.today().isoformat(),
                "version": __version__,
                "oscal-version": "1.1.2",
            },
            "results": [
                {
                    "uuid": f"result-{eng.id}",
                    "title": "Attestra security testing control roll-up",
                    "start": (eng.window_start or date.today()).isoformat(),
                    "findings": [
                        {
                            "uuid": f"ctrl-{r.ref}",
                            "title": r.title,
                            "description": r.reason,
                            "target": {"type": "objective-id", "target-id": r.ref},
                            "props": [
                                {"name": "status", "value": r.status},
                                {"name": "proposed", "value": r.proposed},
                            ],
                        }
                        for r in results
                    ],
                }
            ],
        }
    }


def poam(s: Session, engagement_id: int) -> dict[str, Any]:
    eng = services.get_engagement(s, engagement_id)
    findings = [f for f in services.list_findings(s, engagement_id) if f.status in OPEN_STATUSES]
    return {
        "plan-of-action-and-milestones": {
            "uuid": f"attestra-poam-{eng.id}",
            "metadata": {
                "title": f"POA&M — {eng.name}",
                "last-modified": date.today().isoformat(),
                "version": __version__,
                "oscal-version": "1.1.2",
            },
            "poam-items": [
                {
                    "uuid": f"finding-{f.id}",
                    "title": f.title,
                    "description": f.description or f.title,
                    "props": [
                        {"name": "severity", "value": f.severity},
                        {"name": "status", "value": f.status},
                        {"name": "sla-due", "value": str(f.sla_due or "")},
                    ],
                }
                for f in findings
            ],
        }
    }


def findings_csv(s: Session, engagement_id: int) -> str:
    import csv
    import io

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "severity", "status", "title", "cwe", "owasp_top10", "location", "sla_due"])
    for f in services.list_findings(s, engagement_id):
        w.writerow([f.id, f.severity, f.status, f.title, f.cwe or "", f.owasp_top10, f.location, f.sla_due or ""])
    return buf.getvalue()


def validate_oscal_structure(doc: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    """Lightweight required-key validation against a local schema fragment.

    ``schema["required_top_level"]`` lists top-level keys to require. Callers
    validating POA&M should set that from ``required_top_level_poam`` (via
    ``schema_for_oscal_kind``).
    """
    errors: list[str] = []
    required = schema.get("required_top_level") or []
    for key in required:
        if key not in doc:
            errors.append(f"missing top-level key {key}")
            continue
        nested_req = (schema.get("required_nested") or {}).get(key) or []
        node = doc[key]
        if not isinstance(node, dict):
            errors.append(f"{key} must be object")
            continue
        for nk in nested_req:
            if nk not in node:
                errors.append(f"missing {key}.{nk}")
    return errors


def schema_for_oscal_kind(schema: dict[str, Any], kind: str) -> dict[str, Any]:
    """Return a validate_oscal_structure schema for assessment-results or poam."""
    if kind in ("poam", "plan-of-action-and-milestones"):
        top = schema.get("required_top_level_poam") or ["plan-of-action-and-milestones"]
    else:
        top = schema.get("required_top_level_ar") or schema.get("required_top_level") or ["assessment-results"]
    return {
        "required_top_level": list(top),
        "required_nested": dict(schema.get("required_nested") or {}),
    }


def load_oscal_schema(path: str | None = None) -> dict[str, Any]:
    from pathlib import Path

    p = Path(path) if path else Path(__file__).resolve().parents[2] / "tests" / "schemas" / "oscal_ar_poam_min.json"
    return json.loads(p.read_text(encoding="utf-8"))
