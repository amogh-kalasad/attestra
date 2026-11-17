"""CycloneDX JSON importer (SBOM with a ``vulnerabilities`` section, VEX/VDR).

Components alone are an inventory, not findings; only listed vulnerabilities
become findings. Vulnerabilities whose VEX analysis says ``not_affected``,
``false_positive`` or ``resolved`` are skipped.
"""

from __future__ import annotations

import json

from attestra.importers.base import NormalizedFinding, norm_severity, parse_cwe

_SKIP_STATES = {"not_affected", "false_positive", "resolved", "resolved_with_pedigree"}


def _best_rating(ratings: list[dict]) -> tuple[str, float | None, str]:
    best = ("", None, "")
    for r in ratings or []:
        score = r.get("score")
        sev = r.get("severity", "")
        vector = r.get("vector", "")
        if score is not None and (best[1] is None or float(score) > best[1]):
            best = (sev or best[0], float(score), vector)
        elif not best[0] and sev:
            best = (sev, best[1], best[2])
    return best


def parse(raw: bytes) -> list[NormalizedFinding]:
    doc = json.loads(raw)
    if doc.get("bomFormat") != "CycloneDX":
        raise ValueError("not a CycloneDX document (bomFormat != CycloneDX)")
    root = ((doc.get("metadata") or {}).get("component") or {})
    root_name = root.get("name", "") or "sbom"
    comps: dict[str, dict] = {}

    def walk(items):
        for c in items or []:
            if c.get("bom-ref"):
                comps[c["bom-ref"]] = c
            walk(c.get("components"))

    walk(doc.get("components"))
    out: list[NormalizedFinding] = []
    for v in doc.get("vulnerabilities", []) or []:
        if ((v.get("analysis") or {}).get("state") or "") in _SKIP_STATES:
            continue
        vid = v.get("id", "")
        sev, score, vector = _best_rating(v.get("ratings"))
        cwe = parse_cwe(v.get("cwes"))
        refs = [a.get("ref") for a in v.get("affects", []) or [] if a.get("ref")] or [""]
        for ref in refs:
            c = comps.get(ref, {})
            pkg = f"{c.get('name', ref)}@{c.get('version', '')}" if (c or ref) else ""
            out.append(
                NormalizedFinding(
                    tool="cyclonedx",
                    rule_id=vid,
                    title=f"{vid} in {c.get('name', ref) or root_name}",
                    severity=norm_severity(sev),
                    location=f"{root_name}::{c.get('purl') or ref or root_name}",
                    description=v.get("description", "") or v.get("detail", "") or "",
                    recommendation=v.get("recommendation", "") or "Upgrade the affected component to a fixed version.",
                    cwe=cwe,
                    cves=[vid] if vid.upper().startswith("CVE-") else [],
                    cvss_score=score,
                    cvss_vector=vector,
                    package=pkg,
                )
            )
    return out
