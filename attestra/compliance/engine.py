"""Maps findings to framework controls and proposes a status per control.

The engine proposes; a named assessor confirms (ControlAssessment). A confirmed
status always wins over the proposal.
"""
# @lat: [[compliance]]
# @lat: [[architecture#Propose then confirm]]

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from functools import lru_cache
from pathlib import Path

import yaml

from attestra.models import OPEN_STATUSES, ControlAssessment, Engagement, Finding

DATA = Path(__file__).parent / "data"
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class Library:
    frameworks: dict
    objectives: dict
    titles: dict
    cwe_map: dict
    default_objectives: tuple


@lru_cache(maxsize=1)
def load_library() -> Library:
    controls = yaml.safe_load((DATA / "controls.yaml").read_text())
    cwe = yaml.safe_load((DATA / "cwe_map.yaml").read_text())
    return Library(
        frameworks=controls["frameworks"],
        objectives=controls["objectives"],
        titles=controls.get("control_titles", {}),
        cwe_map={int(k): v for k, v in (cwe.get("cwe") or {}).items()},
        default_objectives=tuple(cwe.get("default", ["vuln_identification"])),
    )


def objectives_for(finding: Finding, lib: Library | None = None) -> list[str]:
    lib = lib or load_library()
    objs = set(lib.default_objectives)
    if finding.cwe and finding.cwe in lib.cwe_map:
        objs.update(lib.cwe_map[finding.cwe])
    if finding.cves:
        objs.update({"patching", "vuln_identification"})
    return sorted(objs)


def in_framework_scope(finding: Finding, framework: str) -> bool:
    """PCI DSS applies to the cardholder data environment. Findings on assets marked
    out of CDE are excluded; findings with no matched asset stay in (conservative)."""
    if framework == "pci_dss_4":
        return finding.asset is None or finding.asset.in_cde
    return True


@dataclass
class ControlResult:
    framework: str
    ref: str
    title: str
    objectives: list[str]
    proposed: str  # met | no_exceptions | partial | not_met | not_assessed
    reason: str
    finding_ids: list[int] = field(default_factory=list)
    confirmed: str | None = None
    assessor: str = ""
    rationale: str = ""

    @property
    def status(self) -> str:
        return self.confirmed or self.proposed


def _finding_status(open_findings: list[Finding]) -> tuple[str, str]:
    if not open_findings:
        return "no_exceptions", "Testing found no exceptions; the assessor must confirm the control with its own evidence."
    worst = max(open_findings, key=lambda f: SEVERITY_RANK.get(f.severity, 0))
    rank = SEVERITY_RANK.get(worst.severity, 0)
    n = len(open_findings)
    if rank >= 3:
        return "not_met", f"{n} open finding(s); worst is {worst.severity}."
    if rank == 2:
        return "partial", f"{n} open finding(s); worst is medium."
    return "no_exceptions", f"Only {n} low/info finding(s) open, tracked for remediation; assessor to confirm."


def _process_status(rule: str, eng: Engagement, findings: list[Finding], import_count: int) -> tuple[str, str]:
    if rule == "has_imports":
        if import_count:
            return "met", f"{import_count} scan result file(s) imported for this engagement."
        return "not_assessed", "No scan results imported yet."
    if rule == "has_valid_authorization":
        valid = [a for a in eng.authorizations if a.is_valid(date.today())]
        if valid:
            return "met", f"Signed authorization on file ({valid[0].document_name}, signer {valid[0].signer})."
        return "not_met", "No currently valid signed authorization on file."
    if rule == "has_validated_pt":
        if eng.type not in ("pt", "vapt", "retest"):
            return "not_assessed", f"Engagement type '{eng.type}' does not include penetration testing."
        validated = [f for f in findings if f.validated_by]
        if validated:
            return "met", f"{len(validated)} finding(s) manually validated by a tester."
        return "partial", "PT engagement recorded but no tester validation yet."
    if rule == "no_open_high_after_retest":
        open_high = [f for f in findings if f.status in OPEN_STATUSES and SEVERITY_RANK.get(f.severity, 0) >= 3]
        retested = [f for f in findings if f.status == "retest_passed"]
        if open_high:
            return "not_met", f"{len(open_high)} critical/high finding(s) still open."
        if retested or not findings:
            return "met", f"{len(retested)} finding(s) passed retest; no open critical/high."
        return "partial", "No open critical/high, but no retest recorded yet."
    return "not_assessed", f"Unknown rule '{rule}'."


def evaluate(
    eng: Engagement,
    findings: list[Finding],
    assessments: list[ControlAssessment],
    import_count: int,
    framework: str,
    lib: Library | None = None,
) -> list[ControlResult]:
    lib = lib or load_library()
    if framework not in lib.frameworks:
        raise ValueError(f"Unknown framework '{framework}'")

    open_by_objective: dict[str, list[Finding]] = {}
    for f in findings:
        if f.status not in OPEN_STATUSES:
            continue
        if not in_framework_scope(f, framework):
            continue
        for obj in objectives_for(f, lib):
            open_by_objective.setdefault(obj, []).append(f)

    # Collect per control ref, since several objectives can feed one ref (e.g. ISO A.8.8).
    results: dict[str, ControlResult] = {}
    # When several objectives feed one ref, the weakest claim wins.
    order = {"not_met": 4, "partial": 3, "not_assessed": 2, "no_exceptions": 1, "met": 0}
    for key, obj in lib.objectives.items():
        refs = obj.get("controls", {}).get(framework, [])
        if not refs:
            continue
        if obj["kind"] == "finding":
            open_f = open_by_objective.get(key, [])
            status, reason = _finding_status(open_f)
            ids = [f.id for f in open_f]
        else:
            status, reason = _process_status(obj["rule"], eng, findings, import_count)
            ids = []
        for ref in refs:
            cur = results.get(ref)
            if cur is None:
                results[ref] = ControlResult(
                    framework=framework,
                    ref=ref,
                    title=lib.titles.get(framework, {}).get(ref, ""),
                    objectives=[key],
                    proposed=status,
                    reason=f"[{obj['name']}] {reason}",
                    finding_ids=ids,
                )
            else:
                cur.objectives.append(key)
                cur.finding_ids = sorted(set(cur.finding_ids) | set(ids))
                cur.reason += f" [{obj['name']}] {reason}"
                if order[status] > order[cur.proposed]:
                    cur.proposed = status

    for a in assessments:
        if a.framework == framework and a.control_ref in results:
            r = results[a.control_ref]
            r.confirmed, r.assessor, r.rationale = a.status, a.assessor, a.rationale

    return sorted(results.values(), key=_ref_sort_key)


def _ref_sort_key(r: ControlResult):
    parts = []
    for p in r.ref.replace("Clause ", "Z.").replace("CC", "").replace("A.", "").split("."):
        parts.append(int(p) if p.isdigit() else 999)
    return parts
