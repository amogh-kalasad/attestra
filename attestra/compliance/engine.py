"""Maps findings to framework controls and proposes a status per control.

The engine proposes; a named assessor confirms (ControlAssessment). A confirmed
status always wins over the proposal.
"""
# @lat: [[compliance]]
# @lat: [[architecture#Propose then confirm]]

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, timedelta
from functools import lru_cache
from pathlib import Path

import yaml

from attestra.models import OPEN_STATUSES, ControlAssessment, Engagement, Finding

DATA = Path(__file__).parent / "data"
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class CweMapping:
    objectives: tuple[str, ...]
    strength: str  # full | partial
    rationale: str


@dataclass(frozen=True)
class Library:
    frameworks: dict
    objectives: dict
    titles: dict
    cwe_map: dict[int, CweMapping]
    default_objectives: tuple


def _parse_cwe_entry(value) -> CweMapping:
    if isinstance(value, list):
        return CweMapping(objectives=tuple(value), strength="full", rationale="Legacy list mapping.")
    objs = tuple(value.get("objectives") or [])
    return CweMapping(
        objectives=objs,
        strength=str(value.get("strength") or ""),
        rationale=str(value.get("rationale") or "").strip(),
    )


def _merge_pack(pack: dict, frameworks: dict, objectives: dict, titles: dict) -> None:
    """Add one YAML framework pack (compliance/data/packs/*.yaml) to the hub.

    A pack only adds refs to existing objectives, so every CWE mapping reaches it
    with no code changes."""
    fw = str(pack.get("framework") or "")
    if not fw or fw in frameworks:
        raise ValueError(f"framework pack {fw!r} is missing or already defined")
    pack_titles = dict(pack.get("titles") or {})
    for obj, refs in (pack.get("controls") or {}).items():
        if obj not in objectives:
            raise ValueError(f"pack {fw}: unknown objective {obj!r}")
        for ref in refs:
            if ref not in pack_titles:
                raise ValueError(f"pack {fw}: ref {ref!r} has no title")
        objectives[obj].setdefault("controls", {})[fw] = list(refs)
    frameworks[fw] = {"name": pack["name"], "pack": pack.get("pack", "framework pack"), "source": "pack"}
    titles[fw] = pack_titles


@lru_cache(maxsize=1)
def load_library() -> Library:
    controls = yaml.safe_load((DATA / "controls.yaml").read_text(encoding="utf-8"))
    cwe = yaml.safe_load((DATA / "cwe_map.yaml").read_text(encoding="utf-8"))
    frameworks = dict(controls["frameworks"])
    objectives = controls["objectives"]
    titles = dict(controls.get("control_titles", {}))
    for path in sorted((DATA / "packs").glob("*.yaml")):
        _merge_pack(yaml.safe_load(path.read_text(encoding="utf-8")), frameworks, objectives, titles)
    return Library(
        frameworks=frameworks,
        objectives=objectives,
        titles=titles,
        cwe_map={int(k): _parse_cwe_entry(v) for k, v in (cwe.get("cwe") or {}).items()},
        default_objectives=tuple(cwe.get("default", ["vuln_identification"])),
    )


def clear_library_cache() -> None:
    load_library.cache_clear()


def objectives_for(finding: Finding, lib: Library | None = None) -> list[str]:
    lib = lib or load_library()
    objs = set(lib.default_objectives)
    if finding.cwe and finding.cwe in lib.cwe_map:
        objs.update(lib.cwe_map[finding.cwe].objectives)
    if finding.cves:
        objs.update({"patching", "vuln_identification"})
    return sorted(objs)


def mapping_for_cwe(cwe: int, lib: Library | None = None) -> CweMapping | None:
    lib = lib or load_library()
    return lib.cwe_map.get(cwe)


STRENGTH_RANK = {"full": 2, "partial": 1}


def mappings_for_objective(findings: list[Finding], objective: str, lib: Library | None = None) -> list[dict]:
    """C7: the CWE mappings (strength + rationale from cwe_map.yaml) that link these
    findings to one objective. One entry per CWE, sorted by CWE id."""
    lib = lib or load_library()
    seen: dict[int, dict] = {}
    for f in findings:
        m = lib.cwe_map.get(f.cwe) if f.cwe else None
        if m and objective in m.objectives and f.cwe not in seen:
            seen[f.cwe] = {"cwe": f.cwe, "objective": objective, "strength": m.strength, "rationale": m.rationale}
    return [seen[k] for k in sorted(seen)]


def _apply_mappings(r: ControlResult, new: list[dict]) -> None:
    known = {(m["cwe"], m["objective"]) for m in r.mappings}
    r.mappings.extend(m for m in new if (m["cwe"], m["objective"]) not in known)
    if not r.mappings:
        return
    # The weakest mapping sets the control's strength: one partial link is a partial claim.
    r.mapping_strength = min((m["strength"] for m in r.mappings), key=lambda s: STRENGTH_RANK.get(s, 0))
    rationales: list[str] = []
    for m in r.mappings:
        line = f"CWE-{m['cwe']} ({m['strength']}): {m['rationale']}"
        if line not in rationales:
            rationales.append(line)
    r.mapping_rationale = " ".join(rationales)


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
    mapping_strength: str = ""
    mapping_rationale: str = ""
    mappings: list[dict] = field(default_factory=list)

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


def _in_current_quarter(d: date, today: date | None = None) -> bool:
    today = today or date.today()
    q_start_month = ((today.month - 1) // 3) * 3 + 1
    q_start = date(today.year, q_start_month, 1)
    if q_start_month == 10:
        q_end = date(today.year, 12, 31)
    else:
        q_end = date(today.year, q_start_month + 3, 1) - timedelta(days=1)
    return q_start <= d <= q_end


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
    if rule == "asv_passing_scan":
        scans = list(getattr(eng, "asv_scans", None) or [])
        passing = [a for a in scans if a.passing and _in_current_quarter(a.scan_date)]
        if passing:
            a = passing[0]
            return "met", f"Passing ASV scan on file ({a.vendor}, {a.scan_date})."
        if scans:
            return "not_met", "ASV scan(s) on file but none passing in the current quarter."
        return "not_assessed", "No ASV scan attestation recorded."
    if rule == "segmentation_tested":
        tests = list(getattr(eng, "segmentation_tests", None) or [])
        ok = [t for t in tests if (t.result or "").lower() in ("pass", "passed", "met")]
        if ok:
            t = ok[0]
            return "met", f"Segmentation test passed ({t.boundary}, {t.tested_on})."
        if tests:
            return "not_met", "Segmentation test(s) recorded but none passed."
        return "not_assessed", "No segmentation test recorded."
    if rule == "internal_scan_quarterly":
        schedules = list(getattr(eng, "scan_schedules", None) or [])
        # Prefer schedule evidence; fall back to any import in the quarter via import count.
        due_ok = any(sch.cadence == "quarterly" and sch.last_enqueued_at for sch in schedules)
        if due_ok or import_count:
            # Mark met if we have a quarterly schedule that has fired, or imports exist this engagement.
            # Strict quarter cleanliness is tracked separately via ScanSchedule.quarter_clean.
            clean = [sch for sch in schedules if sch.cadence == "quarterly" and sch.quarter_clean]
            if clean:
                return "met", "Quarterly internal scan schedule marked clean (no open high/critical)."
            if due_ok or import_count:
                return "partial", "Internal scans present; quarter not yet marked clean of high/critical."
        return "not_assessed", "No quarterly internal scan schedule or imports."
    if rule == "has_risk_assessment":
        acceptances = list(getattr(eng, "risk_acceptances", None) or [])
        # Engagement-level risk analysis evidenced by at least one risk acceptance or assessor note.
        # Also met when any ControlAssessment exists for 12.3.1 / Clause 6.1.2 (handled by confirm).
        if acceptances:
            return "met", f"{len(acceptances)} risk acceptance record(s) on file."
        # Presence of any confirmed control assessment on this engagement counts as assessment activity.
        assessments = list(getattr(eng, "control_assessments", None) or [])
        if assessments:
            return "partial", "Control assessments present; document targeted risk analysis for full credit."
        return "not_assessed", "No risk acceptance or control assessment records yet."
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
            maps = mappings_for_objective(open_f, key, lib)
        else:
            status, reason = _process_status(obj["rule"], eng, findings, import_count)
            ids = []
            maps = []
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
                _apply_mappings(results[ref], maps)
            else:
                cur.objectives.append(key)
                cur.finding_ids = sorted(set(cur.finding_ids) | set(ids))
                cur.reason += f" [{obj['name']}] {reason}"
                if order[status] > order[cur.proposed]:
                    cur.proposed = status
                _apply_mappings(cur, maps)

    for a in assessments:
        if a.framework == framework and a.control_ref in results:
            r = results[a.control_ref]
            r.confirmed, r.assessor, r.rationale = a.status, a.assessor, a.rationale

    return sorted(results.values(), key=_ref_sort_key)


def _ref_sort_key(r: ControlResult):
    parts = []
    ref = r.ref.replace("Clause ", "Z.").replace("CC", "").replace("A.", "")
    for p in re.split(r"[.\-()]+", ref):
        if p:
            parts.append((0, int(p), "") if p.isdigit() else (1, 0, p))
    return parts
