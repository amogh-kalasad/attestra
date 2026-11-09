"""Automatic WSTG/ASVS checklist updates from completed scans and automated VAPT runs.

Conservative by design:

* A raised finding / alerted rule marks the mapped item ``failed`` (note lists finding ids).
* A check that demonstrably ran clean marks the item ``passed`` with
  ``auto: <source> ... no issues`` - only where the tool actually executes that check.
* A skipped / not-ready case marks the item ``blocked`` with the reason, never ``passed``.
* Items a human edited are never touched (``updated_by`` other than ``attestra-auto``).
* ``failed`` is only cleared by a newer clean result from the *same* source and only when
  every linked finding is ``fixed`` / ``retest_passed``.
* Only the run's own engagement (and its tenant) is updated.
"""
# @lat: [[architecture#Authenticated website testing]]

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

AUTO_ACTOR = "attestra-auto"
AUTO_PREFIX = "auto:"
FIXED_FINDING_STATUSES = ("fixed", "retest_passed")
_OPENABLE = ("not_started", "not_tested", "blocked")
_PRIORITY = {"failed": 3, "blocked": 2, "passed": 1}

# ------------------------------------------------------------------ mapping tables
# ZAP plugin ids (alert pluginid / checks_json "zap/<id>").  ``pass`` lists catalog rules that
# ZAP Baseline always runs (see checks.ZAP_BASELINE_CHECK_CATALOG); an item is passed only
# when *all* of them ran with no alert.  Items without ``pass`` can only fail (active rules or
# non-catalog passive rules: we cannot prove they ran).
ZAP_MAP: dict[str, dict[str, tuple[str, ...]]] = {
    "WSTG-CONF-12": {"rules": ("10038", "10055"), "pass": ("10038", "10055")},
    "WSTG-SESS-02": {"rules": ("10010", "10011", "10054"), "pass": ("10010", "10011", "10054")},
    "WSTG-INFO-02": {"rules": ("10036", "10037")},
    "WSTG-INPV-01": {"rules": ("40012", "40014", "40016", "40017", "40026")},
    "WSTG-INPV-05": {"rules": ("40018", "40019", "40020", "40021", "40022", "40024", "40027", "90018")},
    "WSTG-SESS-05": {"rules": ("10202", "20012")},
    "WSTG-ATHZ-01": {"rules": ("6", "7")},
    "WSTG-BUSL-09": {"rules": ("40046",)},
}

# Nuclei template ids (finding original_id, ``template`` or ``template:matcher``).  Fail-only:
# nuclei reports matches, not which templates ran clean.
NUCLEI_MAP: tuple[tuple[str, re.Pattern[str], re.Pattern[str] | None], ...] = (
    ("WSTG-CONF-12", re.compile(r"(^|[-:])csp([-:]|$)|content-security-policy"), None),
    ("WSTG-SESS-02", re.compile(r"cookie"), None),
    ("WSTG-INFO-02", re.compile(r"version-(detect|disclosure)|server-version|x-powered-by|banner"), None),
    ("WSTG-BUSL-09", re.compile(r"ssrf"), None),
    ("WSTG-INPV-01", re.compile(r"xss"), re.compile(r"xss-deprecated-header|x-xss-protection")),
    ("WSTG-INPV-05", re.compile(r"sqli|sql-injection"), None),
    ("WSTG-ATHZ-01", re.compile(r"(^|-)lfi(-|$)|path-traversal|directory-traversal"), None),
    ("WSTG-ATHN-02", re.compile(r"default-login"), None),
    (
        "WSTG-CRYP-01",
        re.compile(r"weak-cipher|deprecated-tls|expired-ssl|self-signed-ssl|mismatched-ssl|untrusted-root|revoked-ssl"),
        None,
    ),
)

# webcheck check ids (checks_json rows) -> item; pass when the row is ``passed``.
WEBCHECK_MAP: dict[str, tuple[str, ...]] = {
    "WSTG-SESS-02": ("cookie-flags",),
    "WSTG-CONF-12": ("csp-policy",),
    "WSTG-ATHN-01": ("http-no-redirect",),
}

# testssl: any non-info finding fails CRYP-01; a scanned report with none passes it.
TESTSSL_REF = "WSTG-CRYP-01"

# Automated VAPT case -> items.  T03-T07 are harness modules: fail-only.
AUTOMATED_MAP: dict[str, tuple[str, ...]] = {
    "T19": ("WSTG-ATHN-04",),
    "T20": ("WSTG-ATHZ-04",),
    "T21": ("WSTG-INPV-05", "WSTG-INPV-01"),
    "T22": ("WSTG-ATHZ-04",),
    "T03": ("WSTG-ATHN-04",),
    "T04": ("WSTG-ATHZ-04",),
    "T05": ("WSTG-ATHZ-02",),
    "T06": ("WSTG-ATHZ-02",),
    "SESSION": ("WSTG-SESS-02",),
    "INJ": ("WSTG-INPV-05",),
    "XSS": ("WSTG-INPV-01",),
    "FILE": ("WSTG-ATHZ-01",),
    "BIZ": ("WSTG-ATHZ-04",),
    "ROLEDIFF": ("WSTG-ATHZ-02",),
}

# Never set automatically (need a human / no tool coverage today).
MANUAL_ONLY: tuple[str, ...] = (
    "WSTG-CONF-01",
    "WSTG-ATHN-07",
    "WSTG-ATHZ-02",
    "ASVS-V2.1.1",
    "ASVS-V4.1.1",
)


@dataclass
class Verdict:
    ref: str
    status: str  # passed | failed | blocked
    source: str  # zap | nuclei | testssl | webcheck | automated_vapt
    label: str  # human label of the run, e.g. "zap import #9 (scan #19, baseline)"
    text: str
    finding_ids: list[int] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ helpers
def _base_rule(original_id: str) -> str:
    return (original_id or "").split("-", 1)[0].strip()


def _canonical_ids(s: Session, ids: Iterable[int]) -> list[int]:
    from attestra.models import Finding

    out: list[int] = []
    for fid in ids:
        f = s.get(Finding, int(fid))
        while f is not None and getattr(f, "merged_into_id", None):
            nxt = s.get(Finding, f.merged_into_id)
            if nxt is None or nxt.id == f.id:
                break
            f = nxt
        if f is not None and f.id not in out:
            out.append(f.id)
    return out


def _describe(s: Session, ids: list[int], limit: int = 6) -> str:
    from attestra.models import Finding

    parts = []
    for fid in ids[:limit]:
        f = s.get(Finding, fid)
        parts.append(f"#{fid} {(f.title if f else '')[:80]}".strip())
    more = f" (+{len(ids) - limit} more)" if len(ids) > limit else ""
    return "; ".join(parts) + more


def _observations(s: Session, import_run_id: int) -> list[Any]:
    from attestra.models import FindingObservation

    return list(s.scalars(select(FindingObservation).where(FindingObservation.import_run_id == import_run_id)))


def _scan_for_import(s: Session, run: Any) -> Any:
    from attestra.models import ScanRun

    return s.scalars(select(ScanRun).where(ScanRun.import_run_id == run.id).order_by(ScanRun.id.desc())).first()


def _import_label(run: Any, scan: Any) -> str:
    label = f"{run.tool} import #{run.id}"
    if scan is not None:
        label += f" (scan #{scan.id}, {scan.profile or 'baseline'})"
    return label


def _evidence_refs(run: Any, scan: Any) -> list[str]:
    refs = [f"import_run:{run.id}"]
    if scan is not None:
        refs.append(f"scan_run:{scan.id}")
    return refs


# ------------------------------------------------------------------ verdicts: imports
def verdicts_for_import(s: Session, run: Any) -> list[Verdict]:
    """Checklist verdicts implied by one completed ImportRun (zap/nuclei/testssl/webcheck)."""
    from attestra import checks

    tool = (run.tool or "").lower()
    scan = _scan_for_import(s, run)
    label = _import_label(run, scan)
    ev = _evidence_refs(run, scan)
    obs = _observations(s, run.id)
    rows = checks.load_checks_json(getattr(run, "checks_json", None))
    if not rows and scan is not None:
        rows = checks.load_checks_json(getattr(scan, "checks_json", None))
    row_status = {str(r.get("id")): str(r.get("status") or "") for r in rows}
    out: list[Verdict] = []
    # Authenticated scan whose session died mid-run (re-login failed): "no alerts" after the
    # loss is unauthenticated coverage, so passed verdicts below are downgraded to blocked.
    from attestra.auth_web.session_guard import note_has_auth_loss

    auth_lost = scan is not None and bool(getattr(scan, "authenticated", False)) and note_has_auth_loss(
        getattr(scan, "auth_note", "")
    )

    if tool == "zap":
        for ref, spec in ZAP_MAP.items():
            rules = spec["rules"]
            alerted = {r for r in rules if row_status.get(f"zap/{r}") == checks.FAILED}
            hit_obs = [o for o in obs if (o.tool or "zap").lower() == "zap" and _base_rule(o.original_id) in rules]
            alerted |= {_base_rule(o.original_id) for o in hit_obs}
            if alerted:
                fids = _canonical_ids(s, [o.finding_id for o in hit_obs])
                txt = f"ZAP rule(s) {', '.join(sorted(alerted))} alerted"
                if fids:
                    txt += f" -> findings {_describe(s, fids)}"
                out.append(Verdict(ref, "failed", "zap", label, txt, fids, ev))
                continue
            need = spec.get("pass") or ()
            if need and all(row_status.get(f"zap/{r}") == checks.PASSED for r in need):
                out.append(
                    Verdict(
                        ref,
                        "passed",
                        "zap",
                        label,
                        f"no issues (ZAP passive rules {', '.join(need)} ran with no alerts)",
                        [],
                        ev,
                    )
                )
    elif tool == "nuclei":
        for ref, pat, exclude in NUCLEI_MAP:
            hit = [
                o
                for o in obs
                if pat.search((o.original_id or "").lower())
                and not (exclude and exclude.search((o.original_id or "").lower()))
            ]
            if hit:
                fids = _canonical_ids(s, [o.finding_id for o in hit])
                tids = sorted({o.original_id for o in hit})
                out.append(
                    Verdict(
                        ref,
                        "failed",
                        "nuclei",
                        label,
                        f"nuclei template(s) {', '.join(tids[:5])} matched -> findings {_describe(s, fids)}",
                        fids,
                        ev,
                    )
                )
    elif tool == "testssl":
        hit = [o for o in obs if (o.severity or "info").lower() not in ("info", "")]
        if hit:
            fids = _canonical_ids(s, [o.finding_id for o in hit])
            out.append(
                Verdict(
                    TESTSSL_REF,
                    "failed",
                    "testssl",
                    label,
                    f"TLS weaknesses -> findings {_describe(s, fids)}",
                    fids,
                    ev,
                )
            )
        elif _testssl_scanned(run):
            out.append(Verdict(TESTSSL_REF, "passed", "testssl", label, "no issues (no TLS weakness reported)", [], ev))
    elif tool == "webcheck":
        for ref, ids in WEBCHECK_MAP.items():
            failed = [i for i in ids if row_status.get(i) == checks.FAILED]
            hit = [o for o in obs if any((o.original_id or "").startswith(i) for i in ids)]
            if failed or hit:
                fids = _canonical_ids(s, [o.finding_id for o in hit])
                txt = f"webcheck {', '.join(failed or sorted({o.original_id for o in hit}))} failed"
                if fids:
                    txt += f" -> findings {_describe(s, fids)}"
                out.append(Verdict(ref, "failed", "webcheck", label, txt, fids, ev))
            elif all(row_status.get(i) == checks.PASSED for i in ids):
                out.append(
                    Verdict(ref, "passed", "webcheck", label, f"no issues (webcheck {', '.join(ids)} passed)", [], ev)
                )
    if auth_lost:
        loss = str(getattr(scan, "auth_note", "") or "")[:200]
        out = [
            Verdict(v.ref, "blocked", v.source, v.label, f"blocked: authenticated session lost mid-scan ({loss})", v.finding_ids, v.evidence)
            if v.status == "passed"
            else v
            for v in out
        ]
    return out


def _testssl_scanned(run: Any) -> bool:
    try:
        from attestra import services
        from attestra.importers import testssl as testssl_importer

        raw = services._read_bytes(getattr(run, "raw_path", "") or "")
        return bool(raw) and bool(testssl_importer.summarize(raw).get("scanned"))
    except Exception:  # noqa: BLE001
        return False


# ------------------------------------------------------------------ verdicts: automated runs
def _cases(ex: Any) -> list[dict[str, Any]]:
    try:
        data = json.loads(ex.result_json or "{}")
    except (TypeError, ValueError):
        return []
    cases = data.get("cases") if isinstance(data, dict) else None
    return [c for c in (cases or []) if isinstance(c, dict)]


def verdicts_for_automated(s: Session, ex: Any) -> list[Verdict]:
    """Checklist verdicts implied by one COMPLETED AutomatedTestExecution."""
    if (getattr(ex, "status", "") or "").upper() != "COMPLETED":
        return []
    out: list[Verdict] = []
    for case in _cases(ex):
        tid = str(case.get("test_id") or "")
        refs = AUTOMATED_MAP.get(tid)
        if not refs:
            continue
        status = str(case.get("status") or "").upper()
        detail = str(case.get("detail") or "")[:300]
        label = f"automated run #{ex.id} {tid}"
        ev = [f"automated_run:{ex.id}:{tid}"]
        fids = _canonical_ids(s, [case["finding_id"]]) if case.get("finding_id") else []
        real = tid in ("T19", "T20", "T21", "T22", "SESSION", "INJ", "XSS", "FILE", "BIZ", "ROLEDIFF", "SSRF", "UPLOAD")
        # SKIPPED / FAILED / DEFERRED / BLOCKED (mid-scan auth loss) never become checklist
        # passed — record blocked with reason.
        if status in ("SKIPPED", "FAILED", "DEFERRED", "BLOCKED"):
            if real and tid != "T22":
                prefix = "deferred" if status == "DEFERRED" else "blocked"
                note = f"{prefix}: {detail}" if detail else f"{prefix}: {tid} {status.lower()} — not executed as full coverage"
                for ref in refs:
                    out.append(Verdict(ref, "blocked", "automated_vapt", label, note, [], ev))
            continue
        if tid == "T21":
            out.extend(_t21_verdicts(s, case, label, ev, fids))
            continue
        if status == "FINDING":
            for ref in refs:
                txt = f"{detail}" + (f" -> findings {_describe(s, fids)}" if fids else "")
                out.append(Verdict(ref, "failed", "automated_vapt", label, txt, fids, ev))
            continue
        if status != "PASSED" or not real:
            continue
        if tid == "T19":
            out.append(Verdict(refs[0], "passed", "automated_vapt", label, f"no issues ({detail})", [], ev))
        elif tid == "T20":
            sec = case.get("secondary_auth") or {}
            if (sec.get("status") or "") == "ready":
                out.append(Verdict(refs[0], "passed", "automated_vapt", label, f"no issues ({detail})", [], ev))
            else:
                out.append(
                    Verdict(
                        refs[0],
                        "blocked",
                        "automated_vapt",
                        label,
                        "blocked: IDOR probe ran with a single (admin) profile and no secondary non-admin "
                        "profile - cannot prove object-level authorization; add a second login profile",
                        [],
                        ev,
                    )
                )
        elif tid == "SESSION":
            out.append(
                Verdict(
                    refs[0],
                    "passed",
                    "automated_vapt",
                    label,
                    f"session cookie/JWT observation completed ({detail})",
                    [],
                    ev,
                )
            )
        elif tid in ("INJ", "XSS", "FILE"):
            # Limited common-path canaries are not full category coverage — stay blocked.
            out.append(
                Verdict(
                    refs[0],
                    "blocked",
                    "automated_vapt",
                    label,
                    f"blocked: limited common-path canary probes only; full coverage not tested ({detail})",
                    [],
                    ev,
                )
            )
        # T22 PASSED alone never proves ATHZ-04 (it only replays one mutation).
    return out


def _t21_verdicts(s: Session, case: dict[str, Any], label: str, ev: list[str], fids: list[int]) -> list[Verdict]:
    """T21 per-payload signals: sqli_* -> INPV-05, reflected xss_script -> INPV-01."""
    sqli_hits: list[str] = []
    xss_hits: list[str] = []
    clean = 0
    for ep in case.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        meta = ep.get("meta") or {}
        st = str(ep.get("status") or "").upper()
        where = f"{meta.get('endpoint') or ep.get('url') or '?'} [{meta.get('param') or '?'}]"
        if st == "PASSED":
            clean += 1
        elif st == "FINDING":
            payload = str(meta.get("payload") or "")
            reason = str(ep.get("detail") or "")
            if payload.startswith("sqli"):
                sqli_hits.append(f"{where}: {reason}")
            elif payload.startswith("xss") and "reflect" in reason.lower():
                xss_hits.append(f"{where}: {reason}")
    out: list[Verdict] = []
    note_f = f" -> findings {_describe(s, fids)}" if fids else ""
    if sqli_hits:
        out.append(
            Verdict(
                "WSTG-INPV-05",
                "failed",
                "automated_vapt",
                label,
                "quote payload broke the request (error-based SQLi indicator, verify manually): "
                + "; ".join(sqli_hits[:3])
                + note_f,
                fids,
                ev,
            )
        )
    elif clean:
        # Limited probe only — do not mark passed (honesty: blind/time-based not covered).
        out.append(
            Verdict(
                "WSTG-INPV-05",
                "blocked",
                "automated_vapt",
                label,
                f"limited coverage: error-based quote probes on {clean} endpoint param(s); "
                "blind/time-based SQLi not covered",
                [],
                ev,
            )
        )
    if xss_hits:
        out.append(
            Verdict(
                "WSTG-INPV-01",
                "failed",
                "automated_vapt",
                label,
                "XSS payload reflected unescaped: " + "; ".join(xss_hits[:3]) + note_f,
                fids,
                ev,
            )
        )
    elif clean:
        # Limited API reflection probe — HTML forms/DOM not covered; never auto-pass.
        out.append(
            Verdict(
                "WSTG-INPV-01",
                "blocked",
                "automated_vapt",
                label,
                f"limited coverage: <script> reflection probe on {clean} API endpoint param(s); "
                "HTML forms/DOM not covered",
                [],
                ev,
            )
        )
    return out


# ------------------------------------------------------------------ applying
def is_manual(item: Any) -> bool:
    """True when a human owns the row (never overwritten automatically)."""
    by = item.updated_by or ""
    if by == AUTO_ACTOR:
        return not (item.notes or "").startswith(AUTO_PREFIX)
    if by:
        return True
    return item.status != "not_started"


def _line(v: Verdict) -> str:
    return f"- [{v.source}] {v.label}: {v.text}"


def _lines(notes: str) -> list[str]:
    return [ln for ln in (notes or "").splitlines()[1:] if ln.startswith("- [")]


def _line_source(line: str) -> str:
    m = re.match(r"^- \[(\w+)\]", line)
    return m.group(1) if m else ""


def _upsert(lines: list[str], v: Verdict, *, same_source: bool) -> list[str]:
    """Replace the line for the same run (or, when ``same_source``, any line of that source) in place."""
    new = _line(v)
    out: list[str] = []
    placed = False
    for ln in lines:
        match = ln.startswith(f"- [{v.source}] {v.label}:") or (same_source and _line_source(ln) == v.source)
        if match:
            if not placed:
                out.append(new)
                placed = True
            continue
        out.append(ln)
    if not placed:
        out.append(new)
    return out


def _compose(status: str, lines: list[str]) -> str:
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    return f"{AUTO_PREFIX} {status} by {AUTO_ACTOR} at {stamp}\n" + "\n".join(lines)


def _combine(verdicts: list[Verdict]) -> list[Verdict]:
    """One verdict per ref per event: failed > blocked > passed."""
    by_ref: dict[str, list[Verdict]] = {}
    for v in verdicts:
        by_ref.setdefault(v.ref, []).append(v)
    out = []
    for ref, vs in by_ref.items():
        top = max(_PRIORITY[v.status] for v in vs)
        chosen = [v for v in vs if _PRIORITY[v.status] == top]
        first = chosen[0]
        fids: list[int] = []
        ev: list[str] = []
        for v in chosen:
            fids += [f for f in v.finding_ids if f not in fids]
            ev += [e for e in v.evidence if e not in ev]
        label = " + ".join(dict.fromkeys(v.label for v in chosen))
        text = " | ".join(v.text for v in chosen)
        out.append(Verdict(ref, first.status, first.source, label, text, fids, ev))
    return out


def _findings_fixed(s: Session, ids: list) -> bool:
    from attestra.models import Finding

    for fid in ids or []:
        try:
            f = s.get(Finding, int(fid))
        except (TypeError, ValueError):
            return False
        if f is None or f.status not in FIXED_FINDING_STATUSES:
            return False
    return True


def apply_verdicts(
    s: Session, engagement_id: int, verdicts: list[Verdict], *, record_audit: bool = True
) -> list[dict[str, Any]]:
    """Apply verdicts to the engagement checklist; returns a list of change/skip records."""
    from attestra import audit
    from attestra.auth_web.checklists import (
        ensure_checklist,
        notes_imply_incomplete_coverage,
        update_checklist_item,
    )
    from attestra.models import Engagement

    verdicts = [v for v in verdicts if v.ref not in MANUAL_ONLY]
    if not verdicts:
        return []
    eng = s.get(Engagement, engagement_id)
    if eng is None:
        return []
    items = {
        i.ref: i
        for i in ensure_checklist(s, engagement_id, eng.tenant_id)
        if i.tenant_id == eng.tenant_id and i.engagement_id == engagement_id
    }
    results: list[dict[str, Any]] = []
    for v in _combine(verdicts):
        item = items.get(v.ref)
        if item is None:
            continue
        rec = {"ref": v.ref, "from": item.status, "to": item.status, "source": v.label, "action": "unchanged"}
        if is_manual(item):
            rec["action"] = "skipped_manual"
            results.append(rec)
            continue
        cur = item.status
        lines = _lines(item.notes)
        new_status = None
        fids = [f for f in (item.finding_ids or [])]
        if v.status == "failed":
            lines = _upsert(lines if cur == "failed" else [], v, same_source=False)
            fids = (fids if cur == "failed" else []) + [
                f for f in v.finding_ids if f not in (fids if cur == "failed" else [])
            ]
            new_status = "failed"
        elif v.status == "passed":
            if cur == "failed":
                srcs = {_line_source(ln) for ln in lines}
                if srcs != {v.source}:
                    rec["action"] = "kept_failed_other_source"
                    results.append(rec)
                    continue
                if not _findings_fixed(s, fids):
                    rec["action"] = "kept_failed_findings_open"
                    results.append(rec)
                    continue
                lines = []
            elif cur == "blocked":
                lines = []
            lines = _upsert(lines if cur == "passed" else [], v, same_source=True)
            new_status = "passed"
        elif v.status == "blocked":
            if cur not in _OPENABLE:
                rec["action"] = f"kept_{cur}"
                results.append(rec)
                continue
            lines = _upsert(lines if cur == "blocked" else [], v, same_source=True)
            new_status = "blocked"
        if new_status is None:
            continue
        evidence = list(item.evidence_ids or [])
        evidence += [e for e in v.evidence if e not in evidence]
        # Never auto-upgrade blocked → passed without evidence refs.
        if new_status == "passed" and cur == "blocked" and not evidence:
            rec["action"] = "kept_blocked_no_evidence"
            results.append(rec)
            continue
        if (
            new_status == cur
            and lines == _lines(item.notes)
            and fids == list(item.finding_ids or [])
            and evidence == list(item.evidence_ids or [])
        ):
            results.append(rec)  # idempotent re-sync: nothing new
            continue
        notes = _compose(new_status, lines)
        # Honesty gate: incomplete-coverage notes must not become passed via auto-apply.
        if new_status == "passed" and notes_imply_incomplete_coverage(notes):
            rec["action"] = "refused_incomplete_notes"
            results.append(rec)
            continue
        update_checklist_item(
            s,
            item.id,
            status=new_status,
            notes=notes,
            evidence_ids=evidence,
            finding_ids=fids,
            actor=AUTO_ACTOR,
        )
        if record_audit:
            audit.record(
                s,
                AUTO_ACTOR,
                "checklist.auto_update",
                "auth_checklist_item",
                item.id,
                engagement_id=engagement_id,
                ref=v.ref,
                status_from=cur,
                status_to=new_status,
                source=v.label,
            )
        rec.update({"to": new_status, "action": "updated", "finding_ids": fids})
        results.append(rec)
    return results


def apply_import_run(s: Session, run: Any, *, record_audit: bool = True) -> list[dict[str, Any]]:
    return apply_verdicts(s, run.engagement_id, verdicts_for_import(s, run), record_audit=record_audit)


def apply_automated_run(s: Session, ex: Any, *, record_audit: bool = True) -> list[dict[str, Any]]:
    from attestra.models import Engagement

    eng = s.get(Engagement, ex.engagement_id)
    if eng is None or (getattr(ex, "tenant_id", None) and eng.tenant_id and ex.tenant_id != eng.tenant_id):
        return []
    return apply_verdicts(s, ex.engagement_id, verdicts_for_automated(s, ex), record_audit=record_audit)


def _safely(fn, s: Session, obj: Any) -> list[dict[str, Any]] | None:
    try:
        with s.begin_nested():
            return fn(s, obj)
    except Exception:  # noqa: BLE001 - checklist sync must never break an import / run
        log.warning(
            "checklist auto-update failed for %s #%s", type(obj).__name__, getattr(obj, "id", "?"), exc_info=True
        )
        return None


def apply_import_run_safely(s: Session, run: Any) -> list[dict[str, Any]] | None:
    return _safely(apply_import_run, s, run)


def apply_automated_run_safely(s: Session, ex: Any) -> list[dict[str, Any]] | None:
    return _safely(apply_automated_run, s, ex)


# ------------------------------------------------------------------ backfill
def _ts(v: Any) -> float:
    if v is None:
        return 0.0
    try:
        return v.replace(tzinfo=None).timestamp() if isinstance(v, datetime) else 0.0
    except (OverflowError, OSError, ValueError):
        return 0.0


def sync_engagement(s: Session, engagement_id: int, *, dry_run: bool = False) -> dict[str, Any]:
    """Backfill: replay every completed import / automated run of one engagement in time order.

    Auto-owned rows are rebuilt from scratch (deterministic, idempotent); rows a human edited
    are left alone.  Rows whose rebuilt state equals the stored state are restored untouched.
    """
    from attestra import audit
    from attestra.auth_web.checklists import ensure_checklist, list_checklist
    from attestra.models import AutomatedTestExecution, Engagement, ImportRun

    eng = s.get(Engagement, engagement_id)
    if eng is None:
        raise LookupError(f"engagement {engagement_id} not found")
    events: list[tuple[float, str, Any]] = []
    for run in s.scalars(select(ImportRun).where(ImportRun.engagement_id == engagement_id)):
        events.append((_ts(run.imported_at), "import", run))
    for ex in s.scalars(
        select(AutomatedTestExecution).where(
            AutomatedTestExecution.engagement_id == engagement_id,
            AutomatedTestExecution.status == "COMPLETED",
        )
    ):
        events.append((_ts(ex.ended_at), "automated", ex))
    events.sort(key=lambda e: (e[0], e[1], e[2].id))

    sp = s.begin_nested()
    try:
        items = [i for i in ensure_checklist(s, engagement_id, eng.tenant_id) if i.tenant_id == eng.tenant_id]
        snap: dict[int, dict[str, Any]] = {}
        for it in items:
            snap[it.id] = {
                "status": it.status,
                "notes": it.notes,
                "evidence_ids": list(it.evidence_ids or []),
                "finding_ids": list(it.finding_ids or []),
                "updated_by": it.updated_by,
                "updated_at": it.updated_at,
                "executed_at": it.executed_at,
            }
            if (it.updated_by or "") == AUTO_ACTOR and not is_manual(it):
                it.status, it.notes, it.evidence_ids, it.finding_ids = "not_started", "", [], []
                it.updated_by, it.executed_at = "", None
        s.flush()
        trace: list[dict[str, Any]] = []
        for _, kind, obj in events:
            res = (
                apply_import_run(s, obj, record_audit=False)
                if kind == "import"
                else apply_automated_run(s, obj, record_audit=False)
            )
            trace += [{"event": f"{kind} #{obj.id}", **r} for r in res if r.get("action") != "unchanged"]
        changes: list[dict[str, Any]] = []
        for it in list_checklist(s, engagement_id):
            old = snap.get(it.id)
            if old is None:
                continue
            same = (
                it.status == old["status"]
                and _lines(it.notes) == _lines(old["notes"])
                and list(it.finding_ids or []) == old["finding_ids"]
                and list(it.evidence_ids or []) == old["evidence_ids"]
            )
            if same:
                for k, val in old.items():
                    setattr(it, k, val)
                continue
            changes.append(
                {"ref": it.ref, "from": old["status"], "to": it.status, "finding_ids": list(it.finding_ids or [])}
            )
            audit.record(
                s,
                AUTO_ACTOR,
                "checklist.auto_sync",
                "auth_checklist_item",
                it.id,
                engagement_id=engagement_id,
                ref=it.ref,
                status_from=old["status"],
                status_to=it.status,
            )
        s.flush()
        final = {i.ref: i.status for i in list_checklist(s, engagement_id)}
        if dry_run:
            # Mongo nested rollback is a no-op; restore snap so dry_run never persists.
            for it in list_checklist(s, engagement_id):
                old = snap.get(it.id)
                if old is None:
                    continue
                for k, val in old.items():
                    setattr(it, k, val)
            s.flush()
    except Exception:
        sp.rollback()
        raise
    if dry_run:
        sp.rollback()
    else:
        sp.commit()
    return {
        "engagement_id": engagement_id,
        "dry_run": dry_run,
        "events": len(events),
        "changes": changes,
        "trace": trace,
        "final": final,
    }
