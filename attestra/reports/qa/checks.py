"""Individual sealed-report QA validators (data-level; no visual/PDF layout)."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.orm import Session

from attestra.models import OPEN_STATUSES
from attestra.reports.qa.model import QaIssue
from attestra.reports.render import _counts_as_open_vuln, _validation_status_of

_MEDIUM_PLUS = frozenset({"critical", "high", "medium"})
_HIGH_PLUS = frozenset({"critical", "high"})
_SEVERITIES = ("critical", "high", "medium", "low", "info")

_FINDING_ID_RE = re.compile(r"""id=["']finding-(\d+)["']""", re.IGNORECASE)
_F_LABEL_RE = re.compile(r"""\bF-(\d+)\b""")
_KPI_SEV_RE = re.compile(
    r"""class=["']kpi["'][^>]*>\s*<span[^>]*class=["'][^"']*sev-(\w+)[^"']*["'][^>]*>"""
    r"""[^<]*</span>\s*<b>\s*(\d+)\s*</b>""",
    re.IGNORECASE | re.DOTALL,
)
_REPORTABLE_COUNT_RE = re.compile(
    r"""(\d+)\s+reportable\s+finding""",
    re.IGNORECASE,
)
_SITE_GRADE_RE = re.compile(
    r"""—\s*<b>\s*([A-F][+-]?)\s*</b>""",
    re.IGNORECASE,
)
_HSTS_MISSING_IN_GRADE_RE = re.compile(
    r"""hsts[^\n]{0,80}(missing|failed|not\s+set)""",
    re.IGNORECASE,
)


@dataclass
class QaContext:
    """Shared inputs for report QA checks."""

    s: Session
    report: Any
    html: str
    engagement: Any
    reportable: list[Any]
    open_vulns: list[Any]
    by_sev: Counter
    tenant_id: int
    kind: str
    issues: list[QaIssue] = field(default_factory=list)

    def add(
        self,
        code: str,
        severity: str,
        message: str,
        *,
        finding_id: int | None = None,
        details: dict | None = None,
    ) -> None:
        self.issues.append(
            QaIssue(
                code=code,
                severity=severity,
                message=message,
                finding_id=finding_id,
                details=details,
            )
        )


def load_reportable_findings(s: Session, engagement_id: int) -> list[Any]:
    """Same consolidate path as [[attestra/reports/render.py#_context]] (exclude false_positive)."""
    from attestra import crossmerge, services
    from attestra.persistence.mongo import report_reads
    from attestra.reports.consolidate import consolidate

    eng = services.get_engagement(s, engagement_id)
    all_findings = services.list_findings(s, engagement_id)
    report_reads.engagement_doc(engagement_id, eng.tenant_id)
    all_findings = report_reads.annotatable(all_findings)
    findings = crossmerge.collapse(s, all_findings)
    return consolidate(s, [f for f in findings if f.status != "false_positive"])


def _html_finding_ids(html: str) -> set[int]:
    return {int(m.group(1)) for m in _FINDING_ID_RE.finditer(html)}


def _html_kpi_by_sev(html: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for m in _KPI_SEV_RE.finditer(html):
        sev = m.group(1).lower()
        if sev in _SEVERITIES:
            out[sev] = int(m.group(2))
    return out


def check_html_shell(ctx: QaContext) -> None:
    """Light check: sealed HTML non-empty and looks like HTML."""
    raw = (ctx.html or "").strip()
    if not raw:
        ctx.add("empty_html", "critical", "Sealed report HTML is empty")
        return
    if "<html" not in raw.lower():
        ctx.add(
            "missing_html_tag",
            "critical",
            "Sealed report does not contain an <html> element",
        )


def check_finding_counts(ctx: QaContext) -> None:
    """Reportable finding count in sealed HTML must match DB consolidate path."""
    db_n = len(ctx.reportable)
    html_ids = _html_finding_ids(ctx.html)
    html_cards = len(html_ids)
    m = _REPORTABLE_COUNT_RE.search(ctx.html)
    conclusion_n = int(m.group(1)) if m else None

    if html_cards and html_cards != db_n:
        ctx.add(
            "finding_count_mismatch",
            "critical",
            f"Sealed HTML has {html_cards} finding card(s) but DB has {db_n} reportable finding(s)",
            details={"html_cards": html_cards, "db_count": db_n},
        )
    elif conclusion_n is not None and conclusion_n != db_n:
        ctx.add(
            "finding_count_mismatch",
            "critical",
            f"Conclusion says {conclusion_n} reportable finding(s) but DB has {db_n}",
            details={"conclusion_count": conclusion_n, "db_count": db_n},
        )
    elif not html_cards and db_n > 0 and ctx.kind == "technical":
        ctx.add(
            "finding_count_mismatch",
            "critical",
            f"DB has {db_n} reportable finding(s) but sealed HTML has no finding cards",
            details={"db_count": db_n, "html_cards": 0},
        )


def check_severity_totals(ctx: QaContext) -> None:
    """KPI / overview by_sev counts must match open vulns (exclude non-vuln validation)."""
    html_by = _html_kpi_by_sev(ctx.html)
    if not html_by and not ctx.open_vulns:
        return
    for sev in _SEVERITIES:
        db_n = int(ctx.by_sev.get(sev, 0))
        if sev not in html_by:
            continue
        html_n = html_by[sev]
        if html_n != db_n:
            ctx.add(
                "severity_total_mismatch",
                "critical",
                f"Open {sev} count in HTML KPIs is {html_n} but DB open vulns is {db_n}",
                details={"severity": sev, "html": html_n, "db": db_n},
            )


def check_finding_ids(ctx: QaContext) -> None:
    """Every reportable finding id must appear in sealed HTML (#finding-{id} or F- label)."""
    if ctx.kind and ctx.kind not in ("technical", "retest", "owasp_top10", ""):
        return
    html_ids = _html_finding_ids(ctx.html)
    # F-N labels alone are not enough without id anchors when cards exist; require id.
    for f in ctx.reportable:
        fid = int(getattr(f, "id", 0) or 0)
        if not fid:
            continue
        if fid not in html_ids:
            # Fallback: allow F-label presence only when no finding cards at all (non-technical).
            label_hit = bool(_F_LABEL_RE.search(ctx.html)) and f"finding-{fid}" in ctx.html
            if not label_hit:
                ctx.add(
                    "missing_finding_id",
                    "critical",
                    f"Reportable finding {fid} is missing from sealed HTML (#finding-{fid})",
                    finding_id=fid,
                )


def check_duplicate_records(ctx: QaContext) -> None:
    """Exact fingerprint dupes among reportable = critical; title+location+asset soft dup = warning."""
    by_fp: dict[str, list[int]] = {}
    soft: dict[tuple, list[int]] = {}
    for f in ctx.reportable:
        fid = int(getattr(f, "id", 0) or 0)
        fp = (getattr(f, "fingerprint", None) or "").strip()
        if fp:
            by_fp.setdefault(fp, []).append(fid)
        key = (
            (getattr(f, "title", None) or "").strip().lower(),
            (getattr(f, "location", None) or "").strip().lower(),
            getattr(f, "asset_id", None),
        )
        if key[0]:
            soft.setdefault(key, []).append(fid)

    for fp, ids in by_fp.items():
        uniq = sorted({i for i in ids if i})
        if len(uniq) > 1:
            ctx.add(
                "duplicate_fingerprint",
                "critical",
                f"Duplicate fingerprint among reportable findings: {uniq}",
                details={"fingerprint": fp, "finding_ids": uniq},
            )

    for key, ids in soft.items():
        uniq = sorted({i for i in ids if i})
        if len(uniq) <= 1:
            continue
        # Skip if already flagged as exact fingerprint dup for the same set.
        fps = {
            (getattr(f, "fingerprint", None) or "").strip()
            for f in ctx.reportable
            if int(getattr(f, "id", 0) or 0) in uniq
        }
        if len(fps) == 1 and next(iter(fps)):
            continue
        ctx.add(
            "duplicate_title_location",
            "warning",
            f"Same title+location+asset with different ids: {uniq}",
            details={"title": key[0], "location": key[1], "asset_id": key[2], "finding_ids": uniq},
        )


def check_cvss_scores(ctx: QaContext) -> None:
    """cvss_score must be 0–10 when set; severity should align with score band (warning)."""
    from attestra.scoring import severity_from_cvss

    open_ids = {int(getattr(f, "id", 0) or 0) for f in ctx.open_vulns}
    for f in ctx.reportable:
        fid = int(getattr(f, "id", 0) or 0)
        score = getattr(f, "cvss_score", None)
        vector = (getattr(f, "cvss_vector", None) or "").strip()
        sev = (getattr(f, "severity", None) or "").strip().lower()
        if score is None:
            # Missing score alone is warning (not critical); keep signal on open medium+ or vector-only.
            if vector or (fid in open_ids and sev in _MEDIUM_PLUS):
                ctx.add(
                    "missing_cvss_score",
                    "warning",
                    "CVSS vector present but score is missing"
                    if vector
                    else "CVSS score is not set",
                    finding_id=fid or None,
                )
            continue
        try:
            val = float(score)
        except (TypeError, ValueError):
            ctx.add(
                "invalid_cvss_score",
                "critical",
                f"CVSS score is not numeric: {score!r}",
                finding_id=fid or None,
            )
            continue
        if val < 0.0 or val > 10.0:
            ctx.add(
                "invalid_cvss_score",
                "critical",
                f"CVSS score {val} is outside 0–10",
                finding_id=fid or None,
            )
            continue
        band = severity_from_cvss(val)
        if sev and band and sev != band:
            ctx.add(
                "cvss_severity_mismatch",
                "warning",
                f"Severity {sev!r} contradicts CVSS score {val} (band {band})",
                finding_id=fid or None,
                details={"severity": sev, "cvss_score": val, "band": band},
            )


def check_cvss_vectors(ctx: QaContext) -> None:
    """Vector must look like CVSS:3.x or CVSS:4.0; malformed + score claimed = critical."""
    from attestra.scoring import cvss_version_from_vector, validate_cvss_vector

    for f in ctx.reportable:
        fid = int(getattr(f, "id", 0) or 0)
        vector = (getattr(f, "cvss_vector", None) or "").strip()
        if not vector:
            continue
        score = getattr(f, "cvss_score", None)
        try:
            validate_cvss_vector(vector)
        except ValueError:
            sev = "critical" if score is not None else "warning"
            ctx.add(
                "malformed_cvss_vector",
                sev,
                f"CVSS vector is malformed: {vector[:80]!r}",
                finding_id=fid,
                details={"cvss_vector": vector, "cvss_version": cvss_version_from_vector(vector)},
            )


def check_cwe_mappings(ctx: QaContext) -> None:
    """CWE if present must be positive int; warn when medium+ open vuln has no CWE."""
    for f in ctx.reportable:
        fid = int(getattr(f, "id", 0) or 0)
        cwe = getattr(f, "cwe", None)
        if cwe is not None:
            try:
                cwe_i = int(cwe)
            except (TypeError, ValueError):
                ctx.add(
                    "invalid_cwe",
                    "critical",
                    f"CWE is not an integer: {cwe!r}",
                    finding_id=fid,
                )
                continue
            if cwe_i <= 0:
                ctx.add(
                    "invalid_cwe",
                    "critical",
                    f"CWE must be a positive integer, got {cwe_i}",
                    finding_id=fid or None,
                )
                continue
        elif (
            getattr(f, "status", None) in OPEN_STATUSES
            and _counts_as_open_vuln(f)
            and (getattr(f, "severity", "") or "").lower() in _MEDIUM_PLUS
        ):
            ctx.add(
                "missing_cwe",
                "warning",
                "Medium+ open vulnerability has no CWE mapping",
                finding_id=fid or None,
            )


def check_owasp_mappings(ctx: QaContext) -> None:
    """Warn when medium+ open vuln has empty owasp_top10."""
    for f in ctx.open_vulns:
        if (getattr(f, "severity", "") or "").lower() not in _MEDIUM_PLUS:
            continue
        owasp = (getattr(f, "owasp_top10", None) or "").strip()
        if not owasp:
            ctx.add(
                "missing_owasp",
                "warning",
                "Medium+ open vulnerability has empty OWASP Top 10 mapping",
                finding_id=int(getattr(f, "id", 0) or 0) or None,
            )


def check_affected_urls(ctx: QaContext) -> None:
    """Warn when open medium+ finding has neither location nor affected_urls."""
    for f in ctx.open_vulns:
        if (getattr(f, "severity", "") or "").lower() not in _MEDIUM_PLUS:
            continue
        loc = (getattr(f, "location", None) or "").strip()
        urls = getattr(f, "affected_urls", None) or []
        has_urls = False
        if isinstance(urls, str):
            has_urls = bool(urls.strip())
        elif isinstance(urls, (list, tuple)):
            has_urls = any(str(u).strip() for u in urls)
        if not loc and not has_urls:
            ctx.add(
                "missing_affected_urls",
                "warning",
                "Open medium+ finding has neither location nor affected_urls",
                finding_id=int(getattr(f, "id", 0) or 0) or None,
            )


def _evidence_rows(f: Any) -> list[Any]:
    return list(getattr(f, "evidence", None) or [])


def check_evidence_availability(ctx: QaContext) -> None:
    """Confirmed open medium+ should have evidence; confirmed critical/high with none is critical."""
    from attestra.finding_validation.statuses import CONFIRMED

    for f in ctx.open_vulns:
        if _validation_status_of(f) != CONFIRMED:
            continue
        sev = (getattr(f, "severity", "") or "").lower()
        if sev not in _MEDIUM_PLUS:
            continue
        rows = _evidence_rows(f)
        fid = int(getattr(f, "id", 0) or 0) or None
        if rows:
            continue
        if sev in _HIGH_PLUS:
            # No evidence rows ⇒ no screenshot/http_pair embeds possible.
            ctx.add(
                "missing_evidence_confirmed_high",
                "critical",
                "Confirmed critical/high finding has zero evidence rows (no HTTP pair embeds possible)",
                finding_id=fid,
            )
        else:
            ctx.add(
                "missing_evidence_confirmed",
                "warning",
                "Confirmed medium finding has zero evidence rows",
                finding_id=fid,
            )


def check_evidence_integrity(ctx: QaContext) -> None:
    """When sha256 is set and path is readable, file bytes must match (skip mongo://)."""
    from attestra import services

    seen: set[int] = set()
    for f in ctx.reportable:
        for ev in _evidence_rows(f):
            eid = getattr(ev, "id", None)
            if eid is not None and eid in seen:
                continue
            if eid is not None:
                seen.add(eid)
            expected = (getattr(ev, "sha256", None) or "").strip()
            if not expected:
                continue
            path_raw = getattr(ev, "path", None) or ""
            path_s = str(path_raw)
            if path_s.startswith("mongo://"):
                continue
            path = Path(path_s)
            if not path_s or not path.exists():
                continue
            try:
                data = services.read_evidence_bytes(path, ctx.tenant_id)
            except (OSError, LookupError, ValueError):
                try:
                    data = services.read_stored_bytes(path)
                except (OSError, LookupError, ValueError):
                    continue
            if isinstance(data, (bytes, bytearray)) and data.startswith(b"mongo://"):
                continue
            actual = hashlib.sha256(data).hexdigest()
            if actual != expected:
                ctx.add(
                    "evidence_hash_mismatch",
                    "critical",
                    f"Evidence {eid} sha256 mismatch (stored {expected[:12]}… vs file {actual[:12]}…)",
                    finding_id=int(getattr(f, "id", 0) or 0) or None,
                    details={"evidence_id": eid, "expected": expected, "actual": actual},
                )


def check_remediation_relevance(ctx: QaContext) -> None:
    """Permissions-Policy / COEP / COOP / CORP must not get CSP-only remediations."""
    from attestra.library.fix_snippets import rejects_csp_guidance_for_finding

    for f in ctx.reportable:
        fid = int(getattr(f, "id", 0) or 0) or None
        recommendation = (getattr(f, "recommendation", None) or "").strip()
        pack = getattr(f, "remediation_pack", None)
        if not isinstance(pack, dict):
            try:
                from attestra.remediation.match import remediation_for_finding

                pack = remediation_for_finding(f)
            except Exception:  # noqa: BLE001 — pack optional
                pack = None

        texts: list[dict[str, Any]] = []
        if recommendation:
            texts.append({"recommendation": recommendation, "title": "", "fix_steps": ""})
        if isinstance(pack, dict):
            texts.append(
                {
                    "title": str(pack.get("concept") or pack.get("title") or ""),
                    "recommendation": str(
                        pack.get("recommendation_text")
                        or pack.get("recommended_fix")
                        or recommendation
                        or ""
                    ),
                    "fix_steps": str(pack.get("recommended_fix") or ""),
                    "snippets": pack.get("config_examples")
                    if isinstance(pack.get("config_examples"), dict)
                    else None,
                }
            )

        mismatched = False
        for guidance in texts:
            try:
                if rejects_csp_guidance_for_finding(f, guidance):
                    mismatched = True
                    break
            except Exception:  # noqa: BLE001
                continue

        if mismatched:
            ctx.add(
                "remediation_csp_mismatch",
                "critical",
                "Remediation text looks CSP-only for a Permissions-Policy / COEP / COOP / CORP / CORS / HSTS finding",
                finding_id=fid,
            )


def check_test_coverage(ctx: QaContext) -> None:
    """Coverage snapshot must keep scan_completion_is_not_security_coverage honesty."""
    from attestra import services

    try:
        snap = services.engagement_coverage_snapshot(ctx.s, ctx.engagement.id)
    except Exception:  # noqa: BLE001
        return
    if not snap:
        return
    honest = snap.get("scan_completion_is_not_security_coverage")
    if honest is False:
        ctx.add(
            "coverage_honesty_flag",
            "critical",
            "security_testing_coverage claims scan completion is security coverage (flag is False)",
        )
    skipped = int(snap.get("checklist_skipped") or 0) + int(snap.get("automated_cases_skipped") or 0)
    blocked = int(snap.get("checklist_blocked") or 0) + int(
        snap.get("automated_cases_blocked") or snap.get("test_cases_blocked") or 0
    )
    pct = float(snap.get("coverage_pct_endpoints") or 0.0)
    if pct >= 100.0 and (skipped > 0 or blocked > 0):
        ctx.add(
            "coverage_100_with_gaps",
            "warning",
            f"Coverage claims {pct}% endpoints while skipped={skipped} blocked={blocked}",
            details={"coverage_pct_endpoints": pct, "skipped": skipped, "blocked": blocked},
        )


def check_skipped_blocked(ctx: QaContext) -> None:
    """Passed checklist rows whose notes imply skipped/limited are critical honesty failures."""
    from attestra.auth_web.checklists import list_checklist, notes_imply_incomplete_coverage

    try:
        rows = list_checklist(ctx.s, ctx.engagement.id)
    except Exception:  # noqa: BLE001
        return
    for item in rows or []:
        status = (getattr(item, "status", None) or "").strip().lower()
        if status != "passed":
            continue
        notes = getattr(item, "notes", None) or ""
        if notes_imply_incomplete_coverage(notes):
            ctx.add(
                "checklist_passed_incomplete",
                "critical",
                f"Checklist {getattr(item, 'ref', '?')} is passed but notes imply skipped/limited coverage",
                details={"ref": getattr(item, "ref", None), "notes": notes[:200]},
            )


def check_site_grade(ctx: QaContext) -> None:
    """When site-grades section exists, letter grades should be present; basic HSTS contradiction warning."""
    if 'id="site-grades"' not in ctx.html and "id='site-grades'" not in ctx.html:
        return
    letters = _SITE_GRADE_RE.findall(ctx.html)
    if not letters:
        ctx.add(
            "site_grade_missing_letter",
            "warning",
            "Site grades section is present but no letter grade was found",
        )
    # Basic: HSTS missing/failed wording in grades while open findings look contradicted.
    if _HSTS_MISSING_IN_GRADE_RE.search(ctx.html):
        from attestra.finding_validation.headers import hsts_present_in_evidence

        blobs: list[str] = []
        for f in ctx.reportable:
            for ev in _evidence_rows(f):
                note = getattr(ev, "note", None)
                if note:
                    blobs.append(str(note))
                if getattr(ev, "kind", None) == "http_pair":
                    blobs.append(str(getattr(ev, "filename", "") or ""))
        try:
            if hsts_present_in_evidence(blobs):
                ctx.add(
                    "site_grade_hsts_contradiction",
                    "warning",
                    "Site grades claim HSTS missing/failed while evidence suggests HSTS is present",
                )
        except Exception:  # noqa: BLE001
            pass


def check_missing_content(ctx: QaContext) -> None:
    """Technical sealed HTML must include key anchors."""
    if ctx.kind and ctx.kind != "technical":
        return
    lower = ctx.html.lower()
    missing: list[str] = []
    if 'id="summary"' not in lower and "id='summary'" not in lower:
        missing.append("#summary")
    if 'id="findings"' not in lower and "id='findings'" not in lower:
        missing.append("#findings")
    has_disclaimer = 'id="disclaimer"' in lower or "id='disclaimer'" in lower
    has_limits = 'id="testing-limitations"' in lower or "id='testing-limitations'" in lower
    if not has_disclaimer and not has_limits:
        missing.append("#disclaimer or #testing-limitations")
    if missing:
        ctx.add(
            "missing_content_anchors",
            "critical",
            f"Technical sealed HTML is missing required anchors: {', '.join(missing)}",
            details={"missing": missing},
        )


def check_missing_screenshots(ctx: QaContext) -> None:
    """Info/warning when screenshot evidence exists but capture failed / not embedded."""
    for f in ctx.reportable:
        fid = int(getattr(f, "id", 0) or 0) or None
        for ev in _evidence_rows(f):
            kind = getattr(ev, "kind", None) or ""
            capture = (getattr(ev, "capture_status", None) or "").strip().lower()
            if kind == "capture_failure" or capture in ("failed", "unavailable"):
                ctx.add(
                    "screenshot_capture_failed",
                    "warning",
                    "Screenshot / capture evidence did not succeed",
                    finding_id=fid,
                    details={
                        "evidence_id": getattr(ev, "id", None),
                        "capture_status": capture or kind,
                        "reason": getattr(ev, "capture_failure_reason", None) or getattr(ev, "note", None),
                    },
                )
            elif kind == "screenshot" and capture == "success":
                path_s = str(getattr(ev, "path", "") or "")
                if path_s and not path_s.startswith("mongo://") and not Path(path_s).is_file():
                    ctx.add(
                        "screenshot_not_embedded",
                        "info",
                        "Screenshot evidence file is missing and cannot be embedded",
                        finding_id=fid,
                        details={"evidence_id": getattr(ev, "id", None)},
                    )


def check_approval_status(ctx: QaContext) -> None:
    """Report.status consistency note for gate callers (informational)."""
    status = (getattr(ctx.report, "status", None) or "").strip()
    known = {"draft", "submitted", "qa_approved", "signed", "rejected"}
    if status not in known:
        ctx.add(
            "unknown_report_status",
            "warning",
            f"Report status {status!r} is not a known workflow status",
            details={"status": status},
        )
    else:
        ctx.add(
            "approval_status",
            "info",
            f"Report status is {status}",
            details={"status": status},
        )


ALL_CHECKS: list[Callable[[QaContext], None]] = [
    check_html_shell,
    check_finding_counts,
    check_severity_totals,
    check_finding_ids,
    check_duplicate_records,
    check_cvss_scores,
    check_cvss_vectors,
    check_cwe_mappings,
    check_owasp_mappings,
    check_affected_urls,
    check_evidence_availability,
    check_evidence_integrity,
    check_remediation_relevance,
    check_test_coverage,
    check_skipped_blocked,
    check_site_grade,
    check_missing_content,
    check_missing_screenshots,
    check_approval_status,
]
