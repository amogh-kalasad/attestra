# World-Class VA + PT — Phase 9 Automated Report QA

**Source:** `Downloads/# MASTER PROMPT WORLD-CLASS VAPT PL.txt`  
**Prior:** `docs/WORLDCLASS_VAPT_PHASE8_REPORT_ENGINE.md`  
**Date:** 2026-11-05

Product wording: **security testing** / **VA + PT**. Technical reports must not invent tool versions or equate scan completion with coverage. No customer-facing “elite”.

---

## Goals

- Introduce automated **data-level** QA against a sealed report and its engagement findings.
- Block `qa_approve`, `sign_report`, and legacy `approve_report` when **critical** QA issues remain.
- Expose a read-only API so reviewers can inspect issues before pressing QA approve.
- Leave PDF blank-page / layout / page-numbering automation and **ENG1 V21 regression** for later (Phase 10).

---

## Check catalog

Implemented in `attestra/reports/qa/checks.py` (`ALL_CHECKS`). Severities: **critical** blocks approval; **warning** / **info** do not.

| Code | Severity | What it checks |
| --- | --- | --- |
| `empty_html` | critical | Sealed HTML file empty |
| `missing_html_tag` | critical | No `<html>` in sealed file |
| `finding_count_mismatch` | critical | Finding cards / conclusion count vs consolidate path |
| `severity_total_mismatch` | critical | HTML KPI open-sev counts vs DB open vulns |
| `missing_finding_id` | critical | Reportable finding missing `#finding-{id}` in technical-family HTML |
| `duplicate_fingerprint` | critical | Exact fingerprint dupes among reportable |
| `duplicate_title_location` | warning | Same title+location+asset, different ids |
| `missing_cvss_score` | warning | Score unset (or vector without score) |
| `invalid_cvss_score` | critical | Non-numeric or outside 0–10 |
| `cvss_severity_mismatch` | warning | Stored severity ≠ CVSS band |
| `malformed_cvss_vector` | critical* | Bad `CVSS:3.x` / `CVSS:4.0` vector (*critical when score also set; else warning) |
| `invalid_cwe` | critical | CWE present but not a positive integer |
| `missing_cwe` | warning | Medium+ open vuln has no CWE |
| `missing_owasp` | warning | Medium+ open vuln empty OWASP Top 10 |
| `missing_affected_urls` | warning | Medium+ open vuln has neither location nor affected_urls |
| `missing_evidence_confirmed_high` | critical | Confirmed critical/high with zero evidence rows |
| `missing_evidence_confirmed` | warning | Confirmed medium with zero evidence |
| `evidence_hash_mismatch` | critical | On-disk evidence bytes ≠ stored sha256 (skips `mongo://`) |
| `remediation_csp_mismatch` | critical | CSP-only remediation on Permissions-Policy / COEP / COOP / CORP / CORS / HSTS |
| `coverage_honesty_flag` | critical | Coverage snapshot claims scan completion is security coverage |
| `coverage_100_with_gaps` | warning | 100% endpoint coverage while skipped/blocked remain |
| `coverage_zero_endpoints` | critical | Technical report presents security testing with `endpoints_tested=0` / empty coverage |
| `all_findings_unvalidated` | critical | Every reportable finding is Unvalidated (client-facing final must not be all unvalidated) |
| `checklist_passed_incomplete` | critical | Checklist `passed` but notes imply skipped/limited |
| `site_grade_missing_letter` | warning | Site-grades section without letter |
| `site_grade_hsts_contradiction` | warning | Grades say HSTS missing while evidence shows HSTS |
| `missing_content_anchors` | critical | Technical HTML missing `#summary` / `#findings` / disclaimer-or-limitations |
| `screenshot_capture_failed` | warning | Capture failure / unavailable screenshot |
| `screenshot_not_embedded` | info | Successful screenshot path missing on disk |
| `unknown_report_status` | warning | Status not in workflow set |
| `approval_status` | info | Echoes current report status |

Visual / PDF: blank pages, broken layouts, and page numbering are **not** automated here (`summary.deferred_visual_qa`).

---

## Gate behavior

After four-eyes and hash checks, before Mongo transition / sign:

1. **`qa_approve`** — `assert_qa_allows_approval(run_report_qa(...))`; critical → `ServiceError`, no status change.
2. **`sign_report`** — same gate (defense in depth).
3. **`approve_report`** legacy path (draft/rejected/submitted → sign) — same gate before `_mongo_sign`. (Path that delegates to `sign_report` when already `qa_approved` is covered by the sign gate.)

Error message shape (from `assert_qa_allows_approval`):  
`report QA blocked approval (N critical): code1: msg1; code2: msg2` (body capped near 500 characters).

API `POST .../qa-approve`, `.../sign`, and `.../approve` continue to surface `ServiceError` via existing `_run` handling (typically HTTP 409).

---

## API

```
GET /api/reports/{rid}/qa
```

Permission: `report.read`. Tenant isolation: `scoped_report` + engagement principal check (same pattern as other report GETs).

Response (via `qa_result_dict`):

```json
{
  "report_id": 1,
  "engagement_id": 1,
  "ok": true,
  "issues": [{"code": "...", "severity": "...", "message": "...", "finding_id": null}],
  "summary": {"critical": 0, "warning": 0, "info": 1, "...": "..."},
  "checked_at": "2026-11-05T12:00:00+00:00"
}
```

`ok` is true iff there are no critical issues. UI: short note next to the QA approve button that automated QA runs on approve and points at this endpoint.

---

## What is deferred

| Item | Notes |
| --- | --- |
| PDF blank pages / broken layouts / page numbering | Visual QA; not in `attestra/reports/qa` |
| ENG1 V21 regression | Phase 10 (`docs` / master prompt §13) |
| Sealing QA identity into approved PDF chrome | Phase 1 audit follow-up; not this gate |
| Always-on Security testing coverage stub | Optional Phase 8 leftover |

---

## Primary files

- `attestra/reports/qa/` — package (`run_report_qa`, `assert_qa_allows_approval`, `qa_result_dict`, checks)
- `attestra/reports/render.py` — gates on `qa_approve` / `sign_report` / `approve_report`
- `attestra/api.py` — `GET /api/reports/{rid}/qa`
- `attestra/web/templates/engagement.html` — light QA note on approve
- `docs/WORLDCLASS_VAPT_PHASE9_REPORT_QA.md` (this file)
- `lat.md/reports.md`, `lat.md/architecture.md`, `lat.md/tests.md`
- `tests/test_report_qa_phase9.py` (local / uncommitted by habit)

---

## Stop

Phase 9 automated report QA package + approval/sign gates + read API ready for review. Next on request: **Phase 10 — ENG1 V21 validation**.
