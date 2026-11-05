# World-Class VA + PT — Phase 4 Coverage and Test Execution Engine

**Source:** `Downloads/# MASTER PROMPT WORLD-CLASS VAPT PL.txt`  
**Prior:** `docs/WORLDCLASS_VAPT_PHASE3_PT_COVERAGE.md`  
**Date:** 2026-11-05

Product wording: **security testing** / **VA + PT**. Do not equate automated scan completion with security-testing coverage.

---

## What this phase deepens

Phase 3 shipped checklist honesty and a lightweight snapshot. Phase 4 deepens the snapshot and adds a per-case execution ledger so reports and APIs can show **what was tested** without folding skips/blocks into passed or mixing in vulnerability severity totals.

### CoverageSnapshot fields (Phase 4 additions)

| Field | Meaning |
| --- | --- |
| `endpoints_discovered` / `endpoints_tested` / `endpoints_untested` | From `AuthRouteInventory` (visited vs rest); Phase 3 |
| `endpoints_authenticated` / `endpoints_unauthenticated` | Route `authenticated` flag **or** non-empty `role_name` vs neither |
| `methods_tested` | Sorted unique HTTP methods from visited routes and exercised ledger rows |
| `parameters_discovered` / `parameters_tested` | Prefer `AuthElementInventory` input-like elements; else ledger param names; else query-string keys (discovered only) |
| `roles_discovered` / `roles_tested` | Unique non-empty roles from routes + credential profiles / visited roles |
| `tested_roles` | Sorted role name list (visited) |
| `coverage_pct_endpoints` | `tested/discovered*100` (0 when none); reuses `auth_web.coverage._route_bucket` |
| `automated_cases_blocked` / `test_cases_blocked` | Automated case status `DEFERRED` (distinct from `SKIPPED`) |
| `automated_cases_skipped` | `SKIPPED` only (no longer folds `DEFERRED`) |
| `checklist_blocked` | Checklist status `blocked` (unchanged) |
| `ledger_entry_count` | Length of `collect_engagement_ledger` rows |
| `scan_completion_is_not_security_coverage` | Always `True` |
| `exclusions_note` | States that 100% scan completion ≠ 100% security testing coverage |

Vulnerability / severity totals are intentionally **absent**.

### Ledger (sibling)

- `attestra/automated_vapt/coverage/ledger.py` — `CoverageLedgerEntry`, `entries_from_case_result`, `merge_ledger`, `collect_engagement_ledger` / `build_coverage_ledger`.
- Stored under `AutomatedTestExecution.result_json.coverage_ledger`.
- Snapshot integrates ledger for `ledger_entry_count` and method/param enrichment when element inventory is empty.
- `engagement_coverage_snapshot(..., include_ledger=True)` attaches the full list; API `?ledger=1`.

### Rule kept

Skipped / blocked / deferred / not executed → **never** `passed`.  
**A 100% automated scan completion rate must never be represented as 100% security testing coverage.**

---

## API and report surface

- `GET /api/engagements/{eid}/coverage` — snapshot JSON; `?ledger=1` includes ledger rows.
- Technical HTML/PDF: **Security testing coverage** subsection (separate from vulnerability summary) via `security_testing_coverage` context.
- Exclusions note states skipped/blocked ≠ passed and scan completion ≠ security testing coverage.

---

## Primary files

- `attestra/automated_vapt/coverage/models.py` — `CoverageSnapshot`
- `attestra/automated_vapt/coverage/snapshot.py` — `build_coverage_snapshot`
- `attestra/automated_vapt/coverage/ledger.py` — execution ledger
- `attestra/automated_vapt/core/orchestrator.py` — persist `coverage_ledger` on each case
- `attestra/auth_web/coverage.py` — `_route_bucket` reused for endpoint %
- `attestra/services.py` — `engagement_coverage_snapshot`
- `attestra/api.py` — coverage route
- `attestra/reports/render.py`, `templates/technical.html.j2`
- `docs/WORLDCLASS_VAPT_PHASE4_COVERAGE_ENGINE.md` (this file)
- Tests (local): `tests/test_coverage_ledger_phase4.py`, `test_coverage_snapshot_phase4.py`, `test_coverage_report_phase4.py`

---

## Limits (later phases)

- Full endpoint × method × param × role matrix execution remains shallow when inventory/ledger are sparse.
- Report chapter polish continues in Phase 8.
- Business-logic workflows remain largely deferred.

---

## Stop

Phase 4 complete for review. Next on request: **Phase 5 — Risk Scoring Engine**.
