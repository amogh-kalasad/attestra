# AASI reporting implementation (Phase 7)

How Phase 7 reporting is wired on `attestra-asi-bundle`.

## Files

| Path | Role |
|---|---|
| [`attestra/reports/aasi_sections.py`](../../attestra/reports/aasi_sections.py) | **New.** Builders for executive / technical / traceability / coverage + `aasi_qa_issues` |
| [`attestra/reports/render.py`](../../attestra/reports/render.py) | Minimal `_aasi_report_context` hook inside `_context` (empty when AASI off / no runs) |
| [`attestra/reports/templates/executive.html.j2`](../../attestra/reports/templates/executive.html.j2) | Conditional `#aasi-executive` block when `aasi.present` |
| [`attestra/reports/templates/technical.html.j2`](../../attestra/reports/templates/technical.html.j2) | Conditional technical / coverage / traceability sections + TOC links |
| [`tests/test_aasi_reporting.py`](../../tests/test_aasi_reporting.py) | Unit coverage for builders and QA helpers |

Shared reporting, signing, QA runner, and four-eyes paths are intentionally left intact. AASI failures during context build are swallowed so classic reports still generate.

## Context shape

```text
ctx["aasi"] = {
  present: bool,
  executive: {...} | null,
  technical: {...} | null,
  traceability: {...} | null,
  coverage_matrix: {...} | null,
  limitations: [...],
  qa_issues: [...],
  tenant_id, engagement_id, known_evidence_ids, runs
}
```

Entry points:

- `aasi_report_context(...)` — pure builders; inject `runs` / `decisions` for tests
- `aasi_context_for_engagement(s, eng, findings=...)` — used by render
- `aasi_qa_issues(report_ctx)` — conceptual QA extension

## Data sources

1. `aasi_runs` / `aasi_decisions` via `AasiStore` (tenant + engagement filter). Missing Mongo → empty sections.
2. Engagement `ai_app` assets for inventory.
3. Reportable findings for validation counts, matrix status, and technical validation/remediation.
4. Catalogues: `get_llm_top10()`, `ai_taxonomy.yaml` Agentic list, ISO 42001 pack CWE/controls.

## Honesty controls in code

- Executive confirmed/potential/needs_manual come from `validation_status`, not conclusion `confidence`.
- Technical rows set `confidence_is_not_severity=True`.
- Coverage default `not_assessed`; planner `NOT_TESTED` / failed AI tools → `not_tested`.
- Cross-tenant run/decision docs dropped before section build; QA also flags them.

## Preserved platforms

Hashing (`sha256`), Ed25519/HMAC signing, submit → QA → sign four-eyes, and Phase 9 `run_report_qa` gates are unchanged. `aasi_qa_issues` is additive and callable; it does not replace `assert_qa_allows_approval`.

## Tests

```bash
pytest tests/test_aasi_reporting.py -q
```

## Follow-ups (out of this slice)

- Optional fold of critical `aasi_qa_issues` into `reports/qa/checks.py` ALL_CHECKS
- CWE / ISO 42001 matrix tables in the technical HTML (data already in context)
- Dedicated completion report status row in `AASI_IMPLEMENTATION_STATUS.md`
