# AASI report field mapping (Phase 7)

Maps AASI store / contract fields and finding columns onto report section keys.

## Runs (`aasi_runs`)

| Source | Report use |
|---|---|
| `id` / `_id` | `technical.run_ids`, `traceability.chains[].run_id`, `aasi.runs[]` |
| `tenant_id` | Tenant filter; QA `aasi_cross_tenant` |
| `engagement_id` | Engagement filter |
| `status` | Executive `gaps` when BLOCKED / FAILED / CANCELLED |
| `tasks[].tool` | Coverage matrix tool “mentioned” set |

## Decisions (`aasi_decisions`)

| `kind` | Payload fields | Report fields |
|---|---|---|
| `hypothesis` | `id`, `statement`, `basis`, `uncertainty`, `evidence_ids` | Executive unresolved list; technical `hypothesis*`; traceability `hypothesis_id` |
| `recommendation` | `id`, `hypothesis_id`, `registered_test_id` / `test_id`, `authorized_test_type`, `rationale` | Technical row core; traceability `recommendation_id` / `registered_test_id` |
| `planner_outcome` | `id`, `recommendation_id`, `registered_test_id`, `outcome` / `status`, `tool`, `llm_ids` | Technical `planner_outcome`; coverage `not_tested`; executive gaps |
| `conclusion` | `id`, `subject_ids`, `conclusion_type`, `evidence_citations`, `evidence_hash`, `finding_id`, `recommended_action`, `confidence` | Technical execution / evidence / remediation; traceability; matrix `assessed_no_issue` only on explicit `rejected` |
| `approval` | (audit only) | Not rendered as a finding |

`confidence` on conclusions is **never** mapped to severity KPIs or `confirmed` counts.

## Findings

| Finding field | Report use |
|---|---|
| `validation_status` | Executive counts; technical `validation`; matrix status |
| `cwe` | Matrix CWE + LLM/ISO linkage via ISO pack |
| `owasp_top10` | Matrix LLM / Agentic id extraction |
| `tools` / `detected_by` | Matrix tool status |
| `evidence[].id` / `sha256` | Known evidence set for QA; technical `evidence_hash` fallback |
| `remediation` | Technical remediation fallback |
| `id` | Traceability `finding_id` |

## Assets

| Asset field | Report use |
|---|---|
| `kind == ai_app` | Executive inventory |
| `id`, `name`, `identifier` | Inventory table |

## Coverage status mapping

| Signal | Matrix status |
|---|---|
| No data | `not_assessed` |
| Planner/tool `NOT_TESTED` / SKIPPED / REFUSED / FAILED / EMPTY | `not_tested` |
| Finding `potential` | `potential` |
| Finding `confirmed` | `confirmed` |
| Finding `needs_manual_validation` | `needs_manual` |
| Finding `not_reproducible` | `inconclusive` |
| Finding false_positive / informational / accepted_risk | `assessed_no_issue` |
| Conclusion `rejected` with no competing worse signal | `assessed_no_issue` |
| Silence / missing evidence | **never** `assessed_no_issue` or pass |

## QA issue codes

| Code | Severity | Trigger |
|---|---|---|
| `aasi_invalid_evidence_ref` | critical | Cite not in `known_evidence_ids` |
| `aasi_unreproduced_confirmed` | critical | `validation=confirmed` and empty evidence hash |
| `aasi_cross_tenant` | critical | Run `tenant_id` ≠ report tenant |
| `aasi_confidence_as_severity` | critical | Technical row missing guard flag |
| `aasi_invalid_coverage_status` | critical | Status outside allowed set |
| `aasi_missing_evidence_as_pass` | critical | Status encoded as pass/passed/ok/clean |
| `aasi_confirmed_without_validation` | critical | Executive confirmed ≠ findings |
| `aasi_orphan_finding_ref` | warning | Traceability finding id missing from reportable set |
| `aasi_broken_traceability` | warning | Missing hypothesis or recommendation id |
