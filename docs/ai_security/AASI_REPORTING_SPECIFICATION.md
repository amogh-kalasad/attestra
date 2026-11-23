# AASI reporting specification (Phase 7)

Branch: `attestra-asi-bundle`. Spec for AI-security sections inside Attestra’s existing report renderer.

## Goals

- Surface AASI posture, technical decision rows, traceability, and an honest AI coverage matrix on executive and technical reports.
- Keep Attestra the system of record: hashing, signing, four-eyes, and Phase 9 sealed-report QA remain unchanged.
- Never present AI confidence / uncertainty as confirmed vulnerability severity.
- Never convert missing evidence, skipped tools, or silence into a pass.

## When sections appear

| Condition | Behaviour |
|---|---|
| `ATTESTRA_AASI` / AASI feature off | `aasi.present=false`; sections absent |
| AASI on, no runs for engagement/tenant | `aasi.present=false`; sections absent |
| AASI on, ≥1 tenant-scoped run | `aasi.present=true`; executive / technical / traceability / coverage payloads populated |

## Executive section

Data key: `aasi.executive`.

| Field | Meaning |
|---|---|
| `posture` | Short honest summary |
| `inventory` | `ai_app` assets only |
| `coverage` | Run / decision / asset counts |
| `confirmed` / `potential` / `needs_manual` / `unvalidated` | Counts from finding `validation_status` only |
| `unresolved_hypotheses` | Hypotheses without a linked conclusion |
| `gaps` | Planner `NOT_TESTED` / skipped / failed run notes |
| `limitations` | Fixed honesty disclaimers + situational notes |
| `confidence_disclaimer` | Explicit “confidence ≠ severity” sentence |

## Technical section

Data key: `aasi.technical.rows[]`.

Each row carries: `test_id`, `framework`, `framework_version`, `hypothesis_id`, `hypothesis`, `recommendation_id`, `recommendation`, `planner_outcome`, `execution_outcome`, `evidence_hash`, `validation`, `uncertainty`, `remediation`, and `confidence_is_not_severity=true`.

## Traceability appendix

Data key: `aasi.traceability.chains[]`.

Chain with **real id fields**: `run_id` → `hypothesis_id` → `recommendation_id` → `planner_outcome_id` → `conclusion_id` → `finding_id` plus `evidence_ids` and `registered_test_id`.

## AI coverage matrix

Data key: `aasi.coverage_matrix`.

Axes: OWASP LLM Top 10 (2025), OWASP Agentic Top 10, CWE (from ISO 42001 pack map), ISO/IEC 42001 AI-linked controls, tools (`garak`, `promptfoo`, `safelabs`, `pyrit`).

Allowed statuses only:

`not_assessed` | `assessed_no_issue` | `potential` | `confirmed` | `needs_manual` | `inconclusive` | `not_tested`

Rules:

- Default = `not_assessed`.
- Tool not invoked = `not_tested` (never pass).
- `assessed_no_issue` only from an explicit clean/rejected conclusion — never from silence.
- Finding `validation_status` drives worst-wins cell status.

## QA extension (conceptual)

`aasi_qa_issues(report_ctx) -> list` rejects at least:

- invalid evidence refs vs known engagement evidence
- confirmed rows without evidence hash / reproduction proof
- cross-tenant run documents
- invalid coverage statuses / “pass” encodings
- broken traceability (missing hypothesis/recommendation ids)

This does **not** bypass hashing, signing, or four-eyes gates.

## Non-goals

- New report kind (reuse `executive` / `technical`)
- Second planner, finding model, or validation enum
- Treating AASI confidence as severity or CVSS
