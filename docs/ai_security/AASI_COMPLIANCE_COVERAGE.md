# AASI compliance coverage in reports (Phase 7)

How the AI coverage matrix relates to OWASP LLM Top 10, OWASP Agentic Top 10, CWE, ISO/IEC 42001, and AI tools — without over-claiming.

## Principles

1. **Evidence or silence.** Cells start as `not_assessed`. Absence of findings is not a pass.
2. **Not tested ≠ assessed.** Planner or adapter outcomes of `NOT_TESTED`, skipped, refused, rate-limited, failed, or empty map to `not_tested`.
3. **Validation class wins for issues.** Confirmed / potential / needs manual come from Attestra `validation_status`, not model confidence.
4. **ISO 42001 is readiness evidence, not certification.** A clean AI tool run never marks a 42001 control `met` by itself (existing pack roll-up).
5. **SafeLabs ASI labels ≠ official Agentic ASI ids** until remapped through `ai_taxonomy.yaml` (low confidence / provisional).

## Framework axes in `aasi.coverage_matrix`

| Axis | Catalog source | Report key |
|---|---|---|
| OWASP LLM Top 10 2025 | `attestra.compliance.owasp.get_llm_top10` | `owasp_llm` |
| OWASP Agentic Top 10 2026 | `ai_taxonomy.yaml` → `owasp_agentic_2026` | `owasp_agentic` |
| CWE | ISO pack `llm_top10[].cwe` (no invented CWEs) | `cwe` |
| ISO/IEC 42001:2023 | Pack `llm_top10[].controls` | `iso42001` |
| Tools | garak, promptfoo, safelabs, pyrit | `tools` |

## Status vocabulary (report-facing)

| Status | Meaning for compliance readers |
|---|---|
| `not_assessed` | Out of scope or no assessment recorded |
| `not_tested` | Expected test did not run — **gap**, not green |
| `inconclusive` | Ran but unreproduced / unclear |
| `needs_manual` | Requires human validation |
| `potential` | Heuristic / scanner potential only |
| `confirmed` | Attestra-confirmed with evidence |
| `assessed_no_issue` | Explicit clean or rejected outcome recorded |

## Mapping to existing Attestra compliance artefacts

| Artefact | Interaction with AASI report sections |
|---|---|
| `owasp_top10` report kind / LLM block | Complementary; AASI matrix is engagement-scoped honesty for AI tests |
| ISO 42001 pack / SoA | Matrix lists linked Annex A refs with assessment status; SoA still assessor-driven |
| Coverage ledger `origin=aasi` | Planner gaps feed executive `gaps` and `not_tested` cells |
| Finding objectives `ai_*` | Unchanged; findings still roll into frameworks via existing engines |

## What reports must not claim

- “LLM01 passed” because no finding was filed
- “ISO 42001 compliant” from AASI or AI scanners alone
- “Confirmed” from AI confidence scores
- Equivalence of SafeLabs ASI01–ASI10 with OWASP Agentic ASI01–ASI10 without taxonomy remap

## Operator reading guide

1. Read executive limitations and confidence disclaimer first.
2. Use the coverage matrix to spot `not_tested` / `not_assessed` gaps before treating residual risk as low.
3. Use the traceability appendix to walk hypothesis → registered test → evidence → finding id for any confirmed or potential AI issue.
4. Treat `aasi_qa_issues` critical codes as blockers before human sign-off even when classic Phase 9 QA is clean.
