# AASI test results (Phase 12)

Branch: `attestra-asi-bundle`. Date: 2026-11-23.

Pytest counts for the Phase 12 security suite and an `tests/aasi/` smoke run. No commit/push in this phase.

## Commands

```bash
python -m pytest tests/aasi/test_aasi_security.py -q
python -m pytest tests/aasi/ -q
```

## Results

| Target | Passed | Failed | Skipped | Duration (approx) |
|---|---:|---:|---:|---|
| `tests/aasi/test_aasi_security.py` | **18** | **0** | 0 | ~5.3s |
| `tests/aasi/` (full package smoke) | **110** | **0** | 0 | ~5.0s |

## Phase 12 scenario pass map

All 18 scenarios in `test_aasi_security.py` passed (see [`AASI_SECURITY_VALIDATION_REPORT.md`](./AASI_SECURITY_VALIDATION_REPORT.md)).

| # | Test function | Result |
|---|---|---|
| 1 | `test_prompt_injection_in_scanner_output_redacted_in_context` | PASS |
| 2 | `test_prompt_injection_in_retrieved_documents_redacted` | PASS |
| 3 | `test_unauthorized_ai_asset_rejected` | PASS |
| 4 | `test_cross_tenant_evidence_citation_rejected` | PASS |
| 5 | `test_unregistered_test_id_rejected` | PASS |
| 6 | `test_scope_escalation_blocked` | PASS |
| 7 | `test_arbitrary_command_request_rejected` | PASS |
| 8 | `test_secret_leakage_prevented_in_provider_prompts` | PASS |
| 9 | `test_unbounded_agent_loop_stopped_by_budget` | PASS |
| 10 | `test_excessive_model_calls_stopped_by_budget` | PASS |
| 11 | `test_approval_bypass_ineffective` | PASS |
| 12 | `test_forged_evidence_id_rejected` | PASS |
| 13 | `test_malformed_tool_output_rejected_by_importers` | PASS |
| 14 | `test_duplicate_run_idempotency` | PASS |
| 15 | `test_ai_disabled_regression` | PASS |
| 16 | `test_failed_scanner_output_not_treated_as_passed` | PASS |
| 17 | `test_report_claims_without_evidence_fail_aasi_qa_issues` | PASS |
| 18 | `test_unpinned_scanner_image_rejection` | PASS |

## Totals

- **Phase 12 security file:** 18 passed / 0 failed
- **`tests/aasi/` smoke:** 110 passed / 0 failed
