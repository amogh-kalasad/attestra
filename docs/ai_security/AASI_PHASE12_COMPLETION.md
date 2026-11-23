# AASI Phase 12 completion report

Branch: `attestra-asi-bundle`. Date: 2026-11-23.

## Summary

Phase 12 adds a focused **security and regression** suite for Attestra Agentic Security Intelligence. Coverage is offline (unit/integration-style with mocks). No live LLM calls, no real network exploitation, and no git commit/push in this phase.

## Deliverables

| File | Purpose |
|---|---|
| [`tests/aasi/test_aasi_security.py`](../../tests/aasi/test_aasi_security.py) | 18 security/regression scenarios (prompt injection, scope, evidence, budgets, digests, AI-off) |
| [`AASI_SECURITY_VALIDATION_REPORT.md`](./AASI_SECURITY_VALIDATION_REPORT.md) | Scenario → module map and pass/fail notes |
| [`AASI_TEST_RESULTS.md`](./AASI_TEST_RESULTS.md) | Pytest counts for the new file and `tests/aasi/` smoke |
| This file | Phase 12 completion record |

## Scenarios covered

1. Prompt injection in scanner output (importer → context redaction)
2. Prompt injection in retrieved documents (context builder)
3. Unauthorized AI asset rejected
4. Cross-tenant evidence citation rejected (`evidence_gate`)
5. Unregistered test ID rejected (orchestrator)
6. Scope escalation blocked
7. Arbitrary command request rejected (PyRIT / Garak adapters)
8. Secret leakage prevented in provider prompts (redaction)
9. Unbounded agent loop stopped by budget
10. Excessive model calls stopped by budget
11. Approval bypass ineffective (model claim ignored)
12. Forged evidence ID rejected
13. Malformed tool output rejected by importers
14. Duplicate run idempotency (store)
15. AI-disabled regression (routes 404 / `enabled: false`)
16. Failed scanner output not treated as passed (`ai_tool_outcome_to_status`)
17. Report claims without evidence fail `aasi_qa_issues`
18. Unpinned scanner image rejection (`require_digest` / placeholder)

## Verified checks

- `pytest tests/aasi/test_aasi_security.py` — **18 passed**
- Smoke: `pytest tests/aasi/ -q` — see [`AASI_TEST_RESULTS.md`](./AASI_TEST_RESULTS.md)
- `lat check` after `lat.md/tests.md` / `lat.md/aasi.md` updates

## Explicitly not done (by design)

- Live AI e2e against real providers or scanner images
- Production digest pins (placeholders remain until operator inspect)
- Git commit or push

## Next

Keep Phase 12 suite green as AASI modules evolve; expand only when new trust boundaries appear.
