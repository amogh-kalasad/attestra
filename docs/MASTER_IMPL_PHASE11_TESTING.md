# Master Implementation — Phase 11 Automated Testing

Executed and extended automated coverage for master plan sections 11.1–11.8 against the existing pytest suite. No production code changes in this phase beyond test/doc/lat alignment.

## Suites run

```text
pytest tests/test_subscription_service_flag.py \
  tests/test_subscription_credits.py \
  tests/test_authorization_document_access.py \
  tests/test_engagement_types.py \
  tests/test_framework_recommend.py \
  tests/test_cross_tool_dedup.py \
  tests/test_evidence_gallery.py \
  tests/test_phase8_reports.py \
  tests/test_phase9_security.py -q
```

**Result:** 89 passed (after fixing the merged-finding Markdown evidence assertion to attach evidence before export).

## Coverage map

| Plan | Area | Module | Notes |
| --- | --- | --- | --- |
| 11.1 | Feature flag | `test_subscription_service_flag.py` | Missing→ON, ON/OFF, invalid, entrypoints share `validate_runtime_config` |
| 11.2 | Credits | `test_subscription_credits.py` | Initial allocate, free engagement create, admit consume, idempotency, overspend, OFF skip, pre/post refund policy, admin allocate RBAC+audit, tenant isolation |
| 11.3 | Authorization docs | `test_authorization_document_access.py` | Admin only; lead/tester/cross-tenant denied; OFF does not bypass |
| 11.4 | Engagement types | `test_engagement_types.py` | VA / PT / VA+PT create keys; historical types readable |
| 11.5 | Framework recommend | `test_framework_recommend.py` | Industry/Country required; optional refine; catalogue-only; invalid id rejected |
| 11.6 | Dedup | `test_cross_tool_dedup.py` | Soft merge, observations, idempotent reimport, different endpoint/param, cross-engagement never merge, ambiguous |
| 11.7 | Evidence | `test_evidence_gallery.py` (+ Phase 9 size/path) | Gallery roles, annotate derivative, capture failure honesty |
| 11.8 | Reporting | `test_phase8_reports.py` | One top-level merged finding in JSON/MD/HTML with tools + evidence |

## Gaps filled in Phase 11

Critical gaps identified during audit and covered with new tests:

- Pre-execution and post-start credit refund policy (`refund_for_scan`)
- Non-admin allocate 403; admin allocate audited; cross-tenant credits read denied; tenant balances isolated
- Same title / different endpoints stay separate; cross-engagement never merges
- Invalid framework id rejected; optional profile fields refine recommendations
- Entrypoints share `validate_runtime_config`
- Merged finding appears once in JSON/Markdown/HTML with evidence under that finding

## Deferred (nice-to-have / not blocking)

- Threaded concurrent overspend stress (sequential overspend already covered)
- MIME / scope evidence edge matrix beyond existing Phase 9 caps and path containment
- PDF crop / visual screenshot readability (manual/visual; not automated here)

## Acceptance

Tests were executed; the one implementation-related failure (missing evidence attachment in the merged-report assertion) was resolved in the test. Production behavior for Markdown `### Evidence` already existed when evidence rows are present.
