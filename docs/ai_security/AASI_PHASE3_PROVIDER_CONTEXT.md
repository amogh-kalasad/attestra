# AASI Phase 3 — Provider wrapper + context builder

Status: **Implemented** (recommend-only primitives). Orchestrator, roles, budget, and store are separate Phase 3 work.

## What changed

### Provider (`attestra/aasi/provider.py`)

Thin façade over the existing [[attestra/ai_narratives.py]] `Provider` protocol. No second AI framework.

| API | Behaviour |
| --- | --- |
| `build_provider(...)` | Honours `ATTESTRA_AASI`, `ATTESTRA_AI_NARRATIVES`, and `ATTESTRA_AI_TENANTS_OFF` via `ai_narratives.is_enabled` / `provider_from_env` / `get_provider`. Raises `AasiProviderDisabled` without contacting the network when off. |
| `AasiProvider.complete_json(system, prompt, schema_hint)` | Redacts outbound text with the narratives redaction patterns (unbounded length via `redact_prompt`), calls the inner provider with timeout + retries (`config.AASI_RETRY_LIMIT`), parses JSON (incl. fenced blocks), checks required keys from `schema_hint`. |
| `ProviderUsage` / `on_usage` | Call / retry / rough token accounting; callback and `usage.to_dict()`. |

Inject a fake `Provider` in tests through `build_provider(provider=...)` or `AasiProvider(fake)`.

### Context (`attestra/aasi/context.py`)

| API | Behaviour |
| --- | --- |
| `build_context_packet(...)` | Assembles a bounded `ContextPacket` from caller-supplied engagement inputs (no DB I/O). |
| `ContextPacket.to_dict()` | Prompt-safe dict: trust-labelled sections, redacted titles/identifiers. |

Included (bounded):

- Engagement objective (untrusted, redacted)
- Authorized assets — **`ai_app` preferred** (sorted first); safe metadata only; identifier/notes untrusted + redacted
- Finding refs — id / redacted title / severity / status only
- Coverage gaps — ledger rows with SKIPPED / DEFERRED / FAILED / NOT_TESTED
- Previous summaries (untrusted, redacted)
- Observation **ids only**
- Available test IDs from `test_registry.list_test_cases` and AI adapters via `list_adapters` (`garak`, `promptfoo`, `safelabs`, `pyrit`)

**Never** included: raw evidence bodies, credentials / ownership tokens, crawl seeds, API base URLs, source code, finding descriptions / locations / recommendations.

## Tests

- `tests/aasi/test_provider.py` — tenant/narratives/AASI off → `AasiProviderDisabled`; URL/host redaction; schema retries
- `tests/aasi/test_context.py` — serialization, `ai_app` preference, omission of evidence/secrets, registry + AI adapter ids

## Out of scope here

- `contracts.py`, `budget.py`, `store.py`, `orchestrator.py`, roles, approval routes
- Live LLM calls
