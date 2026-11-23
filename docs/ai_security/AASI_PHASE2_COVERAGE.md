# AASI Phase 2 — Coverage ledger origin + AI-tool validity

Status: **Implemented** (ledger + run_validity helpers). Digest-pinned scanner adapters are separate Phase 2 work.

## What changed

### Coverage ledger (`attestra/automated_vapt/coverage/ledger.py`)

| API | Meaning |
| --- | --- |
| `CoverageLedgerEntry.origin` | Provenance: `catalogue` (default) or `aasi`. Invalid / empty values normalize to `catalogue` on create. |
| `normalize_origin` / `ALLOWED_ORIGINS` | Public normalizer for the two allowed values. |
| `AI_COVERAGE_CATEGORIES` | `ai_llm`, `ai_agent` risk categories for AI coverage rows. |
| `is_ai_coverage_category` / `normalize_coverage_category` | Helpers; non-AI categories are left unchanged so existing callers keep behaviour. |
| `merge_ledger` dedup key | Extends Phase 4 key with `asset_id`, `category` (risk area), and `origin` (surface × risk × asset × provenance). Legacy rows without `origin` backfill to `catalogue`. |

`entries_from_case_result` reads optional `case_result["origin"]` and normalizes `category`. Defaults remain catalogue origin and empty category when omitted.

Phase 4 status mapping is unchanged: case `NOT_TESTED` / `BLOCKED` still become ledger `SKIPPED`.

### Run validity (`attestra/automated_vapt/core/run_validity.py`)

| API | Meaning |
| --- | --- |
| `ai_tool_outcome_to_status(error, raw_empty, refused, *, rate_limited=False, failed=False)` | Returns `"NOT_TESTED"` when any failure signal is set; otherwise `None` (no override). **Never returns `PASSED`.** |

#### How AI adapters should set status

1. **HTTP / sample-backed runs** — emit `validity_samples` as today. Existing states (`RATE_LIMITED`, `CHALLENGE_DETECTED`, `PARTIALLY_BLOCKED`, …) still drive `gate_case_status` → `BLOCKED` / `INCONCLUSIVE`. A finding stays `FINDING` (confidence capped when not `VALID`).
2. **Tool-level failure without usable output** — empty raw report, provider refusal, adapter exception, or tool rate-limit without samples: set  
   `case_result["status"] = ai_tool_outcome_to_status(...)`  
   so the case is `NOT_TESTED` (honesty: not a pass). The ledger stores that as `SKIPPED` with a limitation.
3. **Do not** mark empty / refused / failed AI-tool runs as `PASSED`.

## Tests

`tests/automated_vapt/test_aasi_coverage_origin.py` covers origin default, `origin=aasi`, invalid origin normalization, AI category helpers, extended merge dedup, and `NOT_TESTED` mapping for failed AI output.

## Out of scope here

- Garak / Promptfoo / SafeLabs runner adapters and image digests
- AASI recommend-only orchestrator (`attestra/aasi/`)
- Changing Phase 4 ledger status vocabulary beyond documenting `NOT_TESTED` → `SKIPPED`
