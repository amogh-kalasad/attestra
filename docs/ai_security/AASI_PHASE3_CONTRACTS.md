# AASI Phase 3 — Contracts and budget

Status: **Implemented** (typed contracts + run budget helpers). Orchestrator, provider, store, and approval queue remain later Phase 3 work.

## What changed

### Contracts (`attestra/aasi/contracts.py`)

Frozen dataclasses with explicit `validate()` / `from_mapping()` — model output is untrusted.

| Type | Key fields | Notes |
| --- | --- | --- |
| `Hypothesis` | `id`, `run_id`, `tenant_id`, `engagement_id`, `asset_id`, `statement`, `basis`, `evidence_ids`, `uncertainty` | `basis` ∈ `{observed, inferred}`. `uncertainty` is a float in `[0, 1]` or a non-empty label. `observation_ids` on input merge into `evidence_ids`. |
| `TestRecommendation` | `id`, `hypothesis_id`, `asset_id`, `registered_test_id`, `authorized_test_type`, `expected_evidence`, `rationale`, `approval_required`, `intrusive` | `intrusive` is **never** taken from the model. `validate(against_catalogue=True)` / `from_mapping(..., against_catalogue=True)` recompute it from `INTRUSIVE_TEST_IDS`, and require a registered test id (catalogue case or scanner adapter) plus a `TEST_TYPES` key. |
| `Conclusion` | `id`, `run_id`, `subject_ids`, `conclusion_type`, `evidence_citations`, `recommended_action`, `confidence`, `confidence_basis` | Claiming kinds (`scanner_result`, `potential_finding`, `manually_reviewed`, `validated`) require non-empty `evidence_citations`. `validate_against_known(evidence_ids)` rejects unknown citation IDs. |

`ContractError` (a `ValueError`) is raised on structural or catalogue failures.

### Budget (`attestra/aasi/budget.py`)

`Budget` tracks `iterations`, `tasks`, `model_calls`, `tokens`, and `wall_clock_s`. Limits default to `attestra.config` `AASI_MAX_*` constants (`AASI_MAX_ITERATIONS`, `AASI_MAX_TASKS`, `AASI_MAX_MODEL_CALLS`, `AASI_MAX_TOKENS`, `AASI_MAX_WALL_CLOCK_S`).

| Method | Behaviour |
| --- | --- |
| `check()` | Raises `BudgetExceeded` when any usage has already reached its limit (no headroom for another unit). |
| `consume(...)` | Applies non-negative deltas only when projected totals stay `<=` limits (exactly `max_*` allowed); otherwise raises without applying. |
| `remaining()` | Returns a `BudgetSnapshot` (usage, limits, remaining) suitable for run records. |

Optional constructor overrides replace individual ceilings (used in tests). Live wall-clock tracking can be disabled with `track_wall_clock=False`.

## Tests

- `tests/aasi/test_contracts.py` — success/failure validation, intrusive override ignored, unknown evidence rejection, claiming-finding citation rule.
- `tests/aasi/test_budget.py` — config defaults, per-dimension limits, remaining snapshot, negative delta rejection.

## Out of scope here

- AASI orchestrator / roles / provider / context builder / decision store
- Approval HTTP endpoint and RBAC
- Mongo `aasi_runs` / `aasi_decisions` write path (separate Phase 3 persistence work)
