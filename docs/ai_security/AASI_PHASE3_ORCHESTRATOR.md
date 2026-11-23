# AASI Phase 3 — Roles and recommend-only orchestrator

Status: **Implemented** (roles + orchestrator slice on `attestra-asi-bundle`).
Scope: logical roles and `AasiOrchestrator` only. Contracts / provider / budget / store modules may land from sibling work; this slice defines compatible local shapes and injectable protocols.

## Intent

Agents **recommend**; Attestra **plans and executes**. One runtime runs five role stages (not five agent processes). Output is typed recommendations of **registered** test IDs. Intrusive / AI-adapter recommendations stay in an approval queue until a human (or policy) calls `approve()`. The orchestrator never calls scanners; it returns planner-ready payloads for Attestra.

## Components

| Path | Role |
|---|---|
| [`attestra/aasi/roles.py`](../../attestra/aasi/roles.py) | Strategist, Hypothesis, AI-security specialist, Evidence reviewer, Quality reviewer |
| [`attestra/aasi/orchestrator.py`](../../attestra/aasi/orchestrator.py) | Context hook, role sequence, budget/cancel, validation, approval gate, decision persistence |
| [`tests/aasi/test_roles.py`](../../tests/aasi/test_roles.py) | Offline stub + provider path tests |
| [`tests/aasi/test_orchestrator.py`](../../tests/aasi/test_orchestrator.py) | Flag, budget, unregistered ID, unauthorized asset, approval gate |

Feature flag: `ATTESTRA_AASI` → [`attestra.aasi.enabled`](../../attestra/aasi/__init__.py). When off, `run()` returns `DISABLED` (or raises if `raise_if_disabled=True`).

## Role sequence

1. **Strategist** — assessment plan outline (`AssessmentPlan`) from objective, authorized assets, coverage gaps.
2. **Hypothesis** — `Hypothesis[]` citing observation IDs when present; empty offline without observations.
3. **AI-security specialist** — `TestRecommendation[]` for catalogue gaps (stub recommends `garak` / `promptfoo` / `safelabs`).
4. **Evidence reviewer** — missing / contradictory evidence notes from findings/evidence metadata.
5. **Quality reviewer** — completeness, skipped cases, unsupported claims.

Each role prefers `provider.complete_json(...)` when a provider is injected; with `provider=None`, deterministic stubs keep tests offline.

Contracts: `roles.py` keeps role DTOs with prompt-oriented fields (`test_id`, `test_type`, `cites`, `needs_approval`). Shared `attestra.aasi.contracts` uses catalogue-oriented names (`registered_test_id`, `authorized_test_type`, `evidence_ids`, `approval_required`). Parent unifies mapping; orchestrator validation does not trust model intrusive/approval flags either way.

## Orchestrator controls

- **Registered tests only** — union of `test_registry` case IDs and AI adapter capabilities (`garak`, `promptfoo`, `safelabs`, `pyrit`). Unregistered IDs are rejected and logged as decisions.
- **Unauthorized assets** — `asset_id` must be in `authorized_assets`; otherwise rejected (`unauthorized_asset`).
- **No scope escalation** — recommendations carrying host/url/new_asset fields are rejected.
- **Intrusive / approval** — computed in code (`INTRUSIVE_TEST_IDS` + AI adapters). Model fields like `approved: true` are stripped; only `approve(recommendation_id)` clears the gate.
- **Budget** — injectable `BudgetGate` / `SimpleBudget` (max roles / calls / wall time). Exhaustion → `BLOCKED` with a recorded decision.
- **Cancellation** — `threading.Event`; set → `CANCELLED`, decision recorded, stop cleanly.
- **Failure recovery** — unexpected exceptions → `FAILED`, decision + run status recorded, no raise from `run()`.
- **Planner integration** — `planner_payloads()` / `result.planner_payload` are recommendation dicts (`origin=aasi`) for Attestra to plan. No scanner or `run_execution` calls from this module.
- **Persistence** — injectable `DecisionStore` (`MemoryStore` for tests); append-only decisions per role/kind.

## Security tests covered here

| Control | Test |
|---|---|
| Feature off | `test_run_disabled_when_flag_off` |
| Unregistered test ID | `test_unregistered_test_id_rejected` |
| Unauthorized asset | `test_unauthorized_asset_rejected` |
| Approval bypass (model claim) | `test_approval_gate_model_claim_has_no_effect` |
| Budget stop | `test_budget_stops_role_sequence` |
| Cancellation | `test_cancellation_stops_cleanly` |

## Out of scope (sibling / later)

- Full `contracts.py` / Mongo `store.py` / provider wrapper / production budget module
- HTTP routes / RBAC approval endpoint
- Evidence-ID existence gate (Phase 4 hardening)
- Calling `planner.plan_cases` or runner adapters from AASI

## Verify

```bash
pytest tests/aasi/test_roles.py tests/aasi/test_orchestrator.py -q
```
