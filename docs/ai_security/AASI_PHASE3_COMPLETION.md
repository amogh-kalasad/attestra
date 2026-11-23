# AASI Phase 3 completion report

Branch: `attestra-asi-bundle`. Date: 2026-11-23.

## Summary

Native recommend-only AASI orchestration package `attestra/aasi/` with Mongo persistence, budget limits, five logical roles, approval gate, and FastAPI routes. Disabled by default (`ATTESTRA_AASI=off`).

## Components

- `contracts.py`, `budget.py`, `provider.py`, `context.py`, `store.py`, `roles.py`, `orchestrator.py`, `routes.py`
- Migration `0005_aasi_collections` for `aasi_runs` / `aasi_decisions`
- Config: `AASI_ENABLED`, `AASI_MAX_*`, `AASI_REQUIRE_APPROVAL`
- Router mounted in `attestra/api.py` at `/api/aasi`

## Tests

`tests/aasi/` — 72 passed. `lat check` passed.

## Security controls

- No scanner invocation from agents
- Unregistered tests rejected
- Unauthorized assets rejected
- Human approval required for intrusive recommendations
- Tenant AI kill-switch respected
- No raw chain-of-thought stored

## Next

Phase 4 — evidence-ID gate, coverage dedup, task tree, endpoint prioritization, evidence/quality reviewers hardening.
