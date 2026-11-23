# AASI Phase 4 — Evidence intelligence

Status: **Implemented** (evidence-ID gate, task-tree helpers, recommendation ranking) on `attestra-asi-bundle`.

## Intent

Harden recommend-only AASI so conclusions cannot cite forged or out-of-scope evidence IDs (Strix-style gate), attach a lightweight parent/child task tree to run state (not a separate agent graph), and rank recommendations for planner handoff. The Attestra planner still decides execution order; AASI never runs scanners.

## Components

| Path | Role |
|---|---|
| [`attestra/aasi/evidence_gate.py`](../../attestra/aasi/evidence_gate.py) | `assert_citations_valid` + injectable `lookup_fn`; `EvidenceGateError` with `reason` |
| [`attestra/aasi/task_tree.py`](../../attestra/aasi/task_tree.py) | Dict helpers: tasks, dependencies, retries, completion summary propagation |
| [`attestra/aasi/prioritize.py`](../../attestra/aasi/prioritize.py) | Score/rank `TestRecommendation` candidates (coverage gap > confirmed adjacency > default) |
| [`attestra/aasi/orchestrator.py`](../../attestra/aasi/orchestrator.py) | Hooks: `persist_conclusion` (evidence gate), `tasks` on run state, prioritize after AI-security |
| [`attestra/aasi/roles.py`](../../attestra/aasi/roles.py) | Evidence reviewer flags unknown/unavailable cites; quality notes conclusion claims without cites |

## Evidence-ID gate

`assert_citations_valid(tenant_id, engagement_id, citations, lookup_fn)` requires every citation to resolve via `lookup_fn(id)` to a record that:

- exists (non-`None`)
- matches the same `tenant_id` and `engagement_id`
- is `accessible` (default true when omitted)
- is not `deleted` / `is_deleted`
- is not `expired` / `is_expired`
- has `kind`/`type` in `{evidence, proof, finding, observation}` when a kind is present

Failures raise `EvidenceGateError` with `reason` (`not_found`, `tenant_mismatch`, `engagement_mismatch`, `deleted`, `expired`, `not_accessible`, `invalid_kind`, …).

`AasiOrchestrator.persist_conclusion` runs the gate before appending a `conclusion` decision; rejections are recorded as `conclusion_rejected` and re-raised.

## Task tree

`run["tasks"]` holds dicts with `id`, `parent_id`, `status`, `dependencies`, `result_refs`, `retry_count`, `summary`, `role`, `kind`, `children_complete`. Helpers: `ensure_task_tree`, `new_task`, `add_task`, `set_task_status`, `dependencies_satisfied`, `propagate_completion`. The orchestrator seeds a root run task and one child per role stage. This is **not** an independent graph execution engine.

## Prioritization

`prioritize_recommendations` stably sorts candidates:

1. **Coverage gap** — `test_id` / `registered_test_id` or `test_type` / `authorized_test_type` matches a coverage-gap token
2. **Confirmed finding adjacency** — recommendation `asset_id` appears on a confirmed/validated finding
3. **Default**

Planner payloads remain approval-gated; ranking only orders the in-memory recommendation list.

## Tests

```bash
pytest tests/aasi/test_evidence_gate.py tests/aasi/test_task_tree.py tests/aasi/test_prioritize.py -q
```

## Out of scope

- Coverage ledger dedupe (already Phase 2 `origin` / surface×risk)
- Calling `planner.plan_cases` or runner adapters
- Expanding to multi-process agents
- Live Mongo evidence lookups (inject `lookup_fn` at the API boundary later)
