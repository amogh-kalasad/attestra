# AASI Phase 3 — Mongo store (`aasi_runs` / `aasi_decisions`)

Status: **Implemented** (tenant-scoped store module + unit tests). Orchestrator / contracts / routes remain later Phase 3 work.

## What landed

| Piece | Path | Role |
| --- | --- | --- |
| Store | `attestra/aasi/store.py` | `AasiStore` over Mongo collections from migration **0005** |
| Collections | `attestra.persistence.mongo.collections` | `AASI_RUNS = "aasi_runs"`, `AASI_DECISIONS = "aasi_decisions"` |
| Migration | `0005_aasi_collections` | Additive create + indexes (parent-owned; not changed here) |
| Tests | `tests/aasi/test_store.py` | In-memory fake collections (no mongomock / live Mongo required) |

## API

`AasiStore(db=None, *, tenant_ids=None)` uses `adapters._db()` when `db` is omitted. Optional `tenant_ids` is enforced via `require_tenant_access` on every call.

| Method | Behaviour |
| --- | --- |
| `create_run(tenant_id, engagement_id, idempotency_key, …)` | Inserts a run with `schema_version`, status, budget/usage/provider/tasks, timestamps. Unique on `(tenant_id, idempotency_key)`; returns the existing doc on conflict with the same key. Optional `retain_until`. |
| `get_run(run_id, tenant_id)` | Always filters by `tenant_id`; returns `None` when missing or cross-tenant. |
| `append_decision(run_id, tenant_id, kind, payload, …)` | **Append-only** insert into `aasi_decisions`. No update path for prior decisions. Payload is sanitized (CoT-like keys stripped). Optional `audit_hash` (default: hash of canonical JSON summary). Inherits `retain_until` from the run when not passed. |
| `list_decisions(run_id, tenant_id, *, kind=None, limit=None)` | Always filters by `tenant_id`; ordered by `created_at` ascending. |

### Decision kinds

`hypothesis` · `recommendation` · `planner_outcome` · `approval` · `conclusion`

### Schema / integrity fields

- `schema_version` — currently `1` on both collections (`SCHEMA_VERSION`).
- `audit_hash` — optional SHA-256 of canonical JSON (`sort_keys`, compact separators) over run_id / tenant_id / kind / role / sanitized payload / cites.
- `retain_until` — soft retention metadata only (optional datetime); purge/reuse policy is enforced by higher layers / engagement retention.

### What is never stored

Raw chain-of-thought. `sanitize_payload` drops keys matching CoT patterns (`chain_of_thought`, `cot`, `raw_reasoning`, `reasoning_trace`, `thought_process`, including nested dicts). Callers must pass structured summaries only.

Best-effort `mongo_audit_record` hooks fire on create/append; audit failures do not roll back the Mongo insert.

## Indexes (migration 0005)

- `aasi_runs`: unique partial `(tenant_id, idempotency_key)` where key is a string; `(tenant_id, engagement_id)`; `(tenant_id, created_at)`
- `aasi_decisions`: `(tenant_id, run_id, created_at)`; `(tenant_id, engagement_id)`

## Out of scope here

- Contracts, budget, roles, orchestrator, FastAPI routes
- Updating run status / usage (caller or later store methods)
- Graph collections / attack-path edges
- Changing migration 0005 (already appended by parent)
