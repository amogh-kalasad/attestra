# AASI Phase 3 — FastAPI routes

Branch: `attestra-asi-bundle`. Recommend-only HTTP surface for AASI runs and human approval.

## Scope

Exclusive deliverable: `attestra/aasi/routes.py` exporting **`api_router`** (prefix `/api/aasi`). Parent INT mounts the router in `attestra/api.py`; this phase does **not** edit that file.

Handlers call injectable `_orch()` / `_store()` facades (unit tests monkeypatch them). Defaults wrap `AasiStore` (Mongo create/get/list/append) and `AasiOrchestrator` (recommend-only loop on start). Cancel updates run status via the runs collection; approve appends an `approval` decision (human-only path).

## Endpoints

| Method | Path | Permission | Behaviour |
|---|---|---|---|
| `GET` | `/api/aasi/status` | `engagement.read` | `{ "enabled": bool }` from `attestra.aasi.enabled` / `config.AASI_ENABLED` |
| `POST` | `/api/aasi/engagements/{engagement_id}/runs` | `engagement.write` | Start run; idempotency via `Idempotency-Key` header or body `idempotency_key` (header wins) |
| `GET` | `/api/aasi/engagements/{engagement_id}/runs/{run_id}` | `engagement.read` | Fetch run |
| `GET` | `/api/aasi/engagements/{engagement_id}/runs/{run_id}/decisions` | `engagement.read` | `{ "decisions": [...] }` |
| `POST` | `.../runs/{run_id}/recommendations/{rec_id}/approve` | `engagement.write` | Human approval only; `audit.record` `aasi.recommendation.approve` |
| `POST` | `.../runs/{run_id}/cancel` | `engagement.write` | Cancel; audit `aasi.run.cancel` |

## Feature flag

`ATTESTRA_AASI` off (default):

- `GET /status` → `200` `{ "enabled": false }`
- All other AASI routes → **404** (`not found`) to avoid advertising the feature (same norm as discovery and AI narratives)

## RBAC

- **Read** (`engagement.read`): admin, lead, tester, reviewer, client_viewer, auditor
- **Mutate** (`engagement.write`): admin, lead, tester

Cross-tenant / missing engagement or run → 404 via `LookupError` mapping (orchestrator/store own tenant checks).

## Mount name

Parent should `include_router` the object named **`api_router`** from `attestra.aasi.routes`.

## Tests

`tests/aasi/test_routes.py` — TestClient + dependency overrides / monkeypatched orchestrator & store.
