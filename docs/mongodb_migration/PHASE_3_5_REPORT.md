# Phases 3–5 completion report

**Date:** 2026-11-03  
**Branch:** `mongodb-migration`

## PHASE 3 — Core persistence

**STATUS:** PARTIAL

**FILES CHANGED / ADDED:**
- `attestra/persistence/` package (`mongo/client`, `config`, `collections`, `indexes`, `migrations`, `sequences`, `serialization`, `tenant`, `transactions`, `health`, `service_bridge`, `repositories/*`)
- `attestra/config.py` — `PERSISTENCE_BACKEND`, `MONGODB_URI`, `MONGODB_DB`
- `attestra/cli.py` — `attestra init` Mongo path
- `attestra/api.py` — health includes mongo when enabled
- `pyproject.toml` — `pymongo>=4.6`
- `tests/persistence/test_mongo_foundation.py`

**MONGODB CODE:** init/migrations/indexes; repos for tenants, users, memberships, api_keys, engagements, assets, authorizations, scope_rules, findings, audit, jobs, credits, artifacts; ID sequences.

**LEGACY REPLACED:** None at default runtime (SQLAlchemy still default). Opt-in via `ATTESTRA_PERSISTENCE=mongo`.

**TESTS:** `pytest tests/persistence/test_mongo_foundation.py` → **8 passed** against Docker `mongo:7` replica set `rs0`.

**RISKS:** Most of `services.py` still SQLAlchemy; full entity repository coverage incomplete.

## PHASE 4 — Durable storage

**STATUS:** PARTIAL

**MONGODB CODE:** `attestra/storage/mongo.py` (GridFS write-once, `mongo://` URIs); wired in `get_storage()` when `ATTESTRA_STORAGE=mongo`; `attestra/credentials/mongo_store.py` for Fernet ciphertext.

**FEATURES VERIFIED:** GridFS put/get/idempotent/overwrite-refuse (`test_gridfs_write_once`).

**RISKS:** Default storage still local; S3 dual-read/migration tool not built; signing keys still filesystem (intentional).

## PHASE 5 — Tenant isolation

**STATUS:** PARTIAL

**MONGODB CODE:** `attestra/persistence/mongo/tenant.py` + scoped repositories; cross-tenant tests green.

**RISKS:** Not all domain collections have dedicated repos yet; API/CLI paths not fully switched to Mongo UoW.

## NEXT PHASE

Phase 6 — audit/jobs/credits hardening in app wiring; Phase 7 migration engine; Phase 8 feature parity. **Awaiting approval for phases 6–8.**
