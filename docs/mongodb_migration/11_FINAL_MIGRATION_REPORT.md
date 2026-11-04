# Final migration report

**Date:** 2026-11-03  
**Branch:** `mongodb-migration`

## Milestone status (separate)

| Milestone | Status |
|---|---|
| Code migration completed | **PARTIAL** — Mongo foundation, adapters, GridFS, migration engine, backup; most `services.py` paths still SQLAlchemy until fully converted |
| Test parity verified | **PARTIAL** — `tests/persistence/` **14 passed** (2026-11-03, rs0); legacy SQL suite retained via conftest |
| Historical data migrated | **TOOLING READY** — `mongo-migrate` verified on fixture + plan against laptop SQLite; production import not executed |
| Production cutover completed | **NOT DONE** — requires explicit authorization (`10_CUTOVER_AND_ROLLBACK.md`) |

## What runs on Mongo by default (Phase 11)

- `ATTESTRA_PERSISTENCE` default = `mongo`
- `ATTESTRA_STORAGE` default = `mongo` when persistence is mongo
- `attestra init` / API lifespan via `bootstrap.init_persistence`
- Audit / job claim-complete-fail-recover / credit consume adapters
- GridFS storage; logical backup/restore
- Helm values + Docker env defaults for Mongo

## SQL remaining (classified)

| Dependency | Classification |
|---|---|
| `attestra/db.py`, `models.py`, `rls.py` | legacy-runtime-when-`ATTESTRA_PERSISTENCE=sql` |
| `attestra/migration/*` SQL reader | legacy-import-only |
| `migrations/versions/*` Alembic | archived historical schema |
| `tests/` + conftest SQL fixtures | test-fixture |
| Most of `services.py` / UI routes | **unresolved conversion** — still Session-based; use `sql` mode or continue repository wiring |

## Integrity notes

- Laptop source audit chain historically broken at event **532** — migrate as-is; never silent-repair.
- Signing keys remain outside Mongo.

## Explicit non-claims

- Production data has **not** been cut over.
- Full API/UI parity on Mongo-only process is **not** claimed.
- GridFS is **not** claimed equivalent to S3 Object Lock WORM.
