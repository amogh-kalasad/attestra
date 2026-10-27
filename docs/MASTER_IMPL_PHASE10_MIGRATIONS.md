# Master Implementation — Phase 10 Migrations

Schema migrations and backward-compatibility notes for Phases 1–9 (credits through evidence provenance). Head revision: `0027_finding_observations_rls`.

## Revision map (Phases 1–9 concerns)

| Concern | Revision | Notes |
| --- | --- | --- |
| Credit balances + ledger | `0023_subscription_credits` | `tenant_credit_accounts`, `credit_transactions`, `credit_renewal_requests`; Postgres RLS included |
| Subscription configuration | *(env only)* | `SUBSCRIPTION_SERVICE`, `INITIAL_TEST_RUN_CREDITS`, refund flags in `attestra/config.py` — no DB table |
| Org profile / framework recommend | `0024_tenant_profile_recommend` | `tenants.country`, `regulatory_status`, `technical_scope` (`industry` from baseline) |
| Observations + dedup fields | `0025_finding_observations` | `finding_observations` table; `findings.dedup_confidence` / `dedup_rationale` |
| Evidence provenance | `0026_evidence_provenance` | Additive columns + FKs via `batch_alter_table` (SQLite-safe); idempotent column adds |
| Observation RLS | `0027_finding_observations_rls` | Postgres only; no-op on SQLite |
| Phase 4 engagement types | *(none)* | Stored as string; no schema change |
| Phase 9 security controls | *(none)* | Code-only |

## Backfill policy

**No automatic historical backfill.** Migrations are additive and do not rewrite findings, evidence paths, or observation history.

| Data | After upgrade | How to populate |
| --- | --- | --- |
| Credit accounts | Empty until first grant / `ensure_account` | Created on first credit use or admin allocate |
| Tenant profile fields | Empty strings / `[]` | Edit tenant profile / recommend UI |
| `finding_observations` | Empty for pre-0025 findings | New imports record observations; optional re-import for history. Non-destructive review: `suggest_historical_duplicates` |
| Evidence provenance | Defaults (`role=original`, `capture_status=success`, empty meta) | New captures set fields; existing rows keep paths/sha256 unchanged |
| Dedup columns | `NULL` / `""` on old findings | Filled on subsequent imports |

Do **not** delete duplicate findings during upgrade. Soft/exact merges happen only at import time and preserve finding ids.

## Upgrade

```powershell
.\.venv\Scripts\alembic.exe upgrade head
```

Production / `attestra init` / serve call `attestra.db.upgrade` (same head). Take a backup before upgrading (`attestra` backup / `docs/RELEASE.md`).

### Partial `0026` recovery (SQLite)

Older builds of `0026` could add provenance columns then fail on `create_foreign_key` under SQLite, leaving `alembic_version` at `0025`. Re-run `alembic upgrade head`: the fixed `0026` skips existing columns and finishes FKs/indexes, then `0027` applies.

## Rollback / recovery

Production migrations are **forward-only**. Prefer restore from the pre-upgrade backup (`attestra restore`) rather than `alembic downgrade`.

Downgrade behaviour if used in non-prod:

| Revision | Downgrade effect |
| --- | --- |
| `0027` | Drops observation RLS (Postgres) |
| `0026` | Drops provenance columns/FKs (evidence blobs on disk remain) |
| `0025` | Drops `finding_observations` and dedup columns |
| `0024` | Drops tenant profile columns |
| `0023` | Drops credit tables |

## Tests

- `tests/test_migrations.py` — empty DB to head, table/column parity, downgrade to base
- `tests/test_phase10_migrations.py` — column parity, representative rows survive 0025→head, partial 0026 resume
- `tests/test_postgres_rls.py` — every tenant-bearing table (including `finding_observations`) has a policy; head revision assert
