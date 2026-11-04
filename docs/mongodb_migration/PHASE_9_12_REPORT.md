# Phases 9–12 report

Completed 2026-11-03 on branch `mongodb-migration`. Production cutover was **not** executed.

## Phase 9 — Backup / restore & ops — **VERIFIED (code + tests)**

| Deliverable | Location |
|---|---|
| Logical Mongo export/restore + SHA-256 manifest | `attestra/ops/mongo_backup.py` |
| Dispatch from existing CLI | `attestra/ops/backup.py` → `backup` / `restore` when persistence is mongo |
| Helm Mongo env | `deploy/helm/attestra/values.yaml`, `_helpers.tpl`, `secret.yaml` |
| Docker defaults | `Dockerfile` (`ATTESTRA_PERSISTENCE=mongo`, GridFS storage, replica-set URI) |
| Tests | `tests/persistence/test_mongo_backup.py` (round-trip + tamper refuse) |

**Note:** Logical export is not mongodump PITR. Cutover runbook states both.

## Phase 10 — Testing & security validation — **PARTIAL**

| Evidence | Result |
|---|---|
| `pytest tests/persistence/` (replica set) | **14 passed** |
| Tenant / GridFS / jobs / credits / reports / migration | covered in foundation + phase6_8 suites |
| Full tree `pytest` under mongo-only app process | **not claimed** — conftest keeps legacy suite on SQL |
| Docs | `09_TEST_RESULTS.md`, updates in `08_SECURITY_AND_TENANCY_VALIDATION.md` |

## Phase 11 — Default Mongo; SQL legacy — **PARTIAL**

| Change | Detail |
|---|---|
| Default `ATTESTRA_PERSISTENCE` | `mongo` (`attestra/config.py`) |
| Default storage | `mongo` when persistence is mongo |
| Bootstrap | `attestra/bootstrap.py#init_persistence` used by API lifespan + `attestra init` |
| SQL module classification | `attestra/db.py` docstring: legacy / sql mode / migrate source |
| Remaining Session-based services/UI | **unresolved conversion** — use `sql` or continue repo wiring |

## Phase 12 — Cutover runbook + final report — **VERIFIED (docs only)**

| Doc | Purpose |
|---|---|
| `10_CUTOVER_AND_ROLLBACK.md` | Preconditions, steps, rollback; requires explicit auth |
| `11_FINAL_MIGRATION_REPORT.md` | Milestone honesty matrix |

**Production cutover: NOT DONE.**
