# Phases 6–8 completion report

**Date:** 2026-11-03  
**Branch:** `mongodb-migration`

## PHASE 6 — Audit, jobs, credits, reports

**STATUS:** PARTIAL (Mongo paths wired; SQL still default)

**IMPLEMENTED:**
- `JobRepository` complete/fail/heartbeat/cancel/recover + durable.py dispatch
- `CreditRepository` consume/allocate/refund + credits.service consume dispatch
- `audit.record` / `audit.verify` / CLI `verify-audit` Mongo dispatch
- `ReportRepository` draft→submitted→qa_approved→signed with four-eyes + SHA freeze
- `persistence/mongo/adapters.py` facade

**TESTS:** concurrent job claims (20 jobs / 4 workers), concurrent credit idempotency, report four-eyes — in `tests/persistence/test_mongo_phase6_8.py`

## PHASE 7 — Source→Mongo migration engine

**STATUS:** VERIFIED (engine + CLI against SQLite fixture)

**IMPLEMENTED:**
- `attestra/migration/` — assess, plan, import (checkpoint/resume/dry-run), validate, status
- CLI: `attestra mongo-migrate {assess,plan,import,validate,status}`
- Docs: `06_DATA_MIGRATION_RUNBOOK.md`
- Read-only source access; upsert by original integer ids; seed sequences; preserve audit hashes

**TESTS:** `test_sql_to_mongo_migration` import + resume skip + validate counts

## PHASE 8 — Feature parity

**STATUS:** PARTIAL

**IMPLEMENTED:** `07_FEATURE_PARITY_MATRIX.md` with evidence-backed statuses; critical concurrency + migration paths green.

**REMAINING:** Full UI/API service conversion, worker scan_run Mongo path, backup Phase 9, SQL removal Phase 11.

## TESTS (aggregate)

```text
pytest tests/persistence/ -q
# 13 passed
```

## NEXT

Phases 9–11: Mongo backup/restore, broader test/security validation, remove SQL runtime. **Awaiting approval.**
