# Test results (Mongo migration)

Evidence captured during Phases 9–10. Do not invent passes.

## Mongo persistence suite

```text
# 2026-11-03 — Docker attestra-mongo-test (mongo:7 rs0), venv pytest
pytest tests/persistence/ -q
# 14 passed in ~20s
```

| Area | File | Result |
|---|---|---|
| Foundation / repos / GridFS / tenant | `test_mongo_foundation.py` | included |
| Jobs/credits concurrency, migration, reports | `test_mongo_phase6_8.py` | included (sql source forced for migrate fixture) |
| Backup/restore manifest | `test_mongo_backup.py` | round-trip + tamper refuse |

Aggregate: **14 passed**. Also recorded in `11_FINAL_MIGRATION_REPORT.md` / `PHASE_9_12_REPORT.md`.

## Legacy SQL suite

Existing `tests/` fixtures force `ATTESTRA_PERSISTENCE=sql` via `tests/conftest.py` so historical SQLite tests remain valid for regression against business logic that still uses SQLAlchemy sessions.

Full `pytest -q` of the entire tree is environment-dependent (optional scanners, Postgres RLS). Treat failures as:

1. Pre-existing
2. Migration-induced regression
3. Expected adaptation still pending
4. Missing dependency

## Security checks exercised

- Cross-tenant Mongo repository denial (`TenantAccessDenied`)
- GridFS overwrite refusal
- Backup manifest tamper refusal
- Credit idempotency under concurrency
- Job claim uniqueness under concurrency
- Report four-eyes + SHA freeze on Mongo `ReportRepository`
