# Feature parity matrix

Tracks API/CLI/UI/worker parity during Mongo cutover. Status: **SQL** = still SQLAlchemy default; **Mongo** = works when `ATTESTRA_PERSISTENCE=mongo`; **Both** = dispatched; **Pending** = not wired.

| Feature | SQL | Mongo | Notes |
|---|---|---|---|
| `attestra init` | Yes | Yes | Mongo path creates collections/indexes |
| `verify-audit` | Yes | Yes | Dispatches via `audit.verify` |
| Audit append | Yes | Yes | `audit.record` → Mongo when persistence=mongo |
| Job enqueue/claim/complete/fail/recover | Yes | Yes | `jobs/durable.py` adapters |
| Credit consume at admit | Yes | Yes | `credits.service.consume_for_scan_admit` |
| Credit allocate | SQL | Repo ready | Adapter `mongo_allocate_credits` available |
| Tenant/user/engagement CRUD repos | — | Yes | Not all services switched |
| Findings / assets / authz repos | — | Yes | |
| Report four-eyes workflow repo | — | Yes | `ReportRepository.transition` |
| GridFS evidence storage | local/S3 | Yes | `ATTESTRA_STORAGE=mongo` |
| `mongo-migrate` assess/plan/import/validate | — | Yes | Phase 7 engine |
| Scanner worker full path | Yes | Partial | Job claim Mongo; scan_run rows still SQL unless full cutover |
| Staff UI / portal / share / trust | Yes | Pending | Need service conversion |
| Backup/restore Mongo-aware | SQLite only | Pending | Phase 9 |
| Remove SQL runtime | — | Pending | Phase 11 |

## Acceptance for Phase 8 (this batch)

- Matrix published with evidence-backed statuses
- Critical concurrency paths (jobs, credits, audit) verified under Mongo
- Migration engine can import and validate a live SQLite source
