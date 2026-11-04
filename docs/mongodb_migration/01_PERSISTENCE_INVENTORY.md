# Persistence inventory

Complete classification of Attestra persistence dependencies discovered in checkout `6718536` (branch `mongodb-migration`). Status values are pre-implementation.

**Legend — storage class:** A operational DB · B durable binary · C sensitive secrets · D temporary execution · E static assets · F browser · G external object store

---

## Summary counts

| Class | Finding |
|---|---|
| A — SQLAlchemy ORM tables | 55 domain tables (+ `alembic_version` in live DB); 51 in `models.py` + `share/models.py` + `trust/models.py` (side-imported so `Base.metadata` sees all) |
| A — modules with SQLAlchemy usage | ~79 app modules under `attestra/`; ~149 `*.py` files repo-wide including tests/migrations |
| A — `db.session` / `from attestra.db` entrypoints | ~96 files; `session()` auto-commits (explicit `.commit` rare) |
| A — Alembic revisions | 37 files, head `0036_tenant_ownership_hosts`; merge revision `0020_email_alerts` |
| A — Postgres RLS | 49 tables in `rls.POLICIES`; **no RLS** on `users`, `api_keys`, `jobs`, `audit_events`, `certification_authority`, `automated_test_executions` |
| A — HTTP surface | ~281 route decorators; ~287 flattened runtime `APIRoute`s |
| B — Storage protocol backends | Local (`local://`) default; S3/SeaweedFS optional |
| B — DATA_DIR durable trees | `evidence`, `imports`, `reports`, `raw`, `tenants/*/…`, `feeds`, `packs`, `keys` |
| C — Credential / signing / env secrets | Fernet credential files; Ed25519/HMAC keys; pepper/session/Vault |
| D — Scratch / cache | Scanner process dirs; `scanner-cache/`; worker log; temp downloads |
| E — Static | Templates, YAML control libraries, JS/CSS, policy Rego |
| F — Browser | **None** found (`localStorage`/`sessionStorage` absent) |
| G — S3 | Optional via `ATTESTRA_STORAGE=s3` |
| MongoDB | **Absent** from runtime code and `pyproject.toml` |

---

## A. Operational database state

### A.1 Core engine and configuration

| Source file | Function/class | Existing backend | Entity/data | R/W | Dependencies | Proposed backend | Risk | Migration phase | Verification | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| `attestra/config.py` | `DATABASE_URL`, `DATA_DIR`, `RAW_DIR`, `STORAGE_BACKEND` | env → SQLite path or Postgres URL | connection + paths | R | all DB/storage | `ATTESTRA_MONGODB_URI` (+ retain DATA_DIR for temp) | critical | 2–11 | config tests / startup | Pending |
| `attestra/db.py` | `init`, `upgrade`, `session`, `tenant_scope` | SQLAlchemy engine | sessions, Alembic | R/W | models, rls | `attestra/persistence/mongo/*` | critical | 3,11 | health + init tests | Pending |
| `attestra/rls.py` | `POLICIES`, `setting_value` | Postgres RLS | tenant isolation | R (DDL) | migrations 0007+ | app-level tenant filters | high | 5 | cross-tenant tests | Pending |
| `alembic.ini` + `migrations/` | Alembic env + 37 revisions | SQLite/Postgres schema | DDL history | W on upgrade | models | archive; Mongo migration versions | medium | 11 | keep import-only | Pending |
| `attestra/models.py` | 51 mapped classes | SQLAlchemy | core domain | R/W | services, jobs | Mongo collections 1:1 preferred | critical | 2–3 | mapping doc + CRUD tests | Pending |
| `attestra/share/models.py` | `ShareLink` | SQLAlchemy | share_links | R/W | share/service | `share_links` | medium | 3,8 | share tests | Pending |
| `attestra/trust/models.py` | Trust* | SQLAlchemy | trust_* | R/W | trust/service | `trust_*` | medium | 3,8 | trust tests | Pending |

### A.2 Entity → proposed Mongo collection (all class A)

Preserve integer `_id` (or `id` field) equal to legacy PK unless noted.

| Table | Proposed collection | Embed? | Notes | Phase | Risk | Status |
|---|---|---|---|---|---|---|
| tenants | tenants | no | root | 3 | critical | Pending |
| tenant_ownership_hosts | tenant_ownership_hosts | optional embed under tenant if bounded | currently separate; keep separate for renew/verify concurrency | 3 | high | Pending |
| users | users | no | global username unique; no RLS today | 3 | critical | Pending |
| api_keys | api_keys | no | key_hash unique | 3 | critical | Pending |
| tenant_memberships | tenant_memberships | no | (user_id,tenant_id) unique | 3 | critical | Pending |
| user_invites | user_invites | no | token_hash unique | 3 | high | Pending |
| engagements | engagements | no | tenant_id index | 3 | critical | Pending |
| authorizations | authorizations | no | document_path → artifact URI | 3–4 | high | Pending |
| assets | assets | no | | 3 | critical | Pending |
| scope_rules | scope_rules | maybe embed if small | keep separate for gate queries | 3 | high | Pending |
| import_runs | import_runs | no | raw_path artifact | 3–4 | high | Pending |
| scan_runs | scan_runs | no | | 3 | critical | Pending |
| jobs | jobs | no | atomic claim indexes | 3,6 | critical | Pending |
| findings | findings | no | (engagement_id,fingerprint) unique | 3 | critical | Pending |
| finding_observations | finding_observations | no | high cardinality | 3 | critical | Pending |
| finding_comments | finding_comments | no | | 3 | medium | Pending |
| evidence | evidence | no | path/sha256; GridFS metadata link | 3–4 | critical | Pending |
| retention_policies | retention_policies | no | | 3,9 | medium | Pending |
| control_assessments | control_assessments | no | unique triple | 3 | high | Pending |
| risk_acceptances | risk_acceptances | no | | 3 | high | Pending |
| asv_scans / asv_scan_items | asv_scans, asv_scan_items | items may embed if bounded | prefer separate for item queries | 3 | medium | Pending |
| segmentation_tests | segmentation_tests | no | | 3 | medium | Pending |
| scan_schedules | scan_schedules | no | worker enqueue | 3,6 | high | Pending |
| nonconformities | nonconformities | no | | 3 | medium | Pending |
| soa_entries | soa_entries | no | | 3 | medium | Pending |
| audit_samples | audit_samples | no | JSON items | 3 | medium | Pending |
| retests | retests | no | | 3 | high | Pending |
| reports | reports | no | path + sha256 + signatures | 3–4,6 | critical | Pending |
| audit_events | audit_events | no | ordered chain; head lock | 3,6 | critical | Pending |
| tenant_risk_weights | tenant_risk_weights | embed in tenant OK | small 1:1 | 3 | low | Pending |
| suppression_rules | suppression_rules | no | | 3 | medium | Pending |
| library_entries | library_entries | no | | 3 | medium | Pending |
| report_templates | report_templates | no | | 3 | medium | Pending |
| proof_replays | proof_replays | no | | 3 | medium | Pending |
| webhook_endpoints / deliveries | webhook_* | no | secret field = C overlay | 3,5 | high | Pending |
| workflow_rules | workflow_rules | no | | 3 | medium | Pending |
| finding_assignments | finding_assignments | no | | 3 | medium | Pending |
| cert_expiry_alerts | cert_expiry_alerts | no | | 3 | low | Pending |
| email_alert_settings / sent | email_alert_* | no | | 3 | medium | Pending |
| auth_credential_profiles | auth_credential_profiles | no | secret_ref → C | 3–4 | critical | Pending |
| auth_route_inventory / element_inventory / checklist_items | auth_* | no | | 3 | high | Pending |
| tenant_credit_accounts | tenant_credit_accounts | no | PK tenant_id | 3,6 | critical | Pending |
| credit_transactions | credit_transactions | no | idempotency unique | 3,6 | critical | Pending |
| credit_renewal_requests | credit_renewal_requests | no | | 3,6 | high | Pending |
| automated_test_executions | automated_test_executions | no | claim like jobs; add tenant filter | 3,5,6 | critical | Pending |
| certification_authority | certification_authority | singleton doc | | 3 | medium | Pending |
| share_links | share_links | no | token_hash | 3 | high | Pending |
| trust_centers / items / access_requests | trust_* | no | | 3 | high | Pending |

### A.3 High-traffic SQL call sites (representative; not exhaustive of every `select`)

| Source file | Function/class | Backend | Entity/data | R/W | Dependencies | Proposed | Risk | Phase | Verification | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| `attestra/services.py` | most business ops | SQLAlchemy Session | engagements…findings… | R/W | models, audit, storage | repositories | critical | 3,8 | API/CLI parity | Pending |
| `attestra/audit.py` | `record`, `verify` | Session | audit_events | R/W | AuditEvent | serialized Mongo append | critical | 6 | verify-audit + concurrency | Pending |
| `attestra/jobs/durable.py` | `claim_job`, enqueue, complete | Session + conditional UPDATE | jobs, scan_runs | R/W | Job, ScanRun | find_one_and_update | critical | 6 | multi-worker tests | Pending |
| `attestra/credits/service.py` | admit/refund/allocate | Session | credits | R/W | accounts+txns | multi-doc txn | critical | 6 | idempotency tests | Pending |
| `attestra/reports/render.py` | generate/submit/qa/sign | Session + files | reports | R/W | Report, storage, signing | repo + GridFS | critical | 3–4,6 | signing verify | Pending |
| `attestra/auth/keys.py` | create/list/revoke | Session | api_keys | R/W | User | repo | high | 3 | key tests | Pending |
| `attestra/users/service.py` | invites/roles | Session | users, invites | R/W | | repo | high | 3 | user tests | Pending |
| `attestra/auth_web/checklist_auto.py` | apply_*_safely | Session + **begin_nested** | checklist | R/W | savepoints | redesign failure isolation | high | 3 | checklist tests | Pending |
| `attestra/crossmerge.py` | recompute_safely | Session + begin_nested | findings | R/W | | redesign | high | 3 | crossmerge tests | Pending |
| `attestra/proof/hooks.py` | after_import | Session + begin_nested | proof | R/W | | redesign | medium | 3–4 | proof tests | Pending |
| `attestra/webhooks/service.py` | emit/dispatch | Session | endpoints/deliveries | R/W | | repo | medium | 3,8 | webhook tests | Pending |
| `attestra/ops/retention.py` | purge_expired | Session + storage | policies + files | R/W | | repo + GridFS delete authz | high | 4,9 | purge dry-run | Pending |
| `attestra/ops/backup.py` | backup/restore | **sqlite3** + filesystem | DB+artifacts | R/W | SQLite only | Mongo backup | critical | 9 | manifest restore | Pending |
| `attestra/cli.py` | all commands | Session via services | all | R/W | | Mongo init path | critical | 8,11 | CLI smoke | Pending |
| `attestra/api.py` / `web/*` | routes | Session | all | R/W | | DI/repos | critical | 8 | OpenAPI snapshot | Pending |
| `attestra/orchestration/*` | Temporal activities | Session | jobs/scans | R/W | optional | same repos | medium | 6,8 | skip if Temporal absent | Pending |

**Savepoint call sites (no Mongo equivalent):** `auth_web/checklist_auto.py`, `crossmerge.py`, `proof/hooks.py`. Must redesign optional-side-effect isolation (Phase 3).

---

## B. Durable binary artifacts

| Source file | Function/class | Backend | Entity/data | R/W | Dependencies | Proposed | Risk | Phase | Verification | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| `attestra/storage/local.py` | `LocalStorage` | local FS | write-once blobs | R/W | DATA_DIR | `MongoStorage`/GridFS | critical | 4 | put/get/idempotent/overwrite-fail | Pending |
| `attestra/storage/s3.py` | `S3Storage` | S3/SeaweedFS | same protocol | R/W | boto3 | retain as optional peer or migrate-into-mongo tool | high | 4,7 | do not discard S3 objects | Pending |
| `attestra/storage/__init__.py` | `get_storage` | switch | backend select | R | config | add `mongo` backend | critical | 4 | config matrix | Pending |
| `attestra/services.py` | `_store` and import/evidence paths | Storage | evidence/imports/reports | W | Storage | mongo:// URIs | critical | 4 | hash equality | Pending |
| `attestra/jobs/durable.py` | scanner raw output | RAW_DIR files | scan-* dirs | W | adapters | GridFS or mongo raw bucket | high | 4 | import after migrate | Pending |
| `attestra/automated_vapt/evidence/*` | run evidence writers | FS under raw/tenants | elite artifacts | W | | GridFS | high | 4 | elite evidence tests | Pending |
| `attestra/proof/store.py` / `screenshots.py` | proof attach | Storage | http_pair / screenshots | W | evidence rows | GridFS | high | 4 | proof integrity | Pending |
| `attestra/reports/render.py` | HTML freeze paths | FS via storage/tenants | report HTML | W | | GridFS | critical | 4 | verify-report | Pending |
| `attestra/trust/service.py` | published docs | Storage | trust item files | W | | GridFS | medium | 4 | trust download | Pending |
| Auth document paths on `authorizations` | services | FS | signed PDF/docs | R/W | | GridFS | high | 4 | authorization gate | Pending |

**URI plan:** new `mongo://bucket/key` (or `gridfs://…`); resolve legacy `local://` and S3 URIs during transition (Phase 4/7).

---

## C. Sensitive persistent secrets

| Source file | Function/class | Backend | Entity/data | R/W | Dependencies | Proposed | Risk | Phase | Verification | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| `attestra/credentials/store.py` | EncryptedLocalStore | Fernet files under tenants/…/credentials | scan login secrets | R/W | fernet key env | encrypted docs in Mongo **or** keep external KMS files; never plaintext | critical | 4,5 | round-trip decrypt; no plaintext logs | Pending |
| `attestra/secret_store.py` | env/Vault provider | env/Vault | pepper, session, OIDC | R | | unchanged outside Mongo | critical | 5 | no secrets in Mongo plaintext | Pending |
| `attestra/reports/signing.py` | Ed25519/HMAC keys | `data/keys/*` | signing material | R/W | | keys remain filesystem/KMS; public key publishable | critical | 4 | old signatures still verify | Pending |
| `webhook_endpoints.secret` | webhooks models | DB column plaintext | HMAC secrets | R/W | | encrypt-at-rest field or secret_ref | high | 5 | delivery still verifies | Pending |
| User `password_hash` | users | DB | scrypt hashes | R/W | | store as-is in Mongo | high | 3 | login tests | Pending |
| API `key_hash` | api_keys | DB | scrypt+pepper | R/W | | as-is | high | 3 | auth tests | Pending |

---

## D. Temporary execution files

| Source file | Function/class | Backend | Entity/data | Class | Proposed | Risk | Phase | Status |
|---|---|---|---|---|---|---|---|---|
| `runner/scanners/*` | process cwd/out | temp dirs / RAW_DIR working files | scanner scratch | D | remain on disk; promote finals to GridFS | medium | 4 | Pending |
| `config.SCANNER_CACHE_DIR` | nuclei/trivy caches | `data/scanner-cache` (~47MB here) | tool caches | D | keep filesystem | low | — | N/A (not migrating) |
| `jobs/launcher.py` | worker.log | FS | logs | D | FS | low | — | N/A |
| `jobs/instance_lock.py` | `.lock-worker` | FS lock file | single-worker guard | D | FS or Mongo lease optional later | medium | 6 | Pending (behavior preserve) |

---

## E. Static application assets (do not put in Mongo)

Templates (`web/templates`, `reports/templates`), compliance YAML, policy Rego, static JS/CSS/fonts, package data in `pyproject.toml`. Class E — leave on disk/in package.

---

## F. Browser-side persistence

No `localStorage`, `sessionStorage`, or IndexedDB usage under `attestra/web/static` or package sources. Class F: none.

---

## G. External storage integrations

| Source | Backend | Action |
|---|---|---|
| `storage/s3.py` | S3 API / SeaweedFS | Support read of existing URIs during migration; optional continued backend; Object Lock ≠ GridFS WORM — document |
| Feeds (`ops/feeds.py`) | downloaded into DATA_DIR/feeds | Cache files; can stay FS or move later (low priority) |

---

## Config / deploy / CI database dependencies

| Source | Finding | Phase |
|---|---|---|
| `Dockerfile`, `deploy/helm/attestra` | Postgres-oriented production defaults | 9,11 |
| `.github/workflows/ci.yml` | pytest; may assume SQLite | 10 |
| `docs/MASTER_IMPL_PHASE10_MIGRATIONS.md` | Alembic upgrade notes (head cited as 0027 — stale) | docs update with migration |
| `pyproject.toml` | sqlalchemy, alembic, optional psycopg; **no pymongo yet** | 2 add pymongo |

---

## Indirect / obscure call sites to retain in scope

- `history.py`, `dashboards.py`, `tuning.py`, `cert_expiry.py`, `assignments.py`, `comments.py`, `retest.py`, `library/*`, `org_ownership/*`, `ownership_settings/*`, `certification/*`, `verify/*`, `share/*`, `alerts/*`, `integrations/tickets.py`, `compliance/sebi_timeline.py`, `reports/*_export.py`, `ai_narratives.py`
- CLI-only: `backup`, `restore`, `purge`, `verify-audit`, `migrate-storage`, enrich feeds
- Test fixtures under `tests/` creating SQLite engines — Phase 10 adaptation

---

## Inventory completeness statement

This inventory is based on Blueprint tables, `__tablename__` enumeration (55), Alembic head verification, ripgrep for sqlalchemy/DATABASE_URL/DATA_DIR/storage/credentials/signing, runtime route and DB probes, and module review of engine/storage/jobs/audit/backup. Obscure service modules are listed for Phase 3 audit even when not given a full per-function row here; each must be converted before Phase 11 declares SQL runtime removed.
