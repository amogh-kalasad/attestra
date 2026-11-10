# DATABASE_AUDIT — MongoDB and persistence (Attestra)

**Agent:** AGENT 2 (MongoDB and Persistence Engineer)  
**Scope:** Inspection only; no application code changes.  
**Date:** 2026-11-10  
**Workspace:** `C:\Github\attestra`  
**Grounding:** `lat search "MongoDB persistence migration"` → [[lat.md/architecture#Architecture#MongoDB migration (in progress)]], [[lat.md/architecture#Architecture#Schema migrations]], [[lat.md/tests#Tests#Mongo schema migrations]].

---

## 1. Current persistence architecture

Runtime persistence is **MongoDB only**. Production execution paths bootstrap Mongo, not SQL engines.

| Layer | Role | Evidence |
| --- | --- | --- |
| Bootstrap | `init_persistence()` → `init_mongo(apply_migrations=…)` | `attestra/bootstrap.py` |
| API lifespan | `config.validate_runtime_config()` then `init_persistence(use_migrations=True)` | `attestra/api.py` lifespan |
| CLI | `attestra init` → `init_persistence`; `serve`/`worker`/`db.init(use_migrations=True)` | `attestra/cli.py` (`cmd_init`, `cmd_worker`, identity helpers) |
| Session façade | `db.session()` yields `MongoSession` (SQLAlchemy Session look-alike) | `attestra/db.py`, `attestra/persistence/mongo/orm_session.py` |
| Schema | SQLAlchemy declarative models remain as the **MongoSession schema / query builder** | `attestra/models.py`, `share/models.py`, `trust/models.py`; `pyproject.toml` comment |
| Repositories | Explicit PyMongo repos for identity, jobs, credits, audit, reports, webhooks, etc. | `attestra/persistence/mongo/repositories/` |
| Adapters | Hot paths for jobs/credits/audit forward to repos | `attestra/persistence/mongo/adapters.py`, `jobs/durable.py` |
| Blobs | Default storage `mongo` → GridFS (`mongo://` URIs) | `attestra/storage/__init__.py`, `attestra/storage/mongo.py` |
| Backup | Logical collection + GridFS export with SHA-256 manifest | `attestra/ops/backup.py` → `ops/mongo_backup.py` |
| Health | `/api/health` reports `persistence: mongo` + `mongo.ping()` | `attestra/api.py`, `persistence/mongo/health.py` |

**Important:** Mongo repositories existing under `persistence/mongo/` is necessary but not sufficient by itself. Verified execution paths (API lifespan, CLI init/serve/worker, `db.session` → MongoSession, backup → `backup_mongo`) all open Mongo. There is **no** live `create_engine` / `sessionmaker` / Alembic upgrade path in current Python sources.

`ATTESTRA_PERSISTENCE` is retained for older deploy env files but config defaults to `mongo` and bootstrap always initializes Mongo (`config.py`, `bootstrap.py`).

---

## 2. MongoDB dependency inventory

### Connection / identity

| Setting | Source | Default / notes |
| --- | --- | --- |
| `ATTESTRA_MONGODB_URI` | `config.py`, `persistence/mongo/config.py`, `.env.example` | `mongodb://127.0.0.1:27017/?replicaSet=rs0` |
| `ATTESTRA_MONGODB_DB` | same | `attestra` |
| `ATTESTRA_TEST_MONGODB_URI` | `.env.example`, `tests/conftest.py` | same host; tests force DB names `attestra_test_*` |
| Auth | URI user/password + `authSource=admin` (documented) | Not separate env vars; see `docs/mongodb_migration/SECURE_LOCAL_MONGO.md` |
| TLS | `ATTESTRA_MONGODB_TLS`, `ATTESTRA_MONGODB_TLS_CA_FILE` | Off by default |
| Pool / timeouts | `ATTESTRA_MONGODB_*_TIMEOUT_MS`, `MAX_POOL_SIZE` | 5s / 5s / 30s / 50 |
| GridFS bucket | `ATTESTRA_MONGODB_GRIDFS_BUCKET` | `attestra_artifacts` |

### Replica set

- **Required** for multi-document transactions (`with_transaction` in credits, audit append, report store, job-related repo paths). Documented in README and `SECURE_LOCAL_MONGO.md`.
- Client does **not** call `require_transactions_capable()` at bootstrap (function exists only in `health.py`, never referenced elsewhere).
- `init_mongo` only `ping`s; it does not assert `hello.setName`.
- Local `.env` in this checkout uses `?directConnection=true` (not the example’s `replicaSet=rs0`), which can talk to a standalone `mongod` and then fail when transaction-using repo paths run.

### Driver / packages

- Runtime: `pymongo>=4.6` (required), `sqlalchemy>=2.0` (schema/query builder only).
- **No** `alembic`, **no** `psycopg` / `[postgres]` extra in current `pyproject.toml`.
- GridFS via `gridfs.GridFSBucket` in `storage/mongo.py` and backup.

---

## 3. Repository inventory (`attestra/persistence/mongo`)

### Package surface

| Module | Purpose |
| --- | --- |
| `client.py` | `MongoClient` lifecycle, `init_mongo` / `get_db` / `close_client`, pytest live-DB guard |
| `config.py` | Env-driven URI/DB/TLS/pool/GridFS |
| `collections.py` | 56 domain collection name constants + meta (`id_sequences`, `_schema_migrations`, `audit_chain_head`) |
| `indexes.py` | Idempotent index creation (partial unique for credit idempotency) |
| `migrations/` | Versioned apply: `0001_mongo_baseline`, `0002_identity_webhooks`, `0003_credit_idempotency_partial` |
| `orm_session.py` | MongoSession: select/flush/commit/rollback without multi-doc txn |
| `transactions.py` | `with_transaction` + retry classification |
| `tenant.py` | `tenant_filter`, `via_engagement_filter`, `TenantAccessDenied` |
| `adapters.py` | Job/credit/audit bridges used by durable worker & services |
| `service_bridge.py` | `MongoUnitOfWork` + `tenant_ids_for_principal` |
| `health.py` | `ping`, unused `require_transactions_capable` |
| `sequences.py` / `serialization.py` / `secrets_codec.py` / `read_models.py` | IDs, BSON shaping, webhook secret protect, DocView |
| `report_store.py` / `report_reads.py` | Report write/read helpers |
| `jobs_proxy.py` | Job proxy helpers |

### Repositories exported (`repositories/__init__.py`)

**Core:** `TenantRepository`, `UserRepository`, `MembershipRepository`, `ApiKeyRepository`, `EngagementRepository`, `AssetRepository`, `AuthorizationRepository`, `ScopeRuleRepository`, `FindingRepository`  

**Identity:** `UserAdminRepository`, `InviteRepository`, `ApiKeyAdminRepository`  

**Ops:** `AuditRepository`, `JobRepository`, `CreditRepository`, `ArtifactRepository`  

**Reports / settings / webhooks:** `ReportRepository`, `EmailAlertSettingsRepository`, `EmailAlertSentRepository`, `CertificationAuthorityRepository`, `WebhookEndpointRepository`, `WebhookDeliveryRepository`, `WorkflowRuleRepository`, `FindingAssignmentRepository`

Many domain collections (comments, ASV, SOA, retests, auth-web inventories, trust items, etc.) are reached primarily through **MongoSession + mapped models**, not dedicated repository classes.

---

## 4. Remaining SQLAlchemy / Alembic paths

### Intentional (still required)

| Usage | Why it remains |
| --- | --- |
| `sqlalchemy.orm.DeclarativeBase` / mapped models | Schema for MongoSession |
| `select()` / `Session` type hints across services, reports, auth_web, jobs, etc. | Compiled by MongoSession into Mongo filters |
| `from sqlalchemy.orm import Session` annotations | API compatibility with MongoSession |

This matches README / `lat.md/architecture`: SQLAlchemy is the query/schema layer over Mongo, not a second database.

### Not intentional leftovers / stale deploy artifacts

| Artifact | Status |
| --- | --- |
| `alembic.ini` | **Absent** (`Test-Path` false) |
| `migrations/versions/*.py` | **Absent**; only `__pycache__/*.pyc` for 0001–0036 remain |
| `pyproject.toml` `[postgres]` / alembic deps | **Removed** |
| `attestra/rls.py` | **Absent** (only `.bak_mongofull2`) |
| `data/attestra.db` | Leftover SQLite file under `data/` (not used by runtime bootstrap) |
| `Dockerfile` | Still `COPY alembic.ini`, `COPY migrations`, `pip wheel ".[postgres]"` — **broken vs current tree** |
| Helm `persistenceBackend: mongo \| sql`, `databaseUrl` / `ATTESTRA_DATABASE_URL` | Chart still advertises SQL legacy; app code no longer runs SQL |
| Docs (`SETUP_GUIDE.md`, `RELEASE.md`, `ELITE_VAPT_DEPLOY.md`, many MASTER_IMPL_*) | Still instruct `alembic upgrade head` / Postgres |
| `.migration_backups/sql_removal/` | Referenced by `migration/engine.py` and lat docs; **not present** in this checkout |

**Conclusion:** SQLAlchemy-on-MongoSession is intentional. Alembic/Postgres runtime is **not** on hot paths. Stale Docker/Helm/docs still imply SQL and will confuse operators or break image builds.

---

## 5. Index / init / migration status

### Init sequence

1. API/CLI: `validate_runtime_config` → `init_persistence` / `db.init` → `init_mongo`.
2. `init_mongo`: build client → `admin.command("ping")` → optional `apply_pending`.
3. Migrations touch collections, call `ensure_indexes`, seed `audit_chain_head`, identity/webhook indexes, credit partial unique indexes.
4. Revisions recorded in `_schema_migrations`.

### Mongo migration revisions (implemented)

| Rev | Description |
| --- | --- |
| `0001_mongo_baseline` | Create domain collections + indexes + audit head |
| `0002_identity_webhooks` | Invite/webhook/workflow/assignment indexes; encrypt webhook secrets |
| `0003_credit_idempotency_partial` | Partial unique indexes for optional idempotency keys |

### Index coverage gaps

`ensure_indexes` / migrations do **not** create indexes for at least these domain collections (present in `DOMAIN_COLLECTIONS`):

`finding_comments`, `risk_acceptances`, `asv_scans`, `asv_scan_items`, `segmentation_tests`, `scan_schedules`, `nonconformities`, `soa_entries`, `audit_samples`, `retests`, `tenant_risk_weights`, `suppression_rules`, `proof_replays`, `cert_expiry_alerts`, `auth_credential_profiles`, `auth_element_inventory`, `tenant_credit_accounts`, `certification_authority`, `trust_items`, `trust_access_requests`.

Some of these are queried by `engagement_id` / `tenant_id` on hot paths (auth-web, compliance, credits account lookup) and will degrade without indexes as data grows.

### SQL Alembic

Archived/removed from source. Pycache-only remnants under `migrations/` are not a runnable migration tree.

---

## 6. Tenant isolation mechanism

| Mechanism | Behavior | Evidence |
| --- | --- | --- |
| Postgres RLS | **Gone** (`rls.py` removed) | filesystem |
| Repository scope | `tenant_ids: frozenset[int] \| None`; `None` = unrestricted; cross-tenant → `TenantAccessDenied` / “not found” | `tenant.py`, `repositories/base.py`, `tests/persistence/test_mongo_tenant_isolation.py` |
| Service helpers | `tenant_ids_for`, `scoped`, `assert_engagement_access`, `get_finding`, … | `services.py` |
| MongoSession | Stores `tenant_ids` in `session.info` but **does not auto-filter** queries | `orm_session.py` (only assignment at `__init__`) |
| `db.tenant_scope` | ContextVar helper exists; **not used** by API routes (no call sites beyond definition) | `db.py` grep |
| Webhooks / reports | Explicit `tenant_ids=` into repos / `report_reads` | `webhooks/mongo_service.py`, `reports/render.py` |

Isolation is **application-enforced**, not database-enforced. Correctness depends on every route/service using `scoped` / `assert_engagement_access` / scoped repositories. Mongo migration doc `08_SECURITY_AND_TENANCY_VALIDATION.md` still lists “end-to-end API cross-tenant matrix against Mongo-backed app process” as not fully verified.

---

## 7. Gaps `DATABASE-G01…`

### DATABASE-G01 — Dockerfile still builds SQL/Alembic image

- **Current:** `Dockerfile` copies missing `alembic.ini`, copies empty-of-source `migrations/`, installs `.[postgres]` (extra removed).
- **Expected:** Image installs Mongo-only deps; no Alembic COPY; env already sets `ATTESTRA_PERSISTENCE=mongo` / GridFS URI.
- **Risk:** Image build fails; or an old Dockerfile misleads ops into expecting Postgres.
- **Required change:** Rewrite Dockerfile for Mongo-only install; drop alembic/postgres COPY and extras.
- **Status:** Open  
- **Evidence:** `Dockerfile` L10–L30; `pyproject.toml` (no postgres/alembic); `Test-Path alembic.ini` → false.

### DATABASE-G02 — No replica-set init in Docker / compose / k8s

- **Current:** App URI defaults to `replicaSet=rs0`. README/SECURE_LOCAL_MONGO document manual `rs.initiate()`. No `docker-compose` in repo; `deploy/k8s/` has no Mongo StatefulSet/init Job; Helm expects external `mongodbUri`.
- **Expected:** Documented + optional compose/Helm sidecar or init container that starts `mongo:7 --replSet rs0` and initiates once.
- **Risk:** Fresh environments time out on server selection or fail first multi-doc transaction.
- **Required change:** Add compose (or Helm subchart) with `--replSet rs0` + one-shot `rs.initiate`, or require managed Atlas/replica URI in install checks.
- **Status:** Open  
- **Evidence:** README replica section; `Dockerfile` default URI; no compose files; `deploy/k8s` grep empty for mongo; Helm `mongodbUri: ""`.

### DATABASE-G03 — Bootstrap never enforces transaction capability

- **Current:** `require_transactions_capable()` is defined but never called. `init_mongo` only pings.
- **Expected:** Fail fast at API/worker/init if `hello.setName` is missing when transaction-using features are required.
- **Risk:** Process starts “healthy”, then credit/audit/report transactions throw at runtime; `/api/health` can still show `ok` without replica set name if ping works with `directConnection`.
- **Required change:** Call `require_transactions_capable()` from `init_mongo` or `init_persistence`; surface `replica_set` failure as startup error.
- **Status:** Open  
- **Evidence:** `health.py` (`require_transactions_capable`); repo-wide grep → single definition; `client.py` ping-only.

### DATABASE-G04 — MongoSession has no multi-document transactions

- **Current:** Orm session commit/rollback is best-effort per-doc; docstring states no multi-doc txn. Critical paths (audit chain, credits consume, some report writes) use `with_transaction` in repositories; most `services.py` MongoSession flushes do not.
- **Expected:** Either document which mutations are txn-safe, or wrap multi-collection service writes in transactions.
- **Risk:** Partial writes on crash mid-`flush` (e.g. finding + observation + evidence metadata).
- **Required change:** Inventory multi-collection service writes; migrate high-risk ones onto `with_transaction` or repo UoW.
- **Status:** Open  
- **Evidence:** `orm_session.py` module docstring L14–15; `transactions.py`; selective use in `repositories/ops.py`, `report_store.py`.

### DATABASE-G05 — Incomplete collection indexes

- **Current:** ~20 domain collections have no index definitions in `indexes.py` / migrations (list in §5).
- **Expected:** Indexes aligned with access patterns (`engagement_id`, `tenant_id`, unique business keys).
- **Risk:** Latency and collection scans as tenants grow; racey uniqueness for some entities.
- **Required change:** Add migration `0004_…` covering auth-web, compliance, credits accounts, trust children, comments, etc.
- **Status:** Open  
- **Evidence:** Diff of `DOMAIN_COLLECTIONS` vs `ensure_indexes` / migrations.

### DATABASE-G06 — Stale SQL docs and Helm SQL toggle

- **Current:** SETUP_GUIDE / RELEASE / elite deploy / MASTER_IMPL still say Alembic/Postgres. Helm `persistenceBackend: sql` and `ATTESTRA_DATABASE_URL` remain.
- **Expected:** Operator docs and charts match Mongo-only runtime.
- **Risk:** Wrong production procedure; failed installs; accidental expectation of RLS.
- **Required change:** Update SETUP_GUIDE and release checklists; remove or hard-error Helm `sql` backend.
- **Status:** Open  
- **Evidence:** `SETUP_GUIDE.md` §7; `deploy/helm/attestra/values.yaml` L26–36; `templates/secret.yaml`.

### DATABASE-G07 — Engagement credentials still filesystem-default

- **Current:** `credentials/store.py` defaults to `EncryptedLocalStore` under `DATA_DIR`. `EncryptedMongoStore` exists (`credential_secrets`) and is included in mongo backup collection list, but is not the default engagement store.
- **Expected:** If storage/persistence are mongo, credentials either live in Mongo (ciphertext) or backup/restore explicitly always copies `DATA_DIR/tenants/*/credentials`.
- **Risk:** GridFS-only restore misses login secrets unless `keys`/tenant credential files are copied; split-brain between Mongo metadata and local ciphertext.
- **Required change:** Wire Mongo store behind config flag or document mandatory DATA_DIR backup for credentials; include tenant credential trees in backup (today backup includes `keys/` only by default).
- **Status:** Open  
- **Evidence:** `credentials/store.py` L9–15, L222; `mongo_store.py`; `mongo_backup.py` `include_data_dir_keys` → `keys` only.

### DATABASE-G08 — Alembic pycache + SQLite file litter

- **Current:** `migrations/**/__pycache__` and `data/attestra.db` remain.
- **Expected:** Clean tree or archive under a clearly named backup folder present in-repo.
- **Risk:** False signal that SQL migrations still run; accidental use of old DB file.
- **Required change:** Delete pycache leftovers / move SQLite to archive; ensure `.gitignore` covers them.
- **Status:** Open  
- **Evidence:** `migrations/versions/__pycache__` listing; `data/attestra.db`.

### DATABASE-G09 — Tenant isolation not automatic on MongoSession

- **Current:** Isolation relies on service helpers; MongoSession ignores `tenant_ids` for queries. `tenant_scope` unused.
- **Expected:** Defense in depth: session-level filter **or** exhaustive API matrix proving every route uses helpers; optionally reintroduce DB-level constraints where possible.
- **Risk:** New route that uses raw `select(Model)` without `scoped()` leaks cross-tenant data (Postgres RLS no longer backs this).
- **Required change:** Enforce tenant filter in MongoSession when `info["tenant_ids"]` is set, and/or add e2e API cross-tenant suite (called out as unverified in migration doc 08).
- **Status:** Open  
- **Evidence:** `orm_session.py` tenant_ids only in `info`; `services.py` `scoped`/`assert_engagement_access`; `08_SECURITY_AND_TENANCY_VALIDATION.md` remaining items.

### DATABASE-G10 — Referenced SQL→Mongo archive missing

- **Current:** Code/docs reference `.migration_backups/sql_removal/` for SQL source reader / Alembic archive; directory absent in this checkout.
- **Expected:** Archive present for one-shot import tooling, or references removed.
- **Risk:** Operators cannot re-run SQL→Mongo import from this tree; lat/docs overclaim archive location.
- **Required change:** Restore archive or update `migration/engine.py` / lat notes to the real location.
- **Status:** Open  
- **Evidence:** `migration/engine.py` L3–4; `Test-Path .migration_backups` → false; lat architecture “Legacy SQL trees… under `.migration_backups/sql_removal/`”.

### DATABASE-G11 — Local `.env` uses `directConnection=true`

- **Current:** Checkout `.env` sets `ATTESTRA_MONGODB_URI=.../?directConnection=true` while `.env.example` and product defaults require `replicaSet=rs0`.
- **Expected:** Dev URI matches replica set (or explicitly documents standalone-dev limitations).
- **Risk:** Local “works until” first transactional credit/audit path; tests using example URI diverge from developer env.
- **Required change:** Align `.env` with example; or make startup warn when URI lacks replicaSet / setName empty.
- **Status:** Open (local config; do not commit secrets)  
- **Evidence:** `.env` vs `.env.example` (inspection; no secret values repeated here).

---

## 8. Does Docker need replica-set init scripts?

**Yes.**  

The application **requires** a transactional Mongo deployment (default URI embeds `replicaSet=rs0`; `with_transaction` used for audit/credits/reports). There is currently:

- no compose file that starts `mongod --replSet rs0`,
- no init container/script that runs `rs.initiate()`,
- no in-cluster Mongo chart—only an external URI requirement in Helm,
- a Dockerfile that points at `mongodb://mongo:27017/?replicaSet=rs0` without defining that service.

**Recommendation:** Ship a `docker-compose` (or Helm dependency) with:

1. `mongo:7` (or newer) command `--replSet rs0 --bind_ip_all`,
2. a one-shot init service (`mongosh --eval 'rs.initiate({_id:"rs0", members:[{_id:0, host:"mongo:27017"}]})'` with retry),
3. optional keyFile/auth matching `SECURE_LOCAL_MONGO.md`,
4. healthcheck that asserts `db.hello().setName === "rs0"`,
5. app service depending on that healthcheck, calling `attestra init` / serve with the authenticated replica URI.

Until then, operators must manually initiate the set (as README describes for Windows Community Server).

---

## Backup / restore compatibility (summary)

| Path | Compatible? | Notes |
| --- | --- | --- |
| `attestra backup` / `restore` | Yes for Mongo logical + GridFS + `DATA_DIR/keys` | Manifest hash refuse-on-mismatch |
| `mongodump` / `mongorestore` | Documented complement for PITR | Not wrapped by CLI |
| Old SQLite/Postgres file backups | No | Runtime cannot open SQL URLs |
| Credentials under `DATA_DIR/tenants/.../credentials` | Partial | Not in default mongo backup file set (only `keys/`) — see G07 |

---

## Gap count and top risks

**Gap count: 11** (`DATABASE-G01` … `DATABASE-G11`).

**Top risks (ordered):**

1. **Replica set not guaranteed at startup (G02, G03, G11)** — silent misconfig until transactional writes fail.  
2. **Broken / misleading Docker & Helm SQL leftovers (G01, G06)** — blocked or wrong production installs.  
3. **Tenant isolation is app-only after RLS removal (G09)** — one missed `scoped()` becomes a data leak.  
4. **MongoSession non-transactional bulk of domain writes (G04)** — integrity under crash.  
5. **Index holes on auth-web / compliance / credits collections (G05)** — scale and uniqueness risk.

**What is solid:** Mongo-only bootstrap on API/CLI/worker; versioned Mongo migrations; GridFS write-once storage; repository-level tenant tests; logical backup/restore with manifests; SQLAlchemy retained only as MongoSession schema (intentional).
