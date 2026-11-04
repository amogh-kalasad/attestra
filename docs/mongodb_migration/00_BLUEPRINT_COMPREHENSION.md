# Blueprint comprehension

Verified understanding of Attestra’s purpose, architecture, persistence invariants, and Blueprint-versus-checkout differences, produced before any MongoDB application refactoring.

**Sources:** `Attestra_Blueprint.md` (2026-11-03 scan), live checkout at commit `6718536d2c5f76a8fdb302f2706603fafc3e32fd` on branch `mongodb-migration`, plus `docs/ARCHITECTURE.md`, `docs/IMPLEMENTATION_STATUS.md`, `docs/GAP_ANALYSIS_CURRENT.md`, `docs/MASTER_IMPL_PHASE10_MIGRATIONS.md`, `docs/MASTER_IMPL_PHASE11_TESTING.md`, `docs/MASTER_IMPL_PHASE12_FINAL.md`, `lat.md/architecture.md`, and direct inspection of `attestra/{db,models,config,audit,storage,jobs,ops,credentials}.py`.

---

## Application purpose

Attestra is a multi-tenant VAPT and compliance platform (“from findings to signed attestation”). Consultancies run engagements for client tenants with signed authorization and scoped assets, prove ownership, run or import scanners, normalize/fingerprint/deduplicate findings, map to compliance frameworks, capture evidence, and produce SHA-256-frozen reports that pass QA / four-eyes sign-off and Ed25519 (or legacy HMAC) signing with public verification.

---

## Current architecture

| Layer | Implementation |
|---|---|
| Interfaces | FastAPI (`attestra/api.py`) + Jinja staff UI / portal / auditor; argparse CLI (`attestra/cli.py`); public `/share`, `/trust`, `/verify` |
| Business | `attestra/services.py` shared by API and CLI; every mutation audited |
| Execution | Durable DB job queue (`jobs/`) + worker pool; optional Temporal (`ATTESTRA_ORCHESTRATOR=temporal`) |
| Runner | Gate, DNS pin, OPA/Python policy, ownership, scanner adapters under `runner/` |
| Ingest | 17+ importers → observations → fingerprint/dedup/crossmerge → findings |
| Elite automated VAPT | `automated_vapt/` T01–T22 with credit admission and evidence |
| Compliance | YAML libraries + assessor confirmation; PCI/ISO/SOC2/SEBI/RBI/CERT-In/DORA/NIST packs |
| Reports | Jinja HTML freeze → submit → qa_approve → sign; PDF/DOCX/exports |
| Persistence | SQLAlchemy 2 + Alembic; SQLite default or PostgreSQL + RLS; local write-once files or optional S3 |

**Runtime data root:** `ATTESTRA_DATA_DIR` (default `./data`): `attestra.db`, `raw/`, `tenants/<id>/{evidence,imports,reports,credentials}`, `keys/`, `scanner-cache/`, worker lock/log.

---

## Persistence architecture

### Relational database

- Engine/session: `attestra/db.py` — `init()`, `upgrade()` (Alembic head), `session()` with optional Postgres `app.tenant_id` via `tenant_scope`.
- Models: **55** SQLAlchemy tables — 51 in `attestra/models.py` plus `share_links`, `trust_centers`, `trust_items`, `trust_access_requests` in `share/models.py` and `trust/models.py`.
- Live SQLite also has `alembic_version` → **56** physical tables.
- IDs: integer primary keys everywhere except `tenant_credit_accounts.tenant_id` as PK.
- Migrations: **37** revision files; verified head `0036_tenant_ownership_hosts`.
- Tenancy: engagement-scoped rows often lack `tenant_id` and isolate via `engagement_id` → `engagements.tenant_id`. App layer uses `services.tenant_ids_for` / `assert_engagement_access`. Postgres RLS in `rls.py` covers most tables; **no RLS** on `users`, `api_keys`, `jobs`, `audit_events`, `certification_authority`, and **`automated_test_executions`** (has `tenant_id` but missing policy — known gap).

### Durable files

- Protocol `Storage` in `attestra/storage/__init__.py`: `put` / `get` / `exists`; backends `LocalStorage` (`local://…`, write-once, chmod 0o444) and optional `S3Storage`.
- Paths also written under `RAW_DIR` for scanner/automated outputs; credentials under `tenants/<tid>/credentials/` (Fernet ciphertext); signing keys under `data/keys/`.
- Backup (`ops/backup.py`) is **SQLite-only** today: online backup API + hashed manifest of DB + selected DATA_DIR trees.

### Sensitive material

- Session secret / API-key pepper: env (dev defaults exist — production must override).
- Engagement credentials: Fernet files keyed by opaque `secret_ref` (`credentials/store.py`); Fernet key outside DB.
- Report signing: Ed25519 PEM + public key; legacy HMAC key file.
- Platform secrets: `secret_store.py` env or Vault/OpenBao KV v2 (read-oriented for platform secrets).

---

## Subsystem dependency map

```text
Auth/sessions/API keys ──► Users/memberships/tenants
        │
        ▼
Engagements ──► Authorizations, assets, scope, ownership hosts
        │
        ├──► ScanRuns + Jobs ──► Worker ──► RAW artifacts ──► Importers
        │                              └──► Automated executions
        ├──► Findings ◄── Observations / evidence / proof / retests
        ├──► Compliance assessments / SoA / NC / ASV / schedules
        ├──► Credits ledger (admit/refund) ◄── scan + automated paths
        ├──► Reports (freeze/QA/sign) ──► keys + report files
        ├──► Share / trust / verify (public)
        └──► Webhooks / alerts / tickets / library / retention

Audit hash chain ◄── nearly every write path (services + jobs + credits + …)
```

---

## Data ownership and tenant boundaries

- Root: `tenants`. Engagements carry `tenant_id`. Most domain rows hang off engagement or finding.
- Explicit `tenant_id` on newer tables (credits, auth_web, webhooks, library, share, trust, comments, automated executions, ownership hosts).
- Admin: unrestricted (`tenant_ids_for` → `None`). Staff without home tenant or memberships currently treated as unrestricted “platform operator” (Blueprint/documented risk).
- Empty Postgres RLS setting = unrestricted; CLI/worker sessions without `tenant_scope` see all rows — isolation relies on application checks.

---

## Critical workflows (must preserve)

1. Engagement setup: tenant → engagement → authorization → assets → ownership verify → scope.
2. Scan admit: credit check → gate → `ScanRun` + `Job` queued → worker claim → scanner → raw store → import → fingerprint/dedup/crossmerge → checklist_auto (savepoint) → complete/refund.
3. Automated VAPT: execution row QUEUED → claim → orchestrator → findings/evidence → credit semantics.
4. Finding lifecycle: transitions, comments, assignments, retests, risk acceptance, SLA.
5. Report: draft HTML freeze (sha256) → submit → QA ≠ author → sign (lead/admin, ≠ author, ≠ QA) → public verify.
6. Audit: append-only hash chain; verify CLI/API.
7. Credits: atomic balance + ledger with idempotency keys.
8. Backup/restore with sha256 manifest (today SQLite-shaped).

---

## Security and compliance invariants

| Invariant | Mechanism today |
|---|---|
| Write-once evidence/reports | Storage refuses conflicting overwrite; identical bytes idempotent |
| Report freeze | Re-hash before workflow transitions |
| Four-eyes | QA ≠ author; signer ≠ author and ≠ QA |
| Signing identity stability | Do not regenerate keys for already-signed reports |
| Audit append-only | SQLite triggers / Postgres triggers; never rewrite history |
| Credential plaintext out of SQL | `secret_ref` only in DB |
| Scope/ownership gate | Intrusive scans blocked without verification (bypass flags refused in staging/prod) |
| Tenant isolation | App checks + Postgres RLS (incomplete for some tables) |

---

## Known architecture risks (pre-migration)

1. **Audit chain concurrency:** laptop DB verifies **BROKEN at event id 532** (`audit.verify`). Race on read-last-then-insert without serialization (Blueprint §5.14). Must migrate hashes as-is; never silent-repair.
2. **RLS gap:** `automated_test_executions` lacks policy despite `tenant_id`.
3. **Unscoped sessions:** empty tenant setting / missing memberships → broad access.
4. **Webhook secrets** stored plaintext in DB; dispatch requires explicit API call (no background drain).
5. **Backup** refuses non-SQLite URLs.
6. **lat.md/architecture.md** still cites Alembic head `0027_…` while checkout head is `0036_…` (docs drift).
7. Scanner image digests include placeholder zeros; live E2E optional.

---

## Blueprint-versus-code differences

| Topic | Blueprint claim | Checkout verification |
|---|---|---|
| ORM tables | 55 | **55** models confirmed (51+1+3) |
| Alembic | 37 files, head `0036_tenant_ownership_hosts` | **37** files; live DB at `0036_…` |
| Integer IDs | Yes | Confirmed |
| FastAPI routes | 291 | **287** flattened `APIRoute`s via nested routers (FastAPI `_IncludedRouter`); ~4 difference vs Blueprint scan |
| JSON columns | 29 in models.py | Accepted as baseline; not re-counted column-by-column in this gate |
| Tests | 102 files / ~808 functions | **102** `test_*.py` files present |
| SQLite DB | Present on laptop | `data/attestra.db` 1,679,360 bytes; mostly empty engagement data; 781 audit events; 9 tenants; 4 users |
| Artifacts | tenants/raw evidence | Empty `tenants/`, `raw/`, `evidence/`; **2** signing key files; large `scanner-cache/` (~47 MB, 14k files — cache, not authoritative evidence) |
| `docs/ARCHITECTURE.md` | Full architecture | Stub pointing at external artifact; Blueprint + `lat.md` + code are authoritative |
| `IMPLEMENTATION_STATUS.md` | Older snapshot | Stale relative to current feature set; `GAP_ANALYSIS_CURRENT.md` closer |
| MongoDB | None | **No** pymongo/motor usage in package |
| Browser storage | — | **No** `localStorage` / `sessionStorage` in package JS |

---

## MongoDB migration impact

| Area | Impact |
|---|---|
| `db.py` / Alembic / SQLAlchemy sessions | Replace with Mongo client, versioned collection migrations, repositories |
| 55 entities + relationships | Collections with preserved integer IDs and explicit integrity checks |
| Jobs claim (`UPDATE … WHERE status='queued'`) | `find_one_and_update` atomic claim + leases |
| Audit chain | Serialized append (transaction/head lock); preserve broken historical chain |
| Credits | Multi-doc transactions + idempotency |
| Storage local/S3 | Mongo/GridFS provider with `mongo://` URIs; resolve legacy `local://` during transition |
| Credentials / signing keys | Ciphertext may move to Mongo only if encryption key remains outside DB; prefer continuing encrypted blob store pattern |
| Postgres RLS | Replace with mandatory tenant filters in repositories |
| Backup | Mongo-aware consistent backup including GridFS |
| Tests | Replace SQLite fixtures with Mongo test deployment for active paths; keep SQL fixtures for import-tool tests |

---

## Features that must remain unchanged

- All CLI commands, flags, and exit semantics.
- REST/UI routes, status codes, permission gates, public IDs in URLs/bodies.
- Finding fingerprints, lifecycle transitions, report workflow states.
- Hash/signature verification for reports and evidence SHA-256.
- Credit balances and ledger semantics.
- Ownership/authorization/gate refusal behavior.
- Multi-tenant isolation for non-admin principals (must not weaken).
- Source SQLite/Postgres and local artifacts retained until authorized cutover.

---

## Gate status

**COMPREHENSION GATE: COMPLETE** — safe to proceed to Phase 0 inventory documentation (this package) and subsequent design/implementation phases under the execution prompt’s controls.
