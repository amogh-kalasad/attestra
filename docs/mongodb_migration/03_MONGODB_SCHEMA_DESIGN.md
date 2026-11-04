# MongoDB schema design

Target MongoDB architecture for Attestra based on verified access patterns (SQLAlchemy models, jobs claim, audit chain, credits, storage protocol). Design only in this phase; production repository code begins after approval (Phase 3+).

---

## Driver and execution model

| Decision | Choice | Rationale |
|---|---|---|
| Driver | **PyMongo** (sync) first-class | Existing FastAPI handlers and worker threads are sync SQLAlchemy-centric; least disruption vs rewriting to Motor everywhere |
| Optional async | Not required for v1 Mongo cutover | Can add later behind same repository interfaces |
| Transactions | Requires **replica set** (or compatible deployment) | Credits, audit+domain atomic pairs, multi-doc job completion |
| Package layout | `attestra/persistence/mongo/` as specified in execution prompt | New package; do not keep SQLAlchemy as hidden compatibility layer |

### Planned modules

- `client.py` — pool, TLS, timeouts, startup/shutdown
- `config.py` — `ATTESTRA_MONGODB_URI`, DB name, options
- `collections.py` — canonical collection names
- `serialization.py` — UTC datetimes, JSON-compatible details, int IDs
- `indexes.py` — idempotent index ensure
- `transactions.py` — session helpers + retry classification
- `health.py` — ping / replica-set check
- `migrations/` — versioned schema/index/validator migrations
- `repositories/` — one module per aggregate area
- `schemas/` — optional document shape helpers / validators

---

## Identity strategy

- Preserve **integer** public IDs used in URLs, FK-like fields, audit `entity_id`, and reports.
- Store as BSON `int` field `id` **and** use the same integer as `_id` for 1:1 imported documents where possible (`_id: <int>`).
- Allocation for new rows: counters collection `id_sequences` with atomic `find_one_and_update` (`$inc`) per entity, seeded to `max(id)` after import.
- Do **not** expose ObjectId in existing API responses.
- Foreign references remain integer fields (`tenant_id`, `engagement_id`, …) with application-level checks (Mongo does not enforce SQL FKs).

---

## Collection mapping principles

1. **Default: one SQL table → one collection** (independent lifecycle, high cardinality, concurrent writers, or cross-references).
2. Embed only when ownership is strict, cardinality bounded, and never queried independently across parents.
3. Respect 16 MB document limit — observations, evidence, webhook deliveries, audit events stay separate.
4. JSON/SQLAlchemy JSON columns → BSON documents/arrays with the same semantic null/bool/number behavior.
5. Timestamps: store timezone-aware UTC (`Date` BSON); serialize ISO-8601 at API edge as today.

### Embedding decisions

| Candidate | Decision |
|---|---|
| `tenant_risk_weights` (1:1 tenant) | **Separate** initially (simpler parity); optional later embed |
| `asv_scan_items` | **Separate** (item lists can grow) |
| `auth_element_inventory` | **Separate** |
| Certification authority singleton | Single doc in `certification_authority` with fixed `_id: 1` |
| Job embedded in scan_run | **No** — claim path needs independent atomic updates |

Full 55-table mapping: see `01_PERSISTENCE_INVENTORY.md` §A.2.

---

## Critical collection designs

### `audit_events`

```text
_id: int                  # legacy id
ts: date
actor: str
action: str
entity: str
entity_id: int|null
details: object
prev_hash: str
hash: str
```

**Concurrency:** maintain `audit_chain_head` singleton (`_id: "head"`, `last_id`, `last_hash`) updated in the same transaction as the insert. On conflict/retry, re-read head. Historical broken links (e.g. id 532) must remain.

**Indexes:** `{_id:1}` PK; `{ts:1}`; `{entity:1, entity_id:1}`.

**No TTL.**

### `jobs`

```text
_id: int
scan_run_id: int          # unique
status: queued|running|completed|failed|…
attempts: int
worker_id: str|null
heartbeat_at: date|null
cancel_requested: bool
error: str|null
lease_token: str|null     # fencing for stale workers (additive)
```

**Claim:** `find_one_and_update` filter `{status:"queued", …}` sort `{_id:1}` update status/worker/heartbeat/attempts/lease_token.

**Indexes:** unique `scan_run_id`; compound `{status:1, _id:1}`; `{status:1, heartbeat_at:1}` for stale recovery; optional join field denorm `tool` for exclude_tools claims.

### Credits

- `tenant_credit_accounts`: `_id: tenant_id`, `balance`, `grant_total`
- `credit_transactions`: integer id; unique `idempotency_key`; links to tenant/engagement/scan_run/renewal
- Admit/refund/allocate: multi-document transaction updating account + inserting txn; reject duplicate idempotency keys

### `findings` / `finding_observations`

- Unique compound index `(engagement_id, fingerprint)` on findings
- Observations high-write; indexes on `engagement_id`, `finding_id`, `import_run_id`, `scan_run_id`

### `reports`

- Keep `path` as storage URI (`mongo://…` after Phase 4)
- Preserve `sha256`, status enum, user id fields for four-eyes
- Unique-ish versioning via index `(engagement_id, kind, version)` if enforced today logically

### Artifacts metadata + GridFS

| Concern | Design |
|---|---|
| Bytes | GridFS bucket `attestra_artifacts` (or separate buckets: `evidence`, `reports`, `raw`) |
| Metadata collection | `artifacts` with `sha256`, `tenant_id`, `content_type`, `gridfs_id`, `uri`, `immutable: true` |
| URI | `mongo://artifacts/<sha256_or_key>` |
| WORM | Application refuse overwrite on sha/uri conflict; document that GridFS ≠ S3 Object Lock |
| Legacy | Resolver accepts `local://` and existing S3 URIs during dual-read |

### Encrypted secrets

- Engagement credential ciphertext: either GridFS/encrypted binary doc keyed by `secret_ref`, or continue file backend until Phase 4 cutover
- Fernet key **never** stored in Mongo
- Signing private keys remain outside Mongo (`DATA_DIR/keys` or KMS)

---

## Tenant isolation design (replaces RLS)

Every repository method that touches tenant-owned data must accept `tenant_ids: frozenset[int] | None` (`None` = unrestricted admin).

| Pattern | Filter |
|---|---|
| Direct tenant column | `{tenant_id: {$in: list}}` or equality |
| Via engagement | resolve engagement ids for tenant set, or `$lookup`/prefilter `engagement_id ∈ …` |
| Via finding | join finding → engagement tenant |
| Global-by-design | `audit_events`, `api_keys`, `jobs`, `certification_authority` — keep global semantics but gate via permissions |
| `automated_test_executions` | **Always** filter by `tenant_id` (fix Blueprint RLS gap in Mongo layer) |

Missing tenant context for non-admin must **not** default to unrestricted in the new layer (stricter than empty Postgres setting); admin remains unrestricted. Document any intentional CLI operator behavior.

---

## Index catalog (minimum)

| Collection | Indexes |
|---|---|
| tenants | unique `name` |
| users | unique `username`; `tenant_id` |
| api_keys | unique `key_hash`; `user_id` |
| tenant_memberships | unique `(user_id,tenant_id)`; `tenant_id` |
| engagements | `tenant_id`; `(tenant_id, status)` |
| findings | unique `(engagement_id, fingerprint)`; `asset_id`; status |
| finding_observations | `engagement_id`, `finding_id`, `import_run_id` |
| evidence | `finding_id`, `sha256` |
| jobs | see above |
| audit_events | see above |
| credit_transactions | unique `idempotency_key`; `tenant_id` |
| credit_renewal_requests | unique `idempotency_key` |
| share_links | unique `token_hash`; `tenant_id` |
| user_invites | unique `token_hash` |
| trust_centers | unique `tenant_id`; unique `slug` |
| webhook_deliveries | `(status, next_attempt_at)` |
| auth_route_inventory | unique `(engagement_id,asset_id,url,role_name,http_method)` |
| auth_checklist_items | unique `(engagement_id, ref)` |
| control_assessments | unique `(engagement_id,framework,control_ref)` |
| library_entries | unique `(tenant_id,title)` |
| report_templates | unique `(tenant_id,kind)` |
| retention_policies | unique `(tenant_id,framework)` |
| tenant_ownership_hosts | unique `(tenant_id,hostname)` |
| email_alert_sent | unique `(event_type,entity_type,entity_id)` |
| artifacts | unique `uri`; unique `sha256` where content-addressed; `tenant_id` |

No TTL indexes on evidence, audit, reports, or legal-hold retention rows.

---

## Validation rules

Use collection validators (moderate strictness) for required fields on `tenants`, `users`, `engagements`, `findings`, `jobs`, `audit_events`, `reports`, credit collections. Avoid brittle validators on frequently evolving JSON blobs (`details`, checklist evidence_ids) — validate in application/Pydantic at write boundaries where Attestra already validates.

---

## Migration versioning

Collection `_schema_migrations`: `{_id: revision, applied_at, description}` analogous to Alembic. Bootstrap creates collections + indexes from ordered Python migration modules under `persistence/mongo/migrations/`.

---

## Transaction boundaries (initial)

| Operation | Transaction? |
|---|---|
| Audit append (+ optional domain write that must be atomic) | Yes + head lock |
| Credit admit/refund/allocate | Yes |
| Job claim | Single-doc atomic op (no multi-doc required) |
| Job complete + scan_run status + optional credit refund | Yes when multi-doc |
| Evidence put + evidence row | Staged write: upload GridFS → verify hash → insert metadata → insert evidence row; compensating delete on failure |
| Report sign | Domain update + audit in txn; artifact already immutable on disk/GridFS |

---

## Dual-run / cutover stance

Phase 2–10 implement Mongo-native repositories behind services. Legacy SQL remains until Phase 11 removal. Data copy via Phase 7 tooling only after backups and dry-runs. Production cutover is Phase 12 and requires explicit approval.

---

## Phase 2 status

**STATUS: VERIFIED (design)** — schema, indexes, ID strategy, GridFS, tenant filters, and transaction boundaries documented. **Mongo foundation code not yet landed** (held for approval gate per operator instruction: pause every 3 phases).
