# AASI repository findings

Phase 0 track B inventory of Attestra source paths that AASI must extend.
Verified on branch `attestra-asi-bundle` against the working tree (no product code changed).

## Source-code baseline paths

Existence and role of every integration point AASI will reuse. Paths are relative to the repository root. **Next free Mongo migration ID: `0005`.**

### Existence table

| Path | Exists | Role (1–3 sentences) |
|---|---|---|
| `attestra/db.py` | yes | Mongo-only session façade. Keeps SQLAlchemy `Base` as the declarative schema; `session()` yields `MongoSession` (no SQL engine). |
| `attestra/persistence/mongo/collections.py` | yes | Canonical Mongo collection name constants (`FINDINGS`, `JOBS`, `AUDIT_EVENTS`, …) plus `DOMAIN_COLLECTIONS`. |
| `attestra/persistence/mongo/migrations/__init__.py` | yes | In-code `MIGRATIONS` list applied by `apply_pending()`; no Alembic / migration files. |
| `attestra/persistence/mongo/tenant.py` | yes | Tenant scope helpers: `effective_scope`, `SYSTEM_SCOPE`, `TenantAccessDenied`; optional K-01 strict mode. |
| `attestra/runner/scanners/sdk.py` | yes | `AdapterMeta`, `ResourceProfile`, `DEFAULT_META`, contract checks (`problems`), safety tiers T0–T3. |
| `attestra/runner/scanners/base.py` | yes | `ScannerResult`, `run_process` (no shell, kill tree), abstract `ScannerAdapter.scan` / `health`. |
| `attestra/runner/scanners/registry.py` | yes | Name → adapter map (`get_adapter`, `list_adapters`). |
| `attestra/runner/authorization.py` | yes | Engagement scope (`scope_for_engagement`), `authorize_target`, URL/IP/path/image validators, `assert_safe_cli_arg`. |
| `attestra/automated_vapt/core/authorization_guard.py` | yes | Pre-execution readiness: `assert_engagement_ready_for_case`, `load_asset`, halt/expiry/ownership reasons. |
| `attestra/automated_vapt/core/planner.py` | yes | `PlanFacts`, `PlannedCase`, `plan_cases()` → run / skip / defer with rate profiles. |
| `attestra/automated_vapt/core/test_registry.py` | yes | Elite catalogue `TestCase` IDs (T01–T22, INJ, XSS*, FILE, SSRF, UPLOAD, BIZ, ROLEDIFF, SESSION, SESSLIFE, OIDCMETA, CORS, HOSTHDR, OREDIR, CACHE, SSIND, GRAPHQL, APIPOST, SCOPE_SMOKE). |
| `attestra/automated_vapt/core/intrusive_policy.py` | yes | Fail-closed gate for SSRF/UPLOAD/XSSSTORE/T22; env flags, profile, allowlist; production forbidden. |
| `attestra/automated_vapt/core/run_validity.py` | yes | Deterministic run-validity states (`VALID`, `AUTH_EXPIRED`, `CHALLENGE_DETECTED`, …) from response classifications. |
| `attestra/automated_vapt/coverage/ledger.py` | yes | Per-case `CoverageLedgerEntry` persisted under execution `result_json.coverage_ledger`. |
| `attestra/finding_validation/statuses.py` | yes | Validation-class constants (separate from workflow status). |
| `attestra/models.py` | yes | Domain ORM schema including `ASSET_KINDS`, `TEST_TYPES`, engagements/assets/findings. |
| `attestra/importers/base.py` | yes | `NormalizedFinding` shape + `parse_cwe` / `norm_severity`. |
| `attestra/importers/__init__.py` | yes | `PARSERS` registry and `parse(tool, raw)`. |
| `attestra/ai_narratives.py` | yes | Optional AI drafts: `Provider` protocol, Ollama/OpenAI-compat, `ATTESTRA_AI_TENANTS_OFF`, redaction. |
| `attestra/proof/` | yes | HTTP pair / screenshot capture, redact, replay, store for exploit evidence. |
| `attestra/audit.py` | yes | Hash-chained `record()` / `verify()` via Mongo audit adapters. |
| `attestra/jobs/durable.py` | yes | Mongo-backed durable job queue (claim, cancel, heartbeat) for scan runs. |
| `attestra/compliance/` | yes | Control libraries, packs (incl. ISO 42001 / LLM Top-10), evaluate/recommend. |
| `attestra/reports/render.py` | yes | Technical / executive / compliance report render, hash and sign freeze. |
| `tests/` | yes | Pytest tree (~186 `test_*.py`); packages under `auth`, `automated_vapt`, `runner`, `persistence`, `security`, … |

### Mongo migrations (`MIGRATIONS`)

| Revision ID | Description |
|---|---|
| `0001_mongo_baseline` | Create collections, indexes, audit head |
| `0002_identity_webhooks` | Identity/webhook indexes; encrypt webhook secrets |
| `0003_credit_idempotency_partial` | Partial unique indexes for optional credit idempotency keys |
| `0004_upgrade_int_indexes` | Upgrade INT collections + indexes (api inventory, discovery, snapshots) |

**Next free number: `0005`** (append as e.g. `0005_<slug>` to `MIGRATIONS`; there are no migration files).

### Registered scanners (`registry._ADAPTERS`)

`checkov`, `dnsx`, `gitleaks`, `httpx_probe`, `kube_bench`, `naabu`, `nuclei`, `prowler`, `semgrep`, `subfinder`, `testssl`, `trivy`, `webcheck`, `zap` (14 adapters). Discovery adapters (`subfinder`, `dnsx`, `httpx_probe`) are candidates-only unless `ATTESTRA_DISCOVERY_ENABLED=1`.

### Importer parsers (`PARSERS`)

`burp`, `checkov`, `cyclonedx`, `dependency_track`, `dnsx`, `gitleaks`, `httpx_probe`, `kube_bench`, `naabu`, `nessus`, `nuclei`, `observatory`, `prowler`, `sarif`, `ssllabs`, `subfinder`, `testssl`, `trivy`, `webcheck`, `zap`.

`DISCOVERY_PARSERS`: `subfinder`, `dnsx`, `httpx_probe` (always return `[]` findings).

### Finding validation statuses

`unvalidated`, `confirmed`, `needs_manual_validation`, `potential`, `false_positive`, `informational`, `not_reproducible`, `accepted_risk`.

### Asset kinds (`ASSET_KINDS`)

`web_app`, `api`, `host`, `repo`, `image`, `cloud_account`, `mobile_app`.

**Gap for AASI:** no `ai_app` (or similar) kind today.

### Test types (`TEST_TYPES`)

`web_dast`, `api_dast`, `manual_pt`, `tls`, `network_va`, `sca_container`, `sast`, `iac_cloud`, `mobile`.

**Gap for AASI:** no `ai_llm` / `ai_agent` (or similar) test types today.

### Active persistence

**MongoDB only.** `db.py` documents that `session()` yields `MongoSession`; SQLAlchemy `Base` remains the schema map; there is no SQL engine. Confirmed by `lat.md/architecture#Architecture#MongoDB migration (in progress)`.

## Git baseline and `*.bak_*` inventory

Phase 0 track A hygiene. No bak files were deleted.

| Item | Value |
|---|---|
| Root | `E:/GitHub/attestra` |
| Branch | `attestra-asi-bundle` (required for AASI V4.0) |
| HEAD at Phase 0 start | `9bae08a` (*new changes*) |
| Working tree at Phase 0 start | Clean vs `origin/attestra-asi-bundle` |

### Bak counts

- **413** total `*.bak_*` files (**412** tracked; **1** under ignored `/data/`).
- **409/413** have a live source twin (historical editor backups of the same basename).
- Top suffixes: `.bak_mongofull` (82), `.bak_int` (28), `.bak_mongofull2` (20), `.bak_wp1` / `.bak_authzharmony` / `.bak_wp3` (16 each).
- By directory: `attestra/` 338 · `tests/` 63 · `deploy/` 4 · root 6 · `data/` 1.

### Ignore rules

- `.gitignore` already had `*.bak` (does **not** match `file.py.bak_mongofull`).
- Phase 0 added `*.bak_*` so **future** backup files stay untracked.
- Existing tracked bak files remain in the tree; archive/preserve only — deletion requires explicit authorization.
