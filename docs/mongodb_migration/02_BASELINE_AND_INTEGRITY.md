# Baseline and integrity

Source preservation, environment baseline, and integrity measurements captured **before** MongoDB persistence code changes. Live customer cutover is **not** authorized by this document.

---

## Git and working tree

| Field | Value |
|---|---|
| Commit | `6718536d2c5f76a8fdb302f2706603fafc3e32fd` (`6718536 quick changes:aj`) |
| Starting branch | `main` (tracking `origin/main`) |
| Migration branch | `mongodb-migration` (created for this work) |
| Uncommitted at start | `D .env.example` only (deleted in working tree) |
| Existing stashes | present (`stash@{0}`, `stash@{1}`) — left untouched |
| Policy | Do not delete/overwrite `data/attestra.db`; do not regenerate signing keys for historical verification |

---

## Source backup (validated copy)

| Field | Value |
|---|---|
| Backup dir | `.migration_backups/pre_mongo_20261103_170857/` |
| DB copy | `attestra.db` (1,679,360 bytes) |
| SHA-256 | `EAEE671F67B88F574D10E0174B66E3FE8221313213D4F06AF31A77C706174FDD` |
| Keys copied | `keys/signing.pub`, `keys/signing_ed25519.pem` |
| Note | Evidence/report trees were empty; scanner-cache intentionally **not** copied (non-authoritative, large) |

Restore check: file hashes recorded above; application `attestra backup` remains available for fuller SQLite+DATA_DIR manifests when needed.

---

## Dependency and entry-point baseline

| Item | Verified |
|---|---|
| Python package | `attestra` 1.0.0 (`pyproject.toml`) |
| Requires | Python ≥3.11 |
| Core deps | FastAPI 0.143.0, SQLAlchemy 2.1.4, Alembic 1.20.0 (venv) |
| Mongo driver | **not** installed |
| Entry points | CLI `attestra = attestra.cli:main`; `serve`, `worker`, `init`, backup/restore, verify-*, scan/import/report workflow commands (Blueprint CLI table) |
| App factory | `attestra.api:app` |
| Test files | 102 `test_*.py` under `tests/` |
| Routes (flattened APIRoute) | **287** (Blueprint claimed 291) |

---

## Runtime database baseline

| Field | Value |
|---|---|
| `DATABASE_URL` | `sqlite:///D:\VAPT attestra\attestra\data\attestra.db` |
| Alembic revision | `0036_tenant_ownership_hosts` |
| Physical tables | 56 (55 domain + `alembic_version`) |

### Row counts (2026-11-03 probe)

| Table | Count | Table | Count |
|---|---:|---|---:|
| alembic_version | 1 | api_keys | 6 |
| assets | 0 | asv_scan_items | 0 |
| asv_scans | 0 | audit_events | **781** |
| audit_samples | 0 | auth_checklist_items | 0 |
| auth_credential_profiles | 0 | auth_element_inventory | 0 |
| auth_route_inventory | 0 | authorizations | 0 |
| automated_test_executions | 0 | cert_expiry_alerts | 0 |
| certification_authority | 0 | control_assessments | 0 |
| credit_renewal_requests | 0 | credit_transactions | 10 |
| email_alert_sent | 0 | email_alert_settings | 0 |
| engagements | 0 | evidence | 0 |
| finding_assignments | 0 | finding_comments | 0 |
| finding_observations | 0 | findings | 0 |
| import_runs | 0 | jobs | 0 |
| library_entries | 0 | nonconformities | 0 |
| proof_replays | 0 | report_templates | 0 |
| reports | 0 | retention_policies | 0 |
| retests | 0 | risk_acceptances | 0 |
| scan_runs | 0 | scan_schedules | 0 |
| scope_rules | 0 | segmentation_tests | 0 |
| share_links | 0 | soa_entries | 0 |
| suppression_rules | 0 | tenant_credit_accounts | 6 |
| tenant_memberships | 0 | tenant_ownership_hosts | 4 |
| tenant_risk_weights | 0 | tenants | **9** |
| trust_access_requests | 0 | trust_centers | 0 |
| trust_items | 0 | user_invites | 0 |
| users | **4** | webhook_deliveries | 0 |
| webhook_endpoints | 0 | workflow_rules | 0 |

**Interpretation:** this checkout DB is a **dev/admin skeleton** (tenants, users, keys, credits, ownership hosts, dense audit log) without engagement/finding/report artifact history. Migration tooling must still support full populated schemas; do not treat empty tables as “nothing to migrate.”

### Credit balances

| tenant_id | balance | grant_total |
|---:|---:|---:|
| 4 | 3 | 3 |
| 5 | 0 | 3 |
| 6 | 3 | 3 |
| 7 | 3 | 3 |
| 8 | 2 | 3 |
| 9 | 3 | 3 |

Ledger rows: 10 `credit_transactions`. Post-migration reconciliation must match these balances.

---

## Artifact directory baseline

| Path under `data/` | Files | Size | Class |
|---|---:|---:|---|
| raw/ | 0 | 0 | B (empty) |
| tenants/ | 0 | 0 | B (empty) |
| evidence/, imports/, reports/, feeds/, packs/ | 0 | 0 | B (empty) |
| keys/ | 2 | 163 B | C (signing) |
| scanner-cache/ | 14437 | ~47 MB | D (do not treat as evidence) |
| attestra.db | 1 | 1.68 MB | A |

No signed report HTML present → signature verification baseline for **historical reports** is N/A on this DB; signing **keys** preserved for future signatures and any later restored artifacts.

---

## Audit chain integrity (pre-existing failure)

Command path: `attestra.audit.verify` via `db.session()`.

| Result | Value |
|---|---|
| `ok` | **False** |
| `first_bad_event_id` | **532** |
| Total events | 781 |

**Mandatory rule:** record and migrate events 1…781 with original `id`, `prev_hash`, `hash`, timestamps, actors, and details. Do **not** rewrite, reorder, or “fix” the chain. Mongo append implementation must serialize new events; historical break remains visible to `verify-audit`.

This matches Blueprint §5.14 (“BROKEN at event 532”).

---

## Automated test baseline

| Item | Status |
|---|---|
| Suite location | `tests/` present (102 files) |
| Full pytest run this phase | **Not executed end-to-end in this gate** (time/env); Phase 10 will capture full matrix |
| Known historical failures (Blueprint / docs) | Postgres RLS test expectations around `automated_test_executions`; treat as investigate-on-run, not as current proof |
| Acceptance rule | Separate pre-existing failures vs migration regressions when tests are run |

OpenAPI / CLI snapshot: route count 287 recorded; CLI command list taken from Blueprint §1.3 (argparse tree) as baseline contract.

---

## Missing inputs (explicit)

| Input | Status |
|---|---|
| Production PostgreSQL dump | Not in checkout |
| Populated engagement evidence/reports | Absent locally |
| Complete prior pytest JUnit artifact | Not present |
| MongoDB replica set | Not provisioned yet (needed from Phase 2 infra onward) |
| `LAT_LLM_KEY` for `lat search` | May be unset; `lat locate` used |

Never invent migration success or test pass counts.

---

## Acceptance criteria for later phases (frozen here)

1. All 55 entities representable in Mongo with original integer IDs.
2. Row counts and credit balances for any migrated source DB match after import.
3. Artifact bytes SHA-256 equal for every migrated blob.
4. Audit events byte-identical in chain fields; verify still reports break at 532 if source had it.
5. Signing keys unchanged; any restored signed report still verifies.
6. API/CLI/UI contracts unchanged unless explicitly documented.
7. No production cutover without separate authorization.

---

## Gate status

**PHASE 1 GATE: COMPLETE** for this checkout — source DB/keys backed up, baseline counts and pre-existing audit failure documented, migration branch established. No live data migration performed.
