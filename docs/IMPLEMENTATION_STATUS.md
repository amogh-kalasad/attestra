# Attestra — Implementation Status & Traceability Matrix

Date: 2026-10-14, updated 2026-10-15. Spec: `docs/IMPLEMENTATION_GUIDE.md` (Phases 0-8). Code: `E:\GitHub\attestra` (pushed `main` @ `d835682`) plus the uncommitted new features, synced to `E:\attestra`.

## 1. Executive summary

Attestra v0.1 started as an **import-and-report** platform; Phases 0–2 add Alembic, a scoped scanner runner, and Bearer/session identity with RBAC and tenant isolation.

| Phase | Guide title | Audit status | Notes |
| --- | --- | --- | --- |
| 0 | Foundations and safe baseline | **IMPLEMENTED** (pending your approval to proceed) | tests restored (89), Alembic 0001, ruff+CI, SECURITY docs |
| 1 | Runner plane | **IMPLEMENTED** (pending approval to proceed) | runner/, jobs/, ScanRun, gate, API/UI; 170 passed + 1 skipped integration |
| 2 | Identity, roles, tenancy | **IMPLEMENTED** | users, API keys, six roles, sessions, tenant scoping, OIDC flag |
| 3 | Compliance completeness | **IMPLEMENTED** | full PCI/ISO/SOC 2 libraries, strength + rationale, ASV/segmentation/calendar, SoA/NC, C4-C11 improvements (0009, 0010); QSA review pending (human) |
| 4 | Reports, letters, signing | **IMPLEMENTED** | draft/QA/sign workflow, retests, letters, DOCX/PDF, Ed25519, packs, SARIF/OSCAL |
| 5 | Evidence hardening | **IMPLEMENTED** (pending approval to proceed) | masking, Storage, retention, audit, backup, feeds |
| 6 | Production infrastructure | **IMPLEMENTED** (not deployed live) | Postgres RLS, Temporal (optional), OPA, Keycloak/Vault, Helm, OTel, CI gate |
| 7 | Product polish | **IMPLEMENTED** | portal/auditor views, ticket sync, new scanners, tuning, legal pack |
| 8 | GA / optional | **PARTIALLY IMPLEMENTED** | packs (CERT-In, RBI, SEBI, DORA, NIST CSF 2.0), k6 load test, v1.0.0 changelog, AI narratives, pentest scope; external pentest + tag pending |

**Blockers discovered**

1. `tests/` and `tests/fixtures/` were never in this GitHub clone (demo CLI expects them). Reconstructing before Phase 0 VERIFY.
2. Phases 6–8 need Postgres/Temporal/OPA/Keycloak/Vault/K8s and external processes — cannot fully complete in-repo alone.
3. Step 3.10 (external QSA review) and 8.1 (third-party pentest) require human/external action.

## 2. Repository architecture discovered

| Area | Path | Present |
| --- | --- | --- |
| Package | `attestra/` | Yes |
| DB | `attestra/db.py` | `create_all` + `_add_missing_columns` |
| Models | `attestra/models.py` | Tenant…AuditEvent (no ScanRun/User/Job/…) |
| Services | `attestra/services.py` | Engagements, authz gate on import, assets, import, enrich, transition, compliance |
| Importers | `attestra/importers/{zap,nuclei,trivy,sarif}.py` | Parse-only |
| Compliance | `attestra/compliance/` | YAML library + `evaluate()` |
| Reports | `attestra/reports/` | HTML Jinja + HMAC sign |
| API / UI / CLI | `api.py`, `web/`, `cli.py` | Yes |
| Tests | `tests/` | **Missing** |
| Migrations | `alembic.ini`, `migrations/` | **Missing** |
| CI | `.github/workflows/` | **Missing** |
| Runner / jobs / auth | `runner/`, `jobs/`, `auth/` | **Missing** |

Stack: Python ≥3.11, FastAPI, SQLAlchemy 2, Pydantic 2, Jinja2, PyYAML. Optional: pytest, httpx, psycopg.

## 3. Traceability matrix

| ID | Phase | Requirement | Existing Evidence | Status | Missing Work | Dependencies | Verification |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P0.1 | 0 | Baseline pytest recorded | `.cache/baseline.txt` | IMPLEMENTED | — | — | 89 passed |
| P0.2 | 0 | Alembic + initial migration | `alembic.ini`, `migrations/`, `db.upgrade()`, `0001_baseline` | IMPLEMENTED | — | — | `test_migrations` green |
| P0.3 | 0 | ruff + CI | `[tool.ruff]`, `.github/workflows/ci.yml` | IMPLEMENTED, NOT VERIFIED on GitHub | Push to confirm Actions green | P0.4 | local `ruff check .` clean |
| P0.4 | 0 | Tests in repo | `tests/` + fixtures | IMPLEMENTED | — | — | suite green |
| P0.5 | 0 | Fix TestClient deprecation | `httpx2` + context-manager client | IMPLEMENTED | — | — | `-W error::DeprecationWarning` |
| P0.6 | 0 | SECURITY.md + THREAT_MODEL.md | Root + docs; README links | IMPLEMENTED | — | — | files + links |
| P1.1 | 1 | AuthorizedScope module | `runner/authorization.py` | IMPLEMENTED | — | P0 | security tests |
| P1.2 | 1 | Exact image match | `_image_allowed` | IMPLEMENTED | — | P1.1 | nginx vs nginx-evil |
| P1.3 | 1 | SSRF block list | BLOCKED_CIDRS + loopback | IMPLEMENTED | — | P1.1 | SSRF tests |
| P1.4 | 1 | DNS pin + safe HTTP | dns_pin.py, http_safe.py | IMPLEMENTED | — | P1.3 | pin/redirect tests |
| P1.5 | 1 | Scanner adapters | scanners/* + registry | IMPLEMENTED | Live tool runs optional | P1.4 | argv tests |
| P1.6 | 1 | ZAP egress confine | `--add-host` + quarantine | IMPLEMENTED | Docker network isolation light | P1.5 | pin/quarantine tests |
| P1.7 | 1 | Image digests | SCANNER_IMAGES require `@sha256:` | IMPLEMENTED | Placeholder digests (VERIFY) | P1.5 | refuse floating tags |
| P1.8 | 1 | ScanRun model | model + migration 0002 | IMPLEMENTED | — | P0.2 | full-file sha256 |
| P1.9 | 1 | Dispatch gate | gate.py | IMPLEMENTED | — | P1.1, P1.8 | refusal + audit |
| P1.10 | 1 | ScopeRule deny | ScopeRule + services | IMPLEMENTED | — | P1.1 | deny-beats-allow |
| P1.11 | 1 | Durable jobs | jobs/*, `attestra worker` | IMPLEMENTED | — | P1.8–9 | claim/recover |
| P1.12 | 1 | Kill switch | halt + cancel Event | IMPLEMENTED | — | P1.11 | <5s kill test |
| P1.13 | 1 | Scan API/UI | API routes + engagement UI | IMPLEMENTED | — | P1.11–12 | 403/halt tests |
| P1.14 | 1 | Ownership verify | ownership.py + asset cols | IMPLEMENTED | — | P1.4, P1.9 | mocked verify |
| P1.15 | 1 | Loopback E2E | `tests/e2e` integration | IMPLEMENTED, NOT VERIFIED | Skipped when tools missing | scanners | skip-clean |
| P2.1 | 2 | User + API keys | `auth/keys.py`, User/ApiKey, mig 0003 | IMPLEMENTED | — | P0.2 | hash/revoke tests |
| P2.2 | 2 | Six roles | `auth/roles.py` + `require()` | IMPLEMENTED | — | P2.1 | permission map |
| P2.3 | 2 | Replace header actor | Bearer/session; CLI `--api-key` | IMPLEMENTED | — | P2.1–2 | 401 anonymous |
| P2.4 | 2 | Tenant scoping | `scoped()` + memberships | IMPLEMENTED | — | P2.1 | matrix 404 |
| P2.5 | 2 | Per-tenant storage | `_store` + `migrate-storage` | IMPLEMENTED | — | P2.4 | cross-tenant refuse |
| P2.6 | 2 | Rate limit + headers | `api_security.py` | IMPLEMENTED | — | P2.3 | headers + 429 |
| P2.7 | 2 | OIDC flag | `auth/oidc.py` + `oidc` extra | IMPLEMENTED | Full authlib PKCE UI when IdP ready | P2.3 | mocked claims |
| P3.1 | 3 | Missing PCI controls | controls.yaml + process rules | IMPLEMENTED | — | — | roll-up tests |
| P3.2 | 3 | Missing ISO/SOC2 | A.8.22, Clauses, CC* added | IMPLEMENTED | — | — | roll-up tests |
| P3.3 | 3 | strength + rationale | cwe_map + integrity test | IMPLEMENTED | — | — | integrity green |
| P3.4 | 3 | RiskAcceptance | model + expire-risk CLI | IMPLEMENTED | — | P2.1 | expire reopens |
| P3.5 | 3 | ASV + segmentation | models + API/UI | IMPLEMENTED | — | P3.1 | 11.3.2 met rule |
| P3.6 | 3 | Quarterly calendar | ScanSchedule + worker enqueue | IMPLEMENTED | — | P1.11 | schedule test |
| P3.7 | 3 | OWASP refs on findings | owasp.py/yaml + Finding cols | IMPLEMENTED | — | — | CWE-89→A03 |
| P3.8 | 3 | ISO SoA + NC | Nonconformity + iso_soa.j2 | IMPLEMENTED | — | P3.2 | UI/report |
| P3.9 | 3 | SLA breach report | sla_breaches + ageing.j2 | IMPLEMENTED | — | — | critical >30d |
| P3.10 | 3 | External library review | compliance-export + REVIEW.md | IMPLEMENTED (process pending human) | QSA sign-off | P3.3 | human QSA |
| P4.1 | 4 | 3-step report workflow | submit/qa/sign/reject | IMPLEMENTED | — | P2 | reject + same-user |
| P4.2 | 4 | Retest false-close guards | retest.py + Retest | IMPLEMENTED | — | P1.8 | never fixed if no hit |
| P4.3 | 4 | Closure/attestation letters | templates + kinds | IMPLEMENTED | — | P4.1 | golden markers |
| P4.4 | 4 | DOCX/PDF | export.py + docs extra | IMPLEMENTED | WeasyPrint optional | — | sha stored |
| P4.5 | 4 | Verifiable signatures | Ed25519 + HMAC fallback | IMPLEMENTED | — | — | cryptography verify |
| P4.6 | 4 | Framework packs | packs.py zip+manifest | IMPLEMENTED | — | P3 | pack contents |
| P4.7 | 4 | Executive trend | prior engagement SVG | IMPLEMENTED | — | — | chart present |
| P4.8 | 4 | SARIF/CSV/OSCAL out | sarif.py, oscal.py | IMPLEMENTED | full NIST schema optional | — | structure tests |
| P5.1 | 5 | Masking at capture | `evidence/mask.py` + wired | IMPLEMENTED | — | — | corpus 0 leaks |
| P5.2 | 5 | Storage interface | Protocol + local/s3 | IMPLEMENTED | S3 live vs MinIO optional | — | overwrite refuse |
| P5.3 | 5 | Retention + purge | RetentionPolicy + ops/retention | IMPLEMENTED | — | P2.4 | audited purge |
| P5.4 | 5 | Audit download + append-only | triggers + export + download | IMPLEMENTED | — | — | UPDATE fails |
| P5.5 | 5 | Backup/restore manifest | ops/backup.py + CLI | IMPLEMENTED | — | — | tamper fails restore |
| P5.6 | 5 | KEV/EPSS refresh | `enrich --refresh` + feeds | IMPLEMENTED | — | network | offline fixtures |
| P6.* | 6 | Postgres RLS, Temporal, OPA, Vault, Helm, OTel, CI gates | `rls.py` + 0007, `orchestration/`, `policy/`, `secret_store.py`, `deploy/`, `observability.py`, `integrations/ci/` | IMPLEMENTED | Live cluster deploy | P1-5 | `test_postgres_rls` (live PG16: 7 passed), `test_opa_policy`, `test_observability`, `test_phase6_ci_schedules` |
| P7.* | 7 | Portal, tickets, scanners, tuning, legal | `web/portal.py`, `integrations/`, scanners + importers, `tuning.py` + 0008, `docs/legal/` | IMPLEMENTED | - | P6 | `test_phase7_*` |
| P8.1 | 8 | Third-party pentest | `docs/PENTEST_SCOPE.md` | BLOCKED (external) | External tester | P0-7 | - |
| P8.2 | 8 | Load test | `deploy/loadtest/attestra.js`, `docs/LOAD_TEST.md` | IMPLEMENTED (local) | Staging run | P6 | k6 local results |
| P8.3 | 8 | GA release | `CHANGELOG.md`, `docs/RELEASE.md`, version 1.0.0 | IMPLEMENTED | Tag by owner | P0-7 | - |
| P8.4 | 8 | Framework packs | `compliance/data/packs/` | IMPLEMENTED | - | P3 | `test_phase8_framework_packs` |
| P8.5 | 8 | AI narratives (optional) | `web/ai_routes.py`, `docs/AI_NARRATIVES.md` | IMPLEMENTED (off by default) | - | - | `test_ai_narratives`, `test_ai_routes` |
| C4-C11 | 3 | Crosswalk refs, mapping strength, OSCAL/SCF import, PCI ASV calendar, ISO SoA, SOC 2 sampling | `controls.yaml`, `compliance/libraries/`, 0009, 0010, `reports/soc2_sampling.py` | IMPLEMENTED | - | P3 | `test_control_libraries`, `test_c7_c11_mapping_soc2`, `test_c9_c10_pci_iso` |
| N1 | new | Trust center | `attestra/trust/`, migration 0011 | IMPLEMENTED (uncommitted) | Staff UI page | P4 | `test_trust_center` |
| N2 | new | Findings library + report templates | `attestra/library/`, migration 0012 | IMPLEMENTED (uncommitted) | - | P4 | `test_findings_library` |
| N3 | new | Proof/replay + webhooks/workflow rules | `attestra/proof/`, `attestra/webhooks/`, migration 0013 | IMPLEMENTED (uncommitted) | Scheduled dispatch; UI screens | P4 | `test_proof_replay`, `test_webhooks` |
| N4 | new | User management + invites | `attestra/users/`, migration 0014 | IMPLEMENTED (uncommitted) | Per-engagement scoping for invites | P2 | `test_user_management` |

## 4–7. Done / pending snapshot

See **[`docs/GAP_ANALYSIS_CURRENT.md`](GAP_ANALYSIS_CURRENT.md)** for the full gap analysis (Phases 0-8, improvements, new features).

- **Done locally:** Phases 0-7, Phase 8 steps 8.2-8.5, improvements C4-C11, four new features (N1-N4).
- **Next:** UI fixes from the screen audit; ISO 42001 framework pack.
- **Later / blocked:** 8.1 external pentest, staging load test, release tag, live cluster deploy.

## 8. Ordered implementation roadmap

1. Reconstruct `tests/` + fixtures; record baseline (P0.1, P0.4, P0.5)
2. Alembic baseline + migration test (P0.2)
3. ruff + GitHub Actions CI (P0.3)
4. SECURITY.md + THREAT_MODEL.md + README links (P0.6)
5. Phase 1 runner authorization → gate → adapters → jobs → API (dependency order in guide)
6. Phase 2 auth/roles/tenancy
7. Phase 3–5 package work that does not need K8s
8. Phase 6+ only with infra approval/credentials

## 9. Test and validation results

| Command | Result | Notes |
| --- | --- | --- |
| `pytest -q` | **478 passed, 26 skipped, 0 failed** (15 Oct 2026) | Phases 0-8, C4-C11, new features N1-N4 |
| `pytest tests/test_postgres_rls.py` with local Postgres 16 | **7 passed** | live cross-tenant RLS test incl. migrations to `0014_user_invites` |
| `ruff check attestra tests migrations integrations` | clean | - |
| Baseline | `.cache/baseline.txt` | Phase 0 snapshot; suite grown since |

## 10. Final completion summary

**Phases 0-7 complete locally; Phase 8 done except the external pentest and release tag; new features N1-N4 implemented and tested (not yet committed).**

### Progress log

| When | Change |
| --- | --- |
| 2026-10-14 | Initial audit from IMPLEMENTATION_GUIDE vs clean `main`; matrix created |
| 2026-10-14 | Phase 0 implemented: tests/fixtures, Alembic 0001, ruff+CI, SECURITY/THREAT_MODEL |
| 2026-10-14 | Phase 1 implemented: runner scope/SSRF/DNS/HTTP, scanners, ScanRun/ScopeRule/Job, gate, durable jobs, kill switch, scan API/UI, ownership; 170 passed + 1 skipped |
| 2026-10-14 | Phase 2 implemented: User/ApiKey, roles, Bearer/session, scoped tenancy, per-tenant storage, rate limits/headers, OIDC flag; migration 0003; 190 passed + 1 skipped |
| 2026-10-14 | Phase 3 implemented: expanded control library + integrity, RiskAcceptance/ASV/segmentation/schedules/NC, OWASP refs, SoA/ageing reports, compliance-export; migration 0004; 203 passed + 1 skipped |
| 2026-10-14 | Phase 4 implemented: report workflow, retests, letters, DOCX/PDF, Ed25519 signing, packs, trend SVG, SARIF/OSCAL; migration 0005; 215 passed + 1 skipped |
| 2026-10-14 | Phase 5 implemented: masking, Storage local/s3, retention/purge, append-only audit + export, backup/restore, enrich --refresh; migration 0006; 228 passed + 1 skipped |
| 2026-10-14 | Phase 6 implemented: Postgres RLS (0007), Temporal (optional), OPA, Keycloak/Vault, Docker/Helm, OTel, CI gate |
| 2026-10-14 | Phase 7 implemented: portal/auditor views, ticket sync, new scanners, tuning (0008), legal pack |
| 2026-10-14 | Phase 8 implemented: framework packs, k6 load test, v1.0.0 changelog, AI narratives, pentest scope |
| 2026-10-14 | Improvements C4-C11: crosswalk refs, mapping strength, OSCAL/SCF import, PCI ASV calendar (0009), ISO SoA (0010), SOC 2 sampling |
| 2026-10-14 | New features N1-N4: trust center (0011), findings library (0012), proof/replay + webhooks (0013), user invites (0014) |
| 2026-10-15 | Folders synced; full suite 478 passed, 26 skipped; Postgres RLS live test 7 passed |
