# Attestra — Gap analysis (implementation guide)

**Date:** 2026-10-15  
**Spec:** [`docs/IMPLEMENTATION_GUIDE.md`](IMPLEMENTATION_GUIDE.md) (Phases 0–8)  
**Codebase:** `attestra` v1.0.0 (local working tree)  
**Validation (15 Oct 2026, local working tree):** `pytest -q` -> **478 passed, 26 skipped, 0 failed**; Postgres 16 RLS test (`tests/test_postgres_rls.py` with `ATTESTRA_TEST_POSTGRES_URL`) **7 passed**; `ruff check` clean  

This document supersedes the *status* of the older architecture-oriented [`GAP_ANALYSIS.md`](GAP_ANALYSIS.md) for **implementation progress**. Keep that file for historical comparison against the v2 architecture narrative; use **this file** for “what is done / what is pending” against the phased implementation guide.

---

## 1. Executive summary

| Band | Phases | Status |
| --- | --- | --- |
| **Done (local)** | 0 – Foundations | Complete |
| **Done (local)** | 1 – Runner plane | Complete (live scanner E2E optional / skipped without tools) |
| **Done (local)** | 2 – Identity, roles, tenancy | Complete (full Keycloak UI login still optional) |
| **Done (local)** | 3 – Compliance completeness | Complete (human QSA sign-off on library still pending) |
| **Done (local)** | 4 – Reports, letters, signing | Complete (WeasyPrint/DOCX rich path optional) |
| **Done (local)** | 5 – Evidence hardening | Complete (S3 live integration optional) |
| **Done (local)** | 6 – Production infrastructure | Complete in repo (Postgres 16 + RLS, Temporal optional, OPA, Keycloak/Vault, Docker/Helm, OTel/Prometheus, CI gate); live cluster deploy pending |
| **Done (local)** | 7 – Product polish & integrations | Complete (tickets off by default) |
| **Partial** | 8 – GA & external validation | 8.2-8.5 done locally; 8.1 external pentest and the release tag pending |

**Rough completion vs guide steps P0.1–P5.6:** ~**54 / 54** marked implemented in the traceability matrix (with residual VERIFY / process items noted below).  
**Guide steps P6–P8:** implemented locally except 8.1 (external pentest), the staging load-test run and the release tag. Improvements C4–C11 and four new features (trust center, findings library, proof/replay + webhooks, user management) are also done; see `CHANGELOG.md`.

**Next:** UI fixes from the screen audit, ISO 42001 framework pack, external pentest (8.1).

---

## 2. Scorecard by phase

| Phase | Theme | Guide steps | Done | Partial / residual | Pending |
| --- | --- | ---: | ---: | --- | --- |
| 0 | Foundations | 6 | 6 | CI not verified on GitHub Actions remote | — |
| 1 | Runner plane | 15 | 15 | Image digests are placeholders; live E2E skipped without tools | — |
| 2 | Identity / tenancy | 7 | 7 | OIDC claim validation present; full IdP PKCE UI when Keycloak ready | — |
| 3 | Compliance library | 10 | 10 | External QSA/ISO review recorded as *pending* in `REVIEW.md` | Human review |
| 4 | Reports & signing | 8 | 8 | WeasyPrint optional; OSCAL uses minimal structure schema not full NIST | — |
| 5 | Evidence hardening | 6 | 6 | S3 live MinIO integration optional | — |
| 6 | Production infra | 7 | 7 | Not yet deployed to a live cluster | — |
| 7 | Polish / integrations | 5 | 5 | Ticket sync off by default | — |
| 8 | GA / external | 5 | 4 | Staging load test, release tag | 8.1 external pentest |

---

## 3. What is done (Phases 0–5; Phases 6–8 are in section 5)

### Phase 0 — Foundations

| Item | Evidence |
| --- | --- |
| Pytest suite + fixtures | `tests/`, `tests/fixtures/` |
| Alembic | `alembic.ini`, `migrations/versions/0001_baseline.py` … `0005_*.py` |
| Ruff + CI workflow | `pyproject.toml` `[tool.ruff]`, `.github/workflows/ci.yml` |
| Security docs | `SECURITY.md`, `docs/THREAT_MODEL.md` |

### Phase 1 — Runner plane

| Item | Evidence |
| --- | --- |
| Scope / SSRF / DNS pin / safe HTTP | `attestra/runner/authorization.py`, `dns_pin.py`, `http_safe.py` |
| Scanner adapters + digests | `attestra/runner/scanners/*`, `SCANNER_IMAGES` |
| Gate, ScanRun, ScopeRule, Jobs | `gate.py`, models + mig `0002`, `attestra/jobs/*` |
| Kill switch, ownership | halt/resume, `ownership.py` |
| Scan API/UI + worker CLI | `api.py`, `web/ui.py`, `attestra worker` |

### Phase 2 — Identity, roles, tenancy

| Item | Evidence |
| --- | --- |
| Users, API keys, scrypt | `attestra/auth/keys.py`, models, mig `0003` |
| Six roles + `require(permission)` | `attestra/auth/roles.py`, `api.py` |
| Bearer / session (header actor removed) | `get_principal`, `/login`, CLI `--api-key` |
| Tenant scoping + storage prefixes | `services.scoped`, `_store(.../tenants/<id>/...)`, `migrate-storage` |
| Rate limit + security headers | `attestra/api_security.py` |
| OIDC behind flag | `attestra/auth/oidc.py`, optional `oidc` extra |

### Phase 3 — Compliance completeness

| Item | Evidence |
| --- | --- |
| Expanded PCI / ISO / SOC 2 library | `compliance/data/controls.yaml` |
| Mapping strength + rationale + integrity test | `cwe_map.yaml`, `tests/test_library_integrity.py` |
| Risk acceptance + expiry | `RiskAcceptance`, `expire-risk` CLI |
| ASV, segmentation, ScanSchedule, Nonconformity | models + services + UI/API |
| OWASP refs on findings | `compliance/owasp.py`, Finding columns |
| SoA / ageing reports | `iso_soa`, `ageing` templates |
| Library export + review stub | `compliance-export`, `compliance/data/REVIEW.md` |

### Phase 4 — Reports, letters, signing

| Item | Evidence |
| --- | --- |
| Submit → QA → sign (+ reject) | `submit_report`, `qa_approve`, `qa_reject`, `sign_report` |
| Retest false-close guard | `attestra/retest.py`, `Retest` model |
| Closure / attestation letters | `closure_letter`, `attestation_letter` kinds |
| DOCX / PDF export | `reports/export.py` (+ optional `docs` extra) |
| Ed25519 signing (HMAC fallback) | `reports/signing.py`, `cryptography` dependency |
| Framework packs | `reports/packs.py` |
| Executive trend SVG | `executive.html.j2` + `_context` |
| SARIF / CSV / OSCAL | `reports/sarif.py`, `oscal.py` |

### Migrations shipped

| Revision | Contents |
| --- | --- |
| `0001_baseline` | Core v0.1 schema |
| `0002_runner` | ScanRun, ScopeRule, Job, ownership columns |
| `0003_users` | User, ApiKey, TenantMembership, report user ids, tenant fields |
| `0004_compliance` | RiskAcceptance, ASV, segmentation, schedules, NC, OWASP cols |
| `0005_reports` | Retest, report workflow/QA/algorithm/export paths |
| `0006_evidence` | Evidence masking column, RetentionPolicy, report legal_hold, audit triggers |

### Phase 5 — Evidence hardening

| Item | Evidence |
| --- | --- |
| Masking at capture | `attestra/evidence/mask.py`; wired in `add_evidence` / import store |
| Storage Protocol | `attestra/storage/` local + optional S3 (`ATTESTRA_STORAGE`) |
| Retention + purge | `RetentionPolicy`, `attestra/ops/retention.py`, `attestra purge` |
| Append-only audit + export | SQLite triggers, download events, `GET /api/audit/export` |
| Backup/restore | `attestra/ops/backup.py`, `attestra backup` / `restore` |
| Feed refresh | `attestra enrich --refresh`, `ops/feeds.py`, catalog dates in reports |

---

## 4. Residuals inside “done” phases

These are implemented enough to mark the phase complete, but still have VERIFY / process follow-ups:

| Residual | Phase | Notes |
| --- | --- | --- |
| GitHub Actions green on remote | 0 | Workflow present; confirm after push |
| Scanner image digests | 1 | Placeholders — replace with real pinned digests before prod scans |
| Live scanner E2E | 1 | `@pytest.mark.integration` skipped without binaries |
| Full Keycloak login UI / PKCE | 2 | Flag + claim validation exist; wire UI when IdP is provisioned |
| Rotate `ATTESTRA_*` secrets | 2 | Dev defaults must change for shared deploy |
| QSA / ISO library sign-off | 3 | `REVIEW.md` reviewer fields still *pending* |
| WeasyPrint on Windows | 4 | Falls back to minimal PDF without GTK |
| Full NIST OSCAL JSON Schema | 4 | Minimal structural schema under `tests/schemas/` |
| Postgres RLS | 6 | Done (`rls.py`, migration `0007_postgres_rls`; policies for all tenant tables incl. 0011-0014); live test passes on local Postgres 16 |

---

## 5. Phases 6–8 status

### Phase 6 — Production infrastructure (done locally)

| Step | Requirement | Status |
| --- | --- | --- |
| 6.1 | PostgreSQL 16 default + RLS | **Done** - `attestra/rls.py`, migration `0007_postgres_rls`, `tests/test_postgres_rls.py` (live test passes on Postgres 16) |
| 6.2 | Temporal workflows | **Done locally (optional, ATTESTRA_ORCHESTRATOR=temporal; scan step only) - see docs/TEMPORAL.md** |
| 6.3 | OPA/Rego scope policy | **Done** - `policy/scope.rego` + `scope_test.rego`, `tests/runner/test_opa_policy.py` |
| 6.4 | Keycloak MFA default + Vault/OpenBao keys | **Done** - `deploy/keycloak/attestra-realm.example.json`, `attestra/secret_store.py`, `docs/IDENTITY_AND_SECRETS.md` |
| 6.5 | Dockerfile + Helm + NetworkPolicy | **Done** - `Dockerfile`, `deploy/helm/attestra/`, `deploy/k8s/` (default deny + scanner egress) |
| 6.6 | OpenTelemetry / Prometheus / Grafana | **Done** - `attestra/observability.py`, `deploy/observability/`, `tests/test_observability.py` |
| 6.7 | CI/CD import gates + scheduler UI polish | **Done** - `integrations/ci/` (GitHub/GitLab gate), `tests/test_phase6_ci_schedules.py` |

### Phase 7 — Product polish and integrations

| Step | Requirement | Status |
| --- | --- | --- |
| 7.1 | Client portal / auditor read-only views | **Done** - `/portal`, `/portal/engagements/{id}` (client_viewer: triaged findings + signed reports only), `/auditor/engagements/{id}` (audit trail, chain verify, report versions); UI POSTs refused for read-only roles (`attestra/web/portal.py`, `tests/test_phase7_portal_tickets.py`) |
| 7.2 | Jira/GitHub ticket sync + CycloneDX/SBOM importers | **Done (off by default)** - `attestra/integrations/{tickets,jira,github,routes}.py`: `POST /api/findings/{id}/ticket`, HMAC-signed status webhook `POST /api/integrations/tickets/{jira,github}/webhook` (back-sync only along allowed transitions); enable with `ATTESTRA_TICKETS_BACKEND` + `ATTESTRA_TICKETS_WEBHOOK_SECRET`. Importers `cyclonedx`, `dependency_track` |
| 7.3 | More scanner adapters (Prowler, kube-bench, etc.) | **Done** - adapters + importers for Prowler, kube-bench, testssl.sh, Gitleaks, Checkov, naabu; OpenVAS/MobSF only as opt-in HTTP services (off by default) |
| 7.4 | Per-tenant risk weights, suppressions | **Done** - tenant weights, expiring audited suppression rules, false-positive rate per tool at `/tuning/false-positives` (linked from the dashboard) |
| 7.5 | Legal pack + `docs/LICENSES.md` | **Done** - `docs/legal/` RoE + authorization templates, `docs/LICENSES.md` |

### Phase 8 — GA and external validation

| Step | Requirement | Status |
| --- | --- | --- |
| 8.1 | Third-party pentest of Attestra | **Blocked** (external) - scope ready in `docs/PENTEST_SCOPE.md`; needs an external tester |
| 8.2 | Load test (locust/k6) on staging | **Done locally** - k6 script `deploy/loadtest/attestra.js`, results in `docs/LOAD_TEST.md` (local Postgres 16, 10 VUs, p95 220 ms, 0% errors); **staging run pending** |
| 8.3 | GA release / tag / CHANGELOG | **Ready** - version 1.0.0, `CHANGELOG.md`, `docs/RELEASE.md`; **tag pending** (done by the owner) |
| 8.4 | v2.1 framework packs (CERT-In, RBI, SEBI CSCRF, DORA, NIST CSF 2.0) as YAML in `compliance/data/packs/` | **Done** |
| 8.5 | AI narratives (explicitly optional / default skip) | **Done** (optional, off by default; `ATTESTRA_AI_NARRATIVES=on` to enable, tester approval required) |

---

## 6. Security posture (current vs remaining)

| Concern | Then (pre Phase 2) | Now | Still open |
| --- | --- | --- | --- |
| Identity spoofing via free-text actor | Open | Mitigated (Bearer/session + user-id four-eyes) | Enable OIDC + rotate secrets for shared deploy |
| Out-of-scope / SSRF scanning | Open (no runner) | Mitigated in runner gate + SSRF/DNS pin; egress NetworkPolicy shipped in `deploy/k8s/` | Apply in a live cluster |
| Cross-tenant leaks | Open | Mitigated in app (`scoped`, tenant storage) + Postgres RLS | Run on Postgres in production (SQLite has no RLS) |
| Evidence secrets in artifacts | Open | Mitigated (mask at capture) | Tune corpus / content-types as needed |
| Audit tampering | Partial (hash chain) | Mitigated (append-only triggers + download events + export) | Postgres revoke UPDATE/DELETE in deploy |
| Report signatures | HMAC-only | Ed25519 + HMAC fallback | Customer runbook for pub key verify |
| Backup integrity | Missing | Mitigated (manifest backup/restore) | Offline restore drills in ops |

---

## 7. Recommended sequence from here

1. Fix the issues from the UI screen audit.  
2. Add the ISO 42001 framework pack and its verification steps.  
3. Deploy to a staging cluster; run the k6 load test there.  
4. External pentest (8.1), then tag the release.

---

## 8. Traceability

| Document | Role |
| --- | --- |
| [`IMPLEMENTATION_GUIDE.md`](IMPLEMENTATION_GUIDE.md) | Authoritative phased steps |
| [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) | Per-step ID matrix (P0.1 … P8.*) |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Threats and mitigations |
| [`PHASES.md`](PHASES.md) / [`ROADMAP.md`](ROADMAP.md) | High-level roadmap |
| [`GAP_ANALYSIS.md`](GAP_ANALYSIS.md) | Older % scorecard vs architecture v2 (stale for runner/identity) |
| **This file** | Current done vs pending snapshot (Phases 0–8, improvements, new features) |

---

## 9. One-line verdict

**Phases 0–7 are implemented and test-green locally, Phase 8 is done except the external pentest and release tag, and the four new features (trust center, findings library, proof/replay + webhooks, user management) are in place and tested.**
