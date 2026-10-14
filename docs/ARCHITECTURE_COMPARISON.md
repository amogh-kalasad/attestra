# Attestra: target architecture vs v1.0.0

**Date:** 2026-10-14
**Sources:** `docs/GAP_ANALYSIS.md`, `docs/GAP_ANALYSIS_CURRENT.md`, `docs/PHASES.md`, `CHANGELOG.md`, and the code in this repo. Every file path below was checked and exists.

## Summary

- Attestra started as v0.1.0, an import-and-report tool that never ran scanners. `GAP_ANALYSIS.md` scored it at 31% of the target architecture (v2: PCI DSS, ISO 27001, SOC 2).
- v1.0.0 covers Phases 0 to 7 of `docs/PHASES.md` plus most of Phase 8: a gated runner plane, real identity and roles, tenant isolation (app scoping plus Postgres RLS), complete PCI/ISO/SOC 2 libraries, five extra framework packs, a three-step signed report workflow, evidence hardening, Temporal/OPA/Vault/Helm/observability, a portal and integrations, and optional AI narratives.
- All improvement items C1 to C11 are done. The list ends at C11.
- Still open: the external pentest, a staging load test, and the release tag, which the owner creates himself. Some areas also have optional or residual follow-ups, listed in the Notes column.
- Note: section 5 of `GAP_ANALYSIS_CURRENT.md` still lists Phase 6 steps as pending. The code and `CHANGELOG.md` show them as implemented, so that file is out of date on this point.

Status legend: **Done**, **Done (optional)** = built but off by default, **Partial**, **Pending**.

## 1. Engagements, scope and authorization

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| Signed authorization required before any scan or import | Done | `attestra/services.py`, `attestra/runner/authorization.py` | |
| Scope allow and deny rules, test window, intrusive flag, rate limit | Done | `attestra/runner/gate.py`, `attestra/models.py` (ScopeRule), `migrations/versions/0002_runner_scan_scope_jobs.py` | |
| OPA/Rego scope policy | Done | `policy/scope.rego`, `policy/scope_test.rego`, `attestra/runner/policy.py` | |
| Target ownership verification | Done | `attestra/runner/ownership.py` | |
| Kill switch (halt/resume) | Done | `attestra/api.py`, `attestra/jobs/` | |
| Legal pack (RoE, authorization templates) | Done | `docs/legal/`, `docs/LICENSES.md` | |

## 2. Scanners and runners

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| Platform runs scanners itself | Done | `attestra/runner/scanners/` (zap, nuclei, trivy, semgrep, prowler, kube_bench, testssl, gitleaks, checkov, naabu), `registry.py` | v0.1 was import-only |
| SSRF block list, DNS pinning, safe HTTP | Done | `attestra/runner/dns_pin.py`, `attestra/runner/http_safe.py` | |
| Image digest pinning | Partial | `attestra/runner/scanners/` | Digests are placeholders; set real digests before production scans |
| GPL/AGPL tools (OpenVAS, MobSF) as separate services | Done (optional) | `attestra/runner/scanners/http_service.py` | Off by default |
| Kubernetes Jobs with NetworkPolicy | Done | `deploy/helm/attestra/templates/scanner-job.yaml`, `scanner-networkpolicy.yaml`, `deploy/k8s/` | Go on-prem runner agent not built (the plan says "later") |
| Scheduled scans and CI/CD gates | Done | `attestra/models.py` (ScanSchedule), `integrations/ci/github/attestra-gate.yml`, `integrations/ci/gitlab/attestra-gate.gitlab-ci.yml`, `integrations/ci/attestra_ci.py` | |
| Live scanner end-to-end tests | Partial | `tests/` (integration marker) | Skipped when the scanner binaries are not installed |

## 3. Findings normalization, dedup and risk

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| Common finding schema | Done | `attestra/importers/base.py`, `attestra/models.py` | |
| Fingerprint dedup | Done | `attestra/fingerprint.py` | |
| Risk score formula, EPSS/KEV | Done | `attestra/scoring.py`, `attestra/ops/feeds.py` | `attestra enrich --refresh`; catalog date shown in reports |
| OWASP Top 10 / ASVS / WSTG refs | Done | `attestra/compliance/owasp.py`, `attestra/compliance/data/owasp.yaml` | |
| Importers incl. SBOM | Done | `attestra/importers/` (cyclonedx, dependency_track, sarif, asv, ...) | |
| Per-tenant weights, suppressions, FP rate per tool | Done | `attestra/tuning.py`, `migrations/versions/0008_tuning.py`, `attestra/web/templates/tuning_fp.html` | |

## 4. Tester review and lifecycle

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| Status lifecycle with actor, time and reason | Done | `attestra/models.py`, `attestra/services.py`, `attestra/audit.py` | |
| Risk acceptance with owner and expiry | Done | `attestra/models.py` (RiskAcceptance), `migrations/versions/0004_compliance_phase3.py` | `expire-risk` CLI reopens expired ones |
| Ageing and SLA breach report | Done | `attestra/reports/templates/ageing.html.j2` | |
| Jira and GitHub ticket sync | Done (optional) | `attestra/integrations/tickets.py`, `jira.py`, `github.py`, `routes.py` | Off by default |

## 5. Compliance mapping

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| CWE to objective to framework hub, roll-up, assessor confirmation | Done | `attestra/compliance/engine.py`, `attestra/compliance/data/cwe_map.yaml` | C1 to C3 |
| PCI DSS 4.0.1 (29 refs), ISO 27001:2022 (20), SOC 2 (14) | Done | `attestra/compliance/data/controls.yaml` | C4 to C6; covers the doc lists 19/19, 12/12, 11/11 |
| Mapping strength and rationale | Done | `controls.yaml`, `cwe_map.yaml`, `engine.py`, `compliance.html.j2` | C7 |
| External libraries (OSCAL, SCF) | Done | `attestra/compliance/libraries/` | C8, `attestra library-import` |
| New packs: CERT-In, RBI, SEBI CSCRF, DORA, NIST CSF 2.0 | Done | `attestra/compliance/data/packs/` | YAML libraries; `tests/test_phase8_framework_packs.py` |
| QSA / ISO lead auditor review of the library | Pending | `attestra/compliance/data/REVIEW.md` | Human process; reviewer fields still pending |

## 6. Evidence and audit

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| Hash at capture | Done | `attestra/services.py` | |
| Masking of PAN, credentials, PII | Done | `attestra/evidence/mask.py` | |
| WORM storage | Done (optional) | `attestra/storage/local.py`, `attestra/storage/s3.py` | S3 Object Lock via `ATTESTRA_STORAGE`; live MinIO test optional |
| Retention and purge | Done | `attestra/ops/retention.py`, `migrations/versions/0006_evidence_hardening.py` | |
| Append-only hash-chained audit, download events, export | Done | `attestra/audit.py`, `attestra/api.py` | |
| Backup/restore with sha256 manifest | Done | `attestra/ops/backup.py` | |
| Per-tenant encryption keys | Partial | `attestra/secret_store.py` | Vault/OpenBao secret store exists; per-tenant evidence encryption keys not found in the code |

## 7. Signed reports

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| Three-step workflow with QA reject | Done | `attestra/reports/render.py`, `migrations/versions/0005_report_workflow_retests.py` | |
| Customer-verifiable signature | Done | `attestra/reports/signing.py` | Ed25519, HMAC fallback |
| Closure and attestation letters | Done | `attestra/reports/templates/closure_letter.html.j2`, `attestation_letter.html.j2` | |
| DOCX / PDF | Done | `attestra/reports/export.py` | WeasyPrint on Windows falls back to a minimal PDF |
| Framework packs, executive trend | Done | `attestra/reports/packs.py`, `executive.html.j2`, `iso_soa.html.j2` | |
| SARIF, CSV, OSCAL | Partial | `attestra/reports/sarif.py`, `attestra/reports/oscal.py` | OSCAL validated against a minimal schema, not the full NIST schema |

## 8. Retest

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| Retest with false-fix guard | Done | `attestra/retest.py` | Fixed only if the scan reached the asset; `tests/test_retest_false_close.py` |

## 9. Portal

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| Client portal and read-only auditor view | Done | `attestra/web/portal.py`, `portal_home.html`, `portal_engagement.html`, `auditor_engagement.html` | Jinja, not React/TypeScript |

## 10. Tenancy and RLS

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| Tenant scoping on every query, per-tenant storage | Done | `attestra/services.py` (`scoped`), `migrations/versions/0003_users_tenancy.py` | |
| PostgreSQL 16 with RLS | Done | `attestra/rls.py`, `migrations/versions/0007_postgres_rls.py`, `tests/test_postgres_rls.py` | |

## 11. Orchestration

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| Durable jobs and worker | Done | `attestra/jobs/durable.py`, `queue.py`, `instance_lock.py` | |
| Temporal workflows | Done (optional) | `attestra/orchestration/`, `docs/TEMPORAL.md` | `ATTESTRA_ORCHESTRATOR=temporal`; covers the scan step only |

## 12. Identity and secrets

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| Users, API keys, sessions, six roles | Done | `attestra/auth/keys.py`, `session.py`, `roles.py` | |
| Keycloak OIDC with JWT checks | Done | `attestra/auth/oidc.py`, `attestra/auth/jwt_verify.py`, `deploy/keycloak/attestra-realm.example.json` | |
| Vault / OpenBao secrets | Done (optional) | `attestra/secret_store.py`, `docs/IDENTITY_AND_SECRETS.md` | `ATTESTRA_SECRETS_BACKEND=vault` |
| Rate limit, security headers | Done | `attestra/api_security.py` | |
| Rotate dev secrets for a shared deploy | Pending | n/a | Operational step |

## 13. Observability and deployment

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| Prometheus metrics, OpenTelemetry, JSON logs | Done | `attestra/observability.py` (`GET /metrics`) | |
| Prometheus, Grafana, Loki config | Done | `deploy/observability/` | |
| Containers and Helm | Done | `Dockerfile`, `deploy/helm/attestra/` | |
| OpenSearch | Pending | n/a | Optional in the plan; not built |

## 14. AI narratives

| Target | Status | Implemented in | Notes |
|---|---|---|---|
| Draft narratives marked AI-generated, with an off switch | Done (optional) | `attestra/ai_narratives.py`, `attestra/web/ai_routes.py`, `docs/AI_NARRATIVES.md` | Off by default (`ATTESTRA_AI_NARRATIVES=on`); redacted metadata only; tester approval needed |

## C1 to C11

| Item | Status | Implemented in |
|---|---|---|
| C1 CWE to objective to framework hub | Done | `attestra/compliance/engine.py`; `tests/test_library_integrity.py` |
| C2 Status roll-up and process controls | Done | `attestra/compliance/engine.py` |
| C3 Assessor confirmation with rationale | Done | `attestra/services.py` |
| C4 PCI DSS 4.0.1 refs (19/19, 29 refs) | Done | `controls.yaml`; `tests/test_control_libraries.py` |
| C5 ISO 27001:2022 refs (12/12, 20 refs) | Done | `controls.yaml`; `tests/test_control_libraries.py` |
| C6 SOC 2 refs (11/11, 14 refs) | Done | `controls.yaml`; `tests/test_control_libraries.py` |
| C7 Mapping strength and rationale | Done | `engine.py`, `compliance.html.j2`; `tests/test_c7_c11_mapping_soc2.py` |
| C8 OSCAL and SCF library import | Done | `attestra/compliance/libraries/`; `tests/test_control_libraries.py` |
| C9 PCI quarterly calendar, segmentation, ASV import | Done | `services.pci_scan_calendar`, `services.import_asv_results`, `attestra/importers/asv.py`, `migrations/versions/0009_pci_asv.py`, `pci.html`, `pci_calendar.html`; `tests/test_c9_c10_pci_iso.py` |
| C10 ISO SoA, nonconformity/corrective action, 9.2 sampling | Done | `models.py` (SoaEntry, Nonconformity, AuditSample), `migrations/versions/0010_iso_soa.py`, `iso.html`; `tests/test_c9_c10_pci_iso.py` |
| C11 SOC 2 Type II population and sample export | Done | `attestra/reports/soc2_sampling.py`, API `GET /api/engagements/{id}/soc2/sample`, CLI `soc2-sample`; `tests/test_c7_c11_mapping_soc2.py` |

## Remaining items

| Item | Status | Where | Notes |
|---|---|---|---|
| External pentest of Attestra (8.1) | Blocked (external) | `docs/PENTEST_SCOPE.md` | Scope is ready; needs a third-party tester |
| Staging load test (8.2) | Pending | `deploy/loadtest/attestra.js`, `docs/LOAD_TEST.md` | The local run is done (local Postgres 16, 10 VUs, p95 220 ms, 0% errors) |
| Release tag (8.3) | Pending (owner) | `CHANGELOG.md`, `docs/RELEASE.md` | Version is 1.0.0; the owner creates the tag himself |
