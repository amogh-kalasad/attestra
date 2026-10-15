# Changelog

All notable changes to Attestra. Format based on Keep a Changelog; versions follow SemVer.

## [Unreleased]

### Added
- Trust center (migration `0011_trust_center`): per-tenant public page, off by default; signed reports only (signature re-checked on download), findings as headlines only; NDA access requests approved by a lead or admin with a hashed one-time token; all requests, decisions and downloads audited. See `docs/TRUST_CENTER.md`.
- Findings library and report templates (migration `0012_findings_library`): reusable writeups (32 starter web entries) with search, suggestions on import by tool rule id or CWE, apply-to-finding that fills empty fields only; sandboxed per-tenant report templates (cover title, logo, section order) with the built-in template as fallback. See `docs/FINDINGS_LIBRARY.md`.
- Proof of exploit and replay (migration `0013_proof_webhooks`): HTTP request/response pairs and screenshots as hashed, redacted evidence, auto-captured from ZAP and Nuclei imports; replay on retest limited to authorized scope with a pinned IP and safe methods by default; the result is a suggestion a tester confirms. See `docs/PROOF_AND_REPLAY.md`.
- Webhooks and workflow rules (migration `0013_proof_webhooks`): per-tenant endpoints (JSON, Slack, Teams) for `finding.created`, `finding.status_changed`, `retest.completed`, `report.signed`; HMAC-SHA256 signatures, SSRF guard, retries with backoff; rules to notify, assign or open a ticket. See `docs/WEBHOOKS.md`.
- User management (migration `0014_user_invites`): admin invites with expiring one-time links, password reset links, disable/enable users (sessions of disabled users are rejected), last-login time, password policy (at least 12 characters). See `docs/USER_MANAGEMENT.md`.

## [1.0.0] - unreleased (GA candidate)

First general-availability release, covering Phases 0 to 7 of the implementation guide.

### Phase 0 - Foundations
- Alembic migrations with a baseline; ruff and CI; tests in the repo; `SECURITY.md` and threat-model note.

### Phase 1 - Runner plane
- Scope authorization, exact scanner image matching and digest pinning, SSRF block list, DNS pinning safe HTTP client.
- Scanner base and adapters, confined ZAP egress, `ScanRun` model, dispatch gate (window, intrusive flag, rate limit).
- Scope deny rules, durable jobs and worker, kill switch (halt/resume), scan API and UI, target ownership checks.

### Phase 2 - Identity, roles and tenancy
- Users and API keys, spec roles (admin, lead, tester, reviewer, client_viewer, auditor), session login.
- Tenant scoping and per-tenant storage, rate limiting and security headers, OIDC (Keycloak) behind a flag.

### Phase 3 - Compliance
- Completed PCI DSS v4, ISO 27001:2022 and SOC 2 control libraries with mapping strength and rationale.
- Risk acceptance, ASV import and segmentation records, PCI quarterly scan calendar, OWASP references.
- ISO SoA view and nonconformities, ageing and SLA breach report.
- C9-C11: PCI quarterly scan calendar with rescan-until-clean, segmentation records and ASV results import (migration `0009_pci_asv`); ISO SoA entries, nonconformity/corrective-action workflow and clause 9.2 audit sampling (migration `0010_iso_soa`); seeded SOC 2 Type II population/sample export (`soc2-sample` CLI, `GET /api/engagements/{id}/soc2/sample`, CSV/JSON).

### Phase 4 - Reports and signing
- Three-step report workflow (draft, QA, sign), retests with false-fix guards.
- Closure and attestation letters, DOCX and PDF output, Ed25519 signatures with verification.
- Framework packs, executive trend, SARIF and audit exports.

### Phase 5 - Evidence hardening
- Secret masking at capture, storage backend interface (local/S3 with object lock).
- Retention and purge, append-only audit log with hash chain, backup/restore with sha256 manifest, KEV/EPSS refresh.

### Phase 6 - Production infrastructure
- PostgreSQL 16 by default with row-level security, Temporal orchestration (optional), OPA/Rego scope policy.
- Keycloak default identity, Vault/OpenBao secret store, containers and Helm chart.
- OpenTelemetry and Prometheus metrics, scheduled scans and CI/CD gate.

### Phase 7 - Product polish and integrations
- Client portal and read-only auditor view.
- Jira and GitHub Issues ticket sync (off by default); CycloneDX and Dependency-Track SBOM importers.
- Adapters for Prowler, kube-bench, testssl.sh, Gitleaks, Checkov and naabu; OpenVAS and MobSF as opt-in services.
- Per-tenant risk weights, suppression rules (migration `0008_tuning`), false-positive rate per tool.
- Legal pack (authorization and rules-of-engagement templates) and `docs/LICENSES.md`.

### Phase 8 - Release
- 8.5 Optional AI-drafted executive summaries and finding narratives (off by default, `ATTESTRA_AI_NARRATIVES=on`); redacted metadata only, tester approval required before anything reaches a report. See `docs/AI_NARRATIVES.md`.

### Fixed
- Session cookies were rejected intermittently (about 1 in 8 logins).
- Migrations now honour the database URL they are given, so they run on Postgres.

### Phase 8 (in this release)
- k6 load test script and local results (`docs/LOAD_TEST.md`); version set to 1.0.0.
