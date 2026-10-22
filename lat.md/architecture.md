# Architecture

Attestra v0.1 is an **import-and-report** security testing evidence platform. Testers run scanners elsewhere; Attestra imports result files, normalizes findings, maps them to compliance controls, and produces hashed, four-eyes-approved, signed reports.

It does **not** execute scanners, spawn runners, or attack targets. That boundary is intentional (license isolation and legal scope).

## Product thesis

Cut the path from engagement kick-off to a signed, audit-ready report. Every claim in a report should be traceable to raw imported evidence.

See also `docs/ARCHITECTURE.md` and `docs/Security Testing & Compliance Platform — Architecture (v2 PCI, ISO 27001, SOC 2).md`.

## System layers

How the Python package is split: interfaces call shared services; importers, compliance, and reports sit underneath.

| Layer | Role | Code |
| --- | --- | --- |
| Interfaces | REST API, CLI, server-rendered dashboard | [[attestra/api.py]], [[attestra/cli.py]], [[attestra/web/ui.py]] |
| Business rules | Shared write path; every mutation audited | [[attestra/services.py]] |
| Importers | Parse ZAP / Nuclei / Trivy / SARIF into one schema | `attestra/importers` |
| Findings | Fingerprint dedup, risk score, lifecycle | [[attestra/fingerprint.py]], [[attestra/scoring.py]] |
| Compliance | CWE → objective → PCI / ISO / SOC 2 | [[attestra/compliance/engine.py]] |
| Reports | Jinja HTML, four-eyes, HMAC signature | [[attestra/reports/render.py]], [[attestra/reports/signing.py]] |
| Evidence and audit | Content-addressed files; hash-chained log | [[attestra/services.py#_store]], [[attestra/audit.py]] |
| Data | SQLAlchemy models; SQLite or PostgreSQL; Alembic for production schema | [[attestra/models.py]], [[attestra/db.py]], [[attestra/db.py#upgrade]], [[attestra/config.py]], [[migrations/versions/0001_baseline.py]] |

## Design decisions

Core product rules that shape the v0.1 implementation. Prefer changing these deliberately over silent drift. Details are in the sections below.

## Import do not execute

Attestra never launches scanners; it only parses result files testers already produced.

[[attestra/importers/__init__.py]] documents that Attestra never runs scanners. Supported formats are registered in [[attestra/importers/__init__.py#PARSERS]].

## Hub and spoke compliance mapping

Findings map once to a control objective through CWE; objectives then fan out to frameworks via YAML.

Findings map once to a control **objective** through CWE. Objectives map to each framework. Adding a framework is YAML, not code. Engine: [[attestra/compliance/engine.py]]. Libraries: `attestra/compliance/data/controls.yaml`, `attestra/compliance/data/cwe_map.yaml`.

## Propose then confirm

The engine proposes control status; a named assessor must confirm before it is treated as decided.

[[attestra/compliance/engine.py#evaluate]] proposes control statuses. A named assessor confirms via [[attestra/services.py#confirm_control]]. `no_exceptions` is distinct from `met` so absence of findings is never treated as proof a control is in place.

## PCI CDE scope

PCI evaluation only counts findings on CDE assets (plus unmatched locations, conservatively).

[[attestra/compliance/engine.py#in_framework_scope]] counts PCI findings only on CDE assets (or findings with no matched asset — conservative).

## Evidence integrity

Raw artifacts are masked, hashed write-once; audit is append-only; backups use manifests.

Raw imports and evidence are masked ([[attestra/evidence/mask.py#mask_bytes]]), SHA-256 hashed, and stored write-once via [[attestra/storage/__init__.py#get_storage]] ([[attestra/services.py#_store]]). Retention and purge live in [[attestra/ops/retention.py#purge_expired]]; backup/restore with sha256 manifests in [[attestra/ops/backup.py#backup]]. The audit log is hash-chained and append-only ([[attestra/audit.py]]). Reports carry Ed25519 or HMAC signatures ([[attestra/reports/signing.py]]).

## Schema migrations

Production and `attestra init` / serve apply Alembic to head; tests still use fast `create_all`.

[[attestra/db.py#upgrade]] runs Alembic (`alembic.ini`, [[migrations/env.py]]) against [[attestra/config.py#DATABASE_URL]]. [[attestra/db.py#init]] takes `use_migrations=True` for CLI/API startup; pytest uses `create_all` for speed. Baseline revision: [[migrations/versions/0001_baseline.py]].

## Engagement flow

End-to-end path for one engagement from create to signed report.

1. Create tenant + engagement ([[attestra/services.py#create_engagement]]).
2. Record signed authorization ([[attestra/services.py#add_authorization]]); imports are blocked without a currently valid one.
3. Add in-scope assets ([[attestra/services.py#add_asset]]).
4. Import scanner results ([[attestra/services.py#import_results]]).
5. Enrich with KEV / EPSS ([[attestra/services.py#enrich]]); triage via [[attestra/services.py#transition]].
6. Evaluate compliance ([[attestra/services.py#compliance]]); assessor confirms controls.
7. Generate, four-eyes approve, and verify reports ([[attestra/reports/render.py#generate_report]]).

## Runner plane (Phase 1)

Scoped scanner dispatch is implemented; Temporal/OPA/SSO remain later phases.

See [[runner]]. Adapters write raw output under [[attestra/config.py#RAW_DIR]] then call [[attestra/services.py#import_results]]. Identity is Bearer/session with RBAC ([[authorization#Identity]]).

## Still deferred

Capabilities intentionally left for later phases (see `docs/GAP_ANALYSIS_CURRENT.md`).

- Temporal workflows, OPA policy engine, Postgres RLS, Helm (Phase 6)
- Full Keycloak UI login flow (OIDC flag and claim validation exist; enable when IdP is provisioned)
- Client portal polish, ticket sync, extra scanners (Phase 7)
- External pentest / GA (Phase 8)

## Observability

Prometheus metrics at `/metrics`, optional OpenTelemetry tracing for FastAPI and SQLAlchemy, and JSON logs for Loki.

[[attestra/observability.py#MetricsMiddleware]] counts requests by route template and records latency into [[attestra/observability.py#REGISTRY]], served by [[attestra/api.py#metrics]]. Anonymous `/metrics` is denied by default; scrapers must send `ATTESTRA_METRICS_TOKEN`, or operators may set `ATTESTRA_METRICS_ALLOW_ANON` for trusted networks, or use an admin session. [[attestra/observability.py#setup_otel]] activates only with `ATTESTRA_OTEL_ENABLED` and the `observability` extra. [[attestra/observability.py#JsonLogFormatter]] is enabled by `ATTESTRA_LOG_JSON`. Grafana, Prometheus and Promtail stubs live in `deploy/observability/`.

## Added modules

Packages added after the core flow. Each one calls the shared services and records audit events.

- [[attestra/users/service.py]]: admin invites, roles, password reset, and the `user set-password` CLI.
- [[attestra/library/service.py]]: findings library and tenant report templates.
- [[attestra/proof/replay.py]]: redacted HTTP proof and in-scope replay for retests.
- [[attestra/trust/service.py]]: opt-in trust center for signed reports.
- [[attestra/webhooks/service.py]] and [[attestra/integrations/tickets.py]]: signed outbound webhooks and pluggable ticket sync (Jira, GitHub, ServiceNow, Azure DevOps); closed/done/resolved back-sync to `fixed` also requests a pending retest when none is open.
- [[attestra/alerts/service.py]]: tenant email alerts for new Critical/High findings, security header changes, and missed SLA (SMTP off by default).
- [[attestra/ai_narratives.py]]: AI draft text, off by default, used only after tester approval.
- [[attestra/tuning.py]] and [[attestra/rls.py]]: per-tenant risk weights and suppression, and PostgreSQL row-level security.
- [[attestra/runner/ownership.py]]: target ownership check by DNS TXT, well-known file, or owner confirmation for a private IP; [[attestra/runner/ownership.py#set_token]] reuses a token from another target.
- [[attestra/integrations/grc.py]]: optional GRC evidence push (Vanta/Drata/Sprinto webhook), off by default.
- [[attestra/reports/signoff.py]]: builds the sign-off banner ([[attestra/reports/signoff.py#banner_html]]) and adds it only to the viewed page ([[attestra/reports/signoff.py#inject]]); the sealed file is never changed.

## AI drafts

Optional narratives via [[attestra/ai_narratives.py]], off unless `ATTESTRA_AI_NARRATIVES=on`. Keys never appear in drafts, logs, or errors.

Default provider is local Ollama when `ATTESTRA_AI_PROVIDER` is unset. OpenAI-compatible needs a key from the secret store or `ATTESTRA_AI_API_KEY`. Tester (or lead/admin) approval is required before any draft reaches a report.

## GRC evidence push

[[attestra/integrations/grc.py#connector_from_env]] returns None until `ATTESTRA_GRC_BACKEND` is `vanta`, `drata`, `sprinto`, or `webhook` with HTTPS URL and secret. [[attestra/integrations/grc.py#push_signed_report]] POSTs signed report metadata (id, sha256, kind, signed_at, download hint) only; [[attestra/integrations/grc.py#safe_push_grc_report]] catches errors so signing is never broken.