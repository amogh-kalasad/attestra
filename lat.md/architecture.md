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
- [[attestra/library/service.py]]: findings library and tenant report templates; [[attestra/library/service.py#seed_defaults]] and [[attestra/library/service.py#import_template_entries]] (JSON/CSV via [[attestra/library/import_convert.py#convert_library_template]]) cover onboarding.
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

## Authenticated website testing

Optional engagement workflow for authorized, authenticated security testing of in-scope web apps with secret references and coverage evidence.

Off by default (`ATTESTRA_AUTH_WEB_ENABLED` → [[attestra/config.py#AUTH_WEB_ENABLED]]). Caps and pacing: [[attestra/config.py#AUTH_WEB_MAX_ROUTES]], [[attestra/config.py#AUTH_WEB_MAX_DEPTH]], [[attestra/config.py#AUTH_WEB_MAX_DURATION_S]], [[attestra/config.py#AUTH_WEB_RATE_PER_HOST]], [[attestra/config.py#AUTH_WEB_CONCURRENCY]]. Test-account secrets use [[attestra/credentials/store.py]] (Fernet files + opaque `secret_ref`; `ATTESTRA_CREDENTIAL_FERNET_KEY`); [[attestra/models.py#AuthCredentialProfile]] stores metadata only. Profile CRUD/validate is [[attestra/auth_web/profiles.py]] with API [[attestra/auth_web/routes.py]] (`/api/auth-web/...`); [[attestra/auth_web/profiles.py#profile_dict]] never returns plaintext. [[attestra/auth_web/checklists.py#ensure_checklist]] seeds a built-in WSTG/ASVS subset into [[attestra/models.py#AuthChecklistItem]]; [[attestra/auth_web/checklists.py#update_checklist_item]] refuses `passed` when notes imply skipped or when leaving `blocked` without evidence. [[attestra/auth_web/coverage.py#coverage_summary]] aggregates route/element/checklist/profile counts (`coverage_pct`, `exclusions_note`, `incomplete`) without treating skipped as passed. Technical reports include the checklist via [[attestra/reports/render.py#_auth_web_report_context]] when rows exist or [[attestra/config.py#AUTH_WEB_ENABLED]] is on (seeds once if empty); HTML never embeds `secret_ref` or credentials. UI (gated by [[attestra/config.py#AUTH_WEB_ENABLED]]): `GET /engagements/{eid}/auth-coverage` renders `engagement_auth_coverage.html` with coverage, checklist, routes, and profiles; profile creates use [[attestra/auth_web/routes.py#create_auth_profile]] and the `_auth_profiles_section.html` form (`secret` once, never echoed in redirects). Engagement subnav links when enabled. Crawl inventory uses [[attestra/auth_web/scope.py#CrawlScope]] / [[attestra/auth_web/crawl.py#crawl]] with [[attestra/auth_web/limits.py#CrawlLimits]]; forms via [[attestra/auth_web/forms.py#synthetic_value]]; role diffs via [[attestra/auth_web/roles.py#compare_roles]] (intrusive IDOR plans need an explicit flag gated by the scan gate). Multi-role access-control runs use [[attestra/auth_web/role_scan.py#run_role_comparison]] (feature flag + valid authorization + tenant check; pluggable fetcher or prebuilt snapshots; always `intrusive=False`; meaningful status/redirect/control diffs persist as findings with `tools=["auth_web_roles"]`, CWE-862, severity info/low; secrets via [[attestra/credentials/store.py#get_secret]] never enter finding text). Gated IDOR / request-tampering probes live in [[attestra/auth_web/tamper.py]] (see [[architecture#Phase 7 gated IDOR / request tampering]]). Crawl and form checks stay non-destructive unless the intrusive gate and signed authorization allow more. Screenshot capture uses [[attestra/proof/screenshot_redact.py#prepare_page_for_capture]] then [[attestra/proof/screenshot_redact.py#attach_redacted_screenshot]] (optional Pillow [[attestra/proof/screenshot_redact.py#redact_png_regions]]) before evidence hash/store. Auto-attach for findings with http(s) locations is [[attestra/proof/screenshots.py#capture_finding_screenshot]] (injected/registered `capture_fn` or provided PNG bytes; default registry empty so imports stay network-free); [[attestra/proof/capture.py#capture_from_import]] calls it after HTTP pairs when a capture_fn is registered. ZAP authenticated contexts are prepared by [[attestra/auth_web/zap_auth.py]] (form/header/cookie; ``sso_bootstrap`` blocked) and optionally wired into [[attestra/runner/scanners/zap.py#ZapAdapter]] via mounted ``.context`` files when [[attestra/config.py#AUTH_WEB_ENABLED]] is on — secrets never on argv (see [[runner#ZAP authentication]]). Local offline mock and setup notes live in `docs/AUTH_WEB_TESTING.md`.

## Phase 7 gated IDOR / request tampering

Intrusive-only object-access probes that plan by default and execute only under the scan scope gate.

[[attestra/auth_web/tamper.py#assert_intrusive_allowed]] requires profile `active` or `intrusive`, then reuses [[attestra/runner/gate.py#policy_input]] / [[attestra/runner/policy.py#decide]] so `intrusive_allowed`, signed authorization environment, ownership, window, and rate limit all apply; refusals raise [[attestra/services.py#ServiceError]]. [[attestra/auth_web/tamper.py#plan_and_maybe_execute_probes]] always builds an [[attestra/auth_web/roles.py#IntrusiveProbePlan]] via [[attestra/auth_web/roles.py#plan_object_access_probes]] (`intrusive=True`). With `execute=False` (default) it returns the plan and never calls `fetch_fn`. With `execute=True` it asserts the gate, caps at five object IDs, paces GETs, stays same-origin to the asset, and never sends exploit payloads or state-changing methods. Results are dicts with `expected` / `observed` / `status` / `redacted`; a sensitive marker redacts the body and stops further probes. Optional synthetic [[attestra/models.py#Finding]] rows (CWE-639) carry confidence and remediation when `create_findings=True`.

### assert_intrusive_allowed

Profile and scope-policy gate before any intrusive IDOR execution.

### plan_and_maybe_execute_probes

Plan-always helper with optional bounded read-only GET execution.

