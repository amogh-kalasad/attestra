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
| Data | MongoDB only (replica set + GridFS); SQLAlchemy models remain as the MongoSession schema | [[attestra/bootstrap.py#init_persistence]], [[attestra/persistence/mongo/client.py#init_mongo]], [[attestra/db.py]], [[attestra/models.py]], [[attestra/config.py]] |

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

Raw imports and evidence are masked ([[attestra/evidence/mask.py#mask_bytes]]), SHA-256 hashed, and stored write-once via [[attestra/storage/__init__.py#get_storage]] ([[attestra/services.py#_store]]). Retention and purge live in [[attestra/ops/retention.py#purge_expired]]; backup/restore with sha256 manifests in [[attestra/ops/backup.py#backup]] (Mongo logical export via [[attestra/ops/mongo_backup.py#backup_mongo]]). The audit log is hash-chained and append-only ([[attestra/audit.py]]). Reports carry Ed25519 or HMAC signatures ([[attestra/reports/signing.py]]).

## Schema migrations

Document schema migrations run on Mongo init; SQL/Alembic is archived (migrate-source only).

[[attestra/persistence/mongo/client.py#init_mongo]] applies pending revisions under `attestra/persistence/mongo/migrations` (baseline indexes, identity/webhook indexes, partial unique credit idempotency keys). [[attestra/db.py#init]] / [[attestra/db.py#upgrade]] open Mongo only. Legacy SQL trees and the one-shot SQL→Mongo importer live under `.migration_backups/sql_removal/`.

## MongoDB migration (in progress)

Runtime persistence is MongoDB only; `db.session()` yields a MongoSession.

Bootstrap: [[attestra/bootstrap.py#init_persistence]]. Client: [[attestra/persistence/mongo/client.py#init_mongo]]; repos under `attestra/persistence/mongo/repositories/`; GridFS [[attestra/storage/mongo.py#MongoStorage]]; tenant filters [[attestra/persistence/mongo/tenant.py]]. Session façade: [[attestra/db.py#session]] → MongoSession. Domain write paths (audit, jobs, credits, reports) hit Mongo repositories. Logical backup: [[attestra/ops/mongo_backup.py#backup_mongo]]. Post-cutover helpers: [[attestra/migration/engine.py#validate]]. Design notes: `docs/mongodb_migration/`.


## Engagement flow

End-to-end path for one engagement from create to signed report.

1. Create tenant + engagement ([[attestra/services.py#create_engagement]]; new types from [[attestra/models.py#NEW_ENGAGEMENT_TYPES]] only).
2. Record signed authorization ([[attestra/services.py#add_authorization]]); imports are blocked without a currently valid one.
3. Add in-scope assets ([[attestra/services.py#add_asset]]; planned tests follow engagement-type workflow via [[attestra/models.py#default_tests_for]]).
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

## World-class security testing audit (Phase 1)

Phase 1 of the world-class VA + PT improvement prompt is an audit-only gap analysis against ENG1 technical report v21; no product code changed in that pass.

Full scorecard, ENG1 issue register (CORS/cdn-cgi, Cloudflare cookies, HSTS evidence contradiction, weak-cipher evidence, XSS-Protection mapping, wrong Permissions-Policy remediation), and prioritized backlog for Phases 2–10 live in `docs/WORLDCLASS_VAPT_PHASE1_AUDIT.md`.

## World-class finding validation (Phase 2)

General classifiers mark scanner and automated-testing observations without treating alerts as confirmed.

[[attestra/finding_validation/classify.py#classify_observation]] returns a validation class plus optional severity/CWE/OWASP/WSTG overrides. CDN/CF helpers live in [[attestra/finding_validation/infrastructure.py]]; header contradiction helpers in [[attestra/finding_validation/headers.py]]. Import apply + post-capture reconcile: [[attestra/services.py#_apply_import_validation]], [[attestra/finding_validation/reconcile.py#reconcile_validation_from_evidence]]. Delivery note: `docs/WORLDCLASS_VAPT_PHASE2_VALIDATION.md`. See [[findings#Lifecycle#Validation class vs workflow status]].

## World-class PT coverage honesty (Phase 3)

Security-testing coverage is tracked separately from vulnerability counts; skipped or limited work must not read as passed.

[[attestra/auth_web/checklists.py#update_checklist_item]] refuses `passed` when notes contain incomplete-coverage markers (`not covered`, `not tested`, `skipped`, `limited`, `forms not covered`, `blind`) via [[attestra/auth_web/checklists.py#notes_imply_incomplete_coverage]], and still requires evidence to leave `blocked`. Auto-apply ([[attestra/auth_web/checklist_auto.py#apply_verdicts]]) never upgrades `blocked`→`passed` without evidence and refuses incomplete notes; limited T21 probes stay `blocked`. Snapshot: [[attestra/automated_vapt/coverage/snapshot.py#build_coverage_snapshot]] / [[attestra/services.py#engagement_coverage_snapshot]] (checklist + route + automated case totals). Category→module map: [[attestra/automated_vapt/testing/coverage_matrix.py#PHASE3_COVERAGE]]. Delivery: `docs/WORLDCLASS_VAPT_PHASE3_PT_COVERAGE.md`. Phase 4 deepens the snapshot, ledger, and report/API surfacing (see below).

## World-class coverage execution engine (Phase 4)

Extends the Phase 3 snapshot with endpoint auth buckets, methods, params, roles, and deferred-case honesty.

[[attestra/automated_vapt/coverage/snapshot.py#build_coverage_snapshot]] / [[attestra/automated_vapt/coverage/models.py#CoverageSnapshot]] add authenticated/unauthenticated endpoint counts (route `authenticated` or non-empty `role_name`), `methods_tested`, parameter and role totals (elements preferred, else ledger/query keys), `automated_cases_blocked` / `test_cases_blocked` (DEFERRED distinct from SKIPPED), `coverage_pct_endpoints` via [[attestra/auth_web/coverage.py#_route_bucket]], `ledger_entry_count` from [[attestra/automated_vapt/coverage/ledger.py#collect_engagement_ledger]], and always `scan_completion_is_not_security_coverage=True`. Vulnerability severity totals stay out of this object. [[attestra/services.py#engagement_coverage_snapshot]] returns that dict and optionally attaches a ledger. Delivery: `docs/WORLDCLASS_VAPT_PHASE4_COVERAGE_ENGINE.md`.

## World-class test execution ledger (Phase 4)

Per-case coverage rows under `AutomatedTestExecution.result_json.coverage_ledger`, separate from vuln counts.

[[attestra/automated_vapt/coverage/ledger.py#CoverageLedgerEntry]] holds test_id, category, target_endpoint, optional http_method, parameters, execution_status, executed_at, auth_context, evidence_refs, short result, limitation, block_or_fail_reason, and engagement/execution/asset ids. [[attestra/automated_vapt/coverage/ledger.py#entries_from_case_result]] extracts endpoints from observations, evidence pairs, pages, replay endpoints, module probes, and finding_location. [[attestra/automated_vapt/core/orchestrator.py#run_execution]] appends via [[attestra/automated_vapt/coverage/ledger.py#merge_ledger]] after each case (persists mid-run). Statuses map PASSED/FINDING/FAILED/SKIPPED/DEFERRED; DEFERRED/SKIPPED always set limitation (not full coverage). Aggregate with [[attestra/automated_vapt/coverage/ledger.py#collect_engagement_ledger]] / [[attestra/automated_vapt/coverage/ledger.py#build_coverage_ledger]].

## World-class coverage visibility (Phase 4)

Surfaces security-testing coverage separately from vulnerability counts via API and technical reports.

`GET /api/engagements/{eid}/coverage` ([[attestra/api.py#engagement_coverage]]) requires `engagement.read`, returns [[attestra/services.py#engagement_coverage_snapshot]], and with `?ledger=1` includes the Phase 4 ledger list. Technical report context key `security_testing_coverage` from [[attestra/reports/render.py#_security_testing_coverage_context]] drives the **Security testing coverage** subsection in `technical.html.j2` (endpoints discovered/tested/untested, checklist passed/failed/blocked/not_started, automated successful/failed/skipped, exclusions note). PDF uses the same HTML path. Scan completion must never be presented as 100% security testing coverage; skipped/blocked ≠ passed.

## World-class risk scoring (Phase 5)

Keeps CVSS as technical severity of record and treats priority/`business_risk` as a separate ranking signal.

[[attestra/scoring.py#validate_cvss_vector]] soft-accepts CVSS 3.x and 4.0 vectors; [[attestra/scoring.py#cvss_version_from_vector]] / `Finding.cvss_version` label the version; v4 scores are never invented. [[attestra/scoring.py#explain_risk_modifiers]] documents reproducible modifiers; [[attestra/services.py#rescore]] sets `business_risk`. [[attestra/grade.py#score_from_findings]] skips the HSTS-missing fail when `validation_status` is not_reproducible / informational / validation FP, or when in-memory HTTP evidence shows HSTS with max-age ([[attestra/finding_validation/headers.py#hsts_present_in_evidence]]). Technical risk legend (and PDF/DOCX injections) separates CVSS technical severity from priority / business risk. [[attestra/reports/render.py#_context]] open-vuln KPIs exclude informational and not-reproducible validation classes. See [[findings#Site grade]], [[findings#CVSS vector]], [[findings#Risk score]]. Delivery: \docs/WORLDCLASS_VAPT_PHASE5_RISK_SCORING.md\.

## World-class finding normalization (Phase 6)

Conservative cross-tool consolidation with retained scanner observations and explicit merge/dedup honesty fields.

Import soft-merges only at high confidence via [[attestra/dedup.py#find_best_soft_match]] / [[attestra/dedup.py#MERGE_THRESHOLD]], always writing a [[attestra/models.py#FindingObservation]] under the canonical finding ([[attestra/services.py#import_results]]). Post-import [[attestra/crossmerge.py#recompute]] links related rows with `merged_into_id` / `merge_rationale` and never deletes findings or observations; [[attestra/crossmerge.py#collapse]] annotates Sources for UI and Markdown. [[attestra/api.py#_finding_dict]] exposes `merged_into_id`, `merge_rationale`, `dedup_confidence`, `dedup_rationale`, `validation_status`, `tools_count`, and loaded-only `observations_count`. JSON export adds the same merge/validation keys on each finding; Markdown lists Sources plus merge rationales and folds member observations onto the primary.

Security context guards: [[attestra/finding_normalize.py#security_context_key]] / [[attestra/finding_normalize.py#path_context_bucket]] (`app`, `cdn-cgi`, `challenge`, `static`). Concept and CWE+path merges in [[attestra/crossmerge.py#match_reason]] require the same context; CVE stays host-level. Rationales include `@{bucket}` for concept/CWE links. [[attestra/crossmerge.py#explain_near_misses]] reports same-host+concept pairs that differ in context. Sibling expansions may populate [[attestra/finding_normalize.py#EXTRA_CONCEPT_RULES]]. See [[findings#Deduplication#Cross-tool deduplication]], [[findings#Deduplication#Cross-tool merge]]; doc `docs/WORLDCLASS_VAPT_PHASE6_NORMALIZE_DEDUP.md`.

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
- [[attestra/tuning.py]]: per-tenant risk weights and suppression.
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

Off by default (`ATTESTRA_AUTH_WEB_ENABLED` → [[attestra/config.py#AUTH_WEB_ENABLED]]). Caps and pacing: [[attestra/config.py#AUTH_WEB_MAX_ROUTES]], [[attestra/config.py#AUTH_WEB_MAX_DEPTH]], [[attestra/config.py#AUTH_WEB_MAX_DURATION_S]], [[attestra/config.py#AUTH_WEB_RATE_PER_HOST]], [[attestra/config.py#AUTH_WEB_CONCURRENCY]]. Test-account secrets use [[attestra/credentials/store.py]] (Fernet files + opaque `secret_ref`; `ATTESTRA_CREDENTIAL_FERNET_KEY`); [[attestra/models.py#AuthCredentialProfile]] stores metadata only. Profile CRUD/validate is [[attestra/auth_web/profiles.py]] with API [[attestra/auth_web/routes.py]] (`/api/auth-web/...`); [[attestra/auth_web/profiles.py#profile_dict]] never returns plaintext. [[attestra/auth_web/checklists.py#ensure_checklist]] seeds a built-in WSTG/ASVS subset into [[attestra/models.py#AuthChecklistItem]]; [[attestra/auth_web/checklists.py#update_checklist_item]] refuses `passed` when notes imply incomplete coverage (skipped/limited/not covered/blind/not tested) or when leaving `blocked` without evidence. [[attestra/auth_web/coverage.py#coverage_summary]] aggregates route/element/checklist/profile counts (`coverage_pct`, `exclusions_note`, `incomplete`) without treating skipped as passed; Phase 3 adds [[attestra/automated_vapt/coverage/snapshot.py#build_coverage_snapshot]] (see [[architecture#World-class PT coverage honesty (Phase 3)]]). Technical reports include the checklist via [[attestra/reports/render.py#_auth_web_report_context]] when rows exist or [[attestra/config.py#AUTH_WEB_ENABLED]] is on (seeds once if empty); HTML never embeds `secret_ref` or credentials. UI (gated by [[attestra/config.py#AUTH_WEB_ENABLED]]): `GET /engagements/{eid}/auth-coverage` renders `engagement_auth_coverage.html` with coverage, checklist, routes, and profiles; profile creates use [[attestra/auth_web/routes.py#create_auth_profile]] and the `_auth_profiles_section.html` form (`secret` once, never echoed in redirects). Engagement subnav links when enabled. Crawl inventory uses [[attestra/auth_web/scope.py#CrawlScope]] / [[attestra/auth_web/crawl.py#crawl]] with [[attestra/auth_web/limits.py#CrawlLimits]]; forms via [[attestra/auth_web/forms.py#synthetic_value]]; role diffs via [[attestra/auth_web/roles.py#compare_roles]] (intrusive IDOR plans need an explicit flag gated by the scan gate). Multi-role access-control runs use [[attestra/auth_web/role_scan.py#run_role_comparison]] (feature flag + valid authorization + tenant check; pluggable fetcher or prebuilt snapshots; always `intrusive=False`; meaningful status/redirect/control diffs persist as findings with `tools=["auth_web_roles"]`, CWE-862, severity info/low; secrets via [[attestra/credentials/store.py#get_secret]] never enter finding text). Gated IDOR / request-tampering probes live in [[attestra/auth_web/tamper.py]] (see [[architecture#Phase 7 gated IDOR / request tampering]]). Crawl and form checks stay non-destructive unless the intrusive gate and signed authorization allow more. Screenshot capture uses [[attestra/proof/screenshot_redact.py#prepare_page_for_capture]] then [[attestra/proof/screenshot_redact.py#attach_redacted_screenshot]] (optional Pillow [[attestra/proof/screenshot_redact.py#redact_png_regions]]) before evidence hash/store. Auto-attach for findings with http(s) locations is [[attestra/proof/screenshots.py#capture_finding_screenshot]] (injected/registered `capture_fn` or provided PNG bytes; default registry empty so imports stay network-free); [[attestra/proof/capture.py#capture_from_import]] calls it after HTTP pairs when a capture_fn is registered. ZAP authenticated contexts are prepared by [[attestra/auth_web/zap_auth.py]] (form/header/cookie; ``sso_bootstrap`` blocked) and optionally wired into [[attestra/runner/scanners/zap.py#ZapAdapter]] via mounted ``.context`` files when [[attestra/config.py#AUTH_WEB_ENABLED]] is on — secrets never on argv (see [[runner#ZAP authentication]]). Local offline mock and setup notes live in `docs/AUTH_WEB_TESTING.md`.

## Elite local mock applications

Controlled secure and intentionally vulnerable FastAPI apps for Elite automated security-testing fixtures, isolated to local tests.

Phase-6-compatible secure smoke app: [[tests/fixtures/auth_web_mock_app.py#create_app]]. Elite pair: [[tests/automated_vapt/fixtures/mock_secure_app.py#create_secure_app]] and [[tests/automated_vapt/fixtures/mock_vulnerable_app.py#create_vulnerable_app]] with Account A/B and `proj-a`/`proj-b`. Both Elite apps expose `GET /__attestra_mock__` (`mode=secure|vulnerable`, `local_only=true`). Gap map: `docs/ELITE_VAPT_GAP_ANALYSIS.md`.

## Elite automated security testing

Engagement-scoped orchestrator for approved automated security-test executions (off by default).

Flag: `ATTESTRA_AUTOMATED_VAPT_ENABLED` → [[attestra/config.py#AUTOMATED_VAPT_ENABLED]]. Rows: [[attestra/models.py#AutomatedTestExecution]] (migration `0034_automated_test_executions`). Statuses QUEUED/RUNNING/COMPLETED/FAILED/CANCELLED via [[attestra/automated_vapt/core/execution_manager.py#transition]]. Create/run/cancel: [[attestra/automated_vapt/core/orchestrator.py#create_execution]], [[attestra/automated_vapt/core/orchestrator.py#run_execution]], [[attestra/automated_vapt/core/orchestrator.py#cancel_execution]]. Scope reuses [[attestra/auth_web/scope.py]] through [[attestra/automated_vapt/core/scope_validator.py#validate_target_url]]. Authorization guard: [[attestra/automated_vapt/core/authorization_guard.py#assert_engagement_ready]]. API under `/api/automated-vapt/...` ([[attestra/automated_vapt/routes.py]]). E3 implements `SCOPE_SMOKE`; other catalogue ids return DEFERRED until later Elite phases.

### Scope validation

Elite targets must pass auth_web crawl allowlist and SSRF checks before execution.

### Authorization guard

Feature flag, engagement.write, valid signed authorization, and testing window.

### Execution status

Finite status graph for automated test execution rows.

### Orchestrator

Queue and run approved test-case lists against an engagement asset.

### HTTP capture

HTTPX capture into [[attestra/proof/pair.py#HttpPair]] with redacted report pairs via [[attestra/automated_vapt/capture/http_capture.py#capture_request]]; request/response normalizers in [[attestra/automated_vapt/capture/request_parser.py#parse_request]] and [[attestra/automated_vapt/capture/response_parser.py#parse_response]]. Catalogue case `T01` is wired in the orchestrator.

### Browser capture

Playwright (when installed) or injectable ``capture_fn`` via [[attestra/automated_vapt/capture/browser_capture.py#capture_screenshot]]; DOM prep from [[attestra/proof/screenshot_redact.py#prepare_page_for_capture]]; catalogue case `T02`.

### Authz test modules

Elite authn/authz/session modules (`T03`–`T07`, `SESSION`) with ``finding_candidate`` → FINDING/PASSED.

Modules under [[attestra/automated_vapt/testing/idor_bola_tests.py]] and siblings cover authentication, BOLA/IDOR, roles, tenant isolation, and API disclosure. [[attestra/automated_vapt/testing/authentication_tests.py#run]] adds account-enumeration differentials and post-clear auth-state checks (no spraying). Horizontal/vertical helpers: [[attestra/automated_vapt/testing/privilege_escalation_tests.py#probe_horizontal_privilege]], [[attestra/automated_vapt/testing/privilege_escalation_tests.py#probe_vertical_privilege]]. Session: [[attestra/automated_vapt/testing/session_security_tests.py#run]]. Phase 3 category map: [[attestra/automated_vapt/testing/coverage_matrix.py#PHASE3_COVERAGE]].

### Safe non-destructive probes

World-Class Phase 3 safe canary modules for injection, XSS, and file traversal (catalogue ids `INJ` / `XSS` / `FILE`), plus header/CORS observation and authn/session expansions under [[architecture#Elite automated security testing#Authz test modules]].

[[attestra/automated_vapt/testing/injection_tests.py#run]] sends benign ``ATTSTRA_CANARY_*`` query values and flags only unencoded HTML reflection. [[attestra/automated_vapt/testing/xss_tests.py#run]] uses a quote-break canary with no stored writes. [[attestra/automated_vapt/testing/file_security_tests.py#run]] probes ``....//attestra-probe-not-a-file`` and requires [[attestra/automated_vapt/testing/file_security_tests.py#detect_sensitive_content]] proof. [[attestra/automated_vapt/testing/information_disclosure_tests.py#run]] adds observation-only security-header/CORS snapshots via [[attestra/automated_vapt/testing/information_disclosure_tests.py#observe_security_headers]] / [[attestra/automated_vapt/testing/information_disclosure_tests.py#observe_cors]]. Pure helpers: [[attestra/automated_vapt/testing/_reflection.py#detect_unencoded_reflection]], [[attestra/automated_vapt/testing/_reflection.py#reflected_unencoded_in_html]]. Coverage statuses: [[attestra/automated_vapt/testing/coverage_matrix.py#PHASE3_COVERAGE]]. Related API input replay remains catalogue ``T21``.

### Validation engine

[[attestra/automated_vapt/validation/vulnerability_validator.py#validate_result]] classifies CONFIRMED/POTENTIAL/NOT_VULNERABLE/INCONCLUSIVE/NEEDS_MANUAL_REVIEW without treating HTTP 200 alone as proof. FP heuristics: [[attestra/automated_vapt/validation/false_positive_checker.py#check_false_positive]].

### Evidence visuals

Two-panel HTTP PNG via [[attestra/automated_vapt/evidence/request_response_renderer.py#render_http_pair_png]]; annotation wraps [[attestra/evidence/annotate.py#annotate_png]]; screenshot association via [[attestra/automated_vapt/evidence/screenshot_manager.py#ScreenshotManager]].

### Evidence integrity

Redaction façade [[attestra/automated_vapt/evidence/evidence_redactor.py#redact_http_pair]]; SHA-256 manifest [[attestra/automated_vapt/evidence/evidence_hasher.py#EvidenceManifest]].

### Burp import

[[attestra/automated_vapt/integrations/burp_importer.py#import_burp_bytes]] reuses [[attestra/importers/burp.py]] and proof pair extraction.

### Finding integration

[[attestra/automated_vapt/integrations/attestra_findings.py#create_finding_from_validation]] creates findings only for CONFIRMED/POTENTIAL with fingerprint dedup.

### Finding evidence documents

When Elite documents a CONFIRMED/POTENTIAL finding, [[attestra/automated_vapt/integrations/attestra_findings.py#document_finding_evidence]] attaches `http_pair` evidence and PNG screenshots (browser captures plus two-panel HTTP visuals from [[attestra/automated_vapt/evidence/request_response_renderer.py#render_http_pair_png]]) via [[attestra/proof/store.py#attach_http_pair]] / [[attestra/proof/store.py#attach_screenshot]]. Technical HTML/PDF/DOCX reports embed those kinds automatically ([[reports#Generation]]).

### Subscription credits

[[attestra/automated_vapt/integrations/subscription_adapter.py#ensure_credit_for_execution]] charges one organization credit per Elite execution when `SUBSCRIPTION_SERVICE=ON`.

### Engagement UI

When enabled, engagement page shows Automated security testing card (queue/run/cancel + history) via [[attestra/automated_vapt/routes.py]] UI routes.

## Phase 7 gated IDOR / request tampering

Intrusive-only object-access probes that plan by default and execute only under the scan scope gate.

[[attestra/auth_web/tamper.py#assert_intrusive_allowed]] requires profile `active` or `intrusive`, then reuses [[attestra/runner/gate.py#policy_input]] / [[attestra/runner/policy.py#decide]] so `intrusive_allowed`, signed authorization environment, ownership, window, and rate limit all apply; refusals raise [[attestra/services.py#ServiceError]]. [[attestra/auth_web/tamper.py#plan_and_maybe_execute_probes]] always builds an [[attestra/auth_web/roles.py#IntrusiveProbePlan]] via [[attestra/auth_web/roles.py#plan_object_access_probes]] (`intrusive=True`). With `execute=False` (default) it returns the plan and never calls `fetch_fn`. With `execute=True` it asserts the gate, caps at five object IDs, paces GETs, stays same-origin to the asset, and never sends exploit payloads or state-changing methods. Results are dicts with `expected` / `observed` / `status` / `redacted`; a sensitive marker redacts the body and stops further probes. Optional synthetic [[attestra/models.py#Finding]] rows (CWE-639) carry confidence and remediation when `create_findings=True`.

### assert_intrusive_allowed

Profile and scope-policy gate before any intrusive IDOR execution.

### plan_and_maybe_execute_probes

Plan-always helper with optional bounded read-only GET execution.

