# Tests

Pytest suite covering importers, scope/authorization logic, business services, the REST API, and compliance+reports. Lives in `tests/`.

## Fixtures

Synthetic data used by both `attestra/cli.py cmd_demo` and the test suite lives in `tests/fixtures/`.

| File | Contents |
| --- | --- |
| `authorization.txt` | Plain-text signed RoE sample |
| `zap.json` | OWASP ZAP traditional-json: 3 alerts (XSS high, CSRF medium, header low) on `https://shop.example.com`; one confidence-0 false-positive that must be skipped |
| `nuclei.jsonl` | Three JSONL findings on `shop.example.com`: CVE-2024-9999 (critical, CVSS 9.8), CVE-2023-1234 (high), TLS cipher (medium) |
| `trivy.json` | Container image `registry.example.com/shop/api`: CVE-2024-9999 and CVE-2023-5678 in packages; DS002 misconfiguration |
| `semgrep.sarif` | SARIF 2.1 with CWE-89 SQL injection on `services/payments/views.py:42` and CWE-78 on `services/payments/tasks.py:87` |
| `kev.json` | CISA KEV catalog with CVE-2024-9999 (matches nuclei and trivy) |
| `epss.csv` | EPSS scores for CVE-2024-9999 (0.97) and CVE-2023-1234 (0.45) |
| `testssl/gaps_r17_r18.json` | SHA224 `cert_signatureAlgorithm` (INFO) plus OCSP stapling not offered with empty `cert_ocspURL` |
| `testssl/gaps_r18_ocsp.json` | OCSP stapling not offered with non-empty `cert_ocspURL` |

## conftest.py

Shared fixtures that isolate each test from real data and from other tests.

- `fresh_db`: patches [[attestra/config.py#DATA_DIR]] and [[attestra/config.py#DATABASE_URL]], resets `db._engine`/`db._SessionLocal` to `None`, and calls [[attestra/db.py#init]] with a fresh `tmp_path` SQLite URL. Disposes the engine on teardown.
- `engagement`: creates an engagement with a valid authorization covering `production`+`staging`, and four assets (web app, container image, two repos).
- `loaded`: extends `engagement` by importing all four fixture tool files and applying KEV+EPSS enrichment.
- `api_credentials` / `auth_headers`: lead + reviewer users with Bearer API keys.
- `client`: wraps `fresh_db` in a `TestClient(app)` with a lead Bearer token; the lifespan's `db.init()` call is a no-op because the engine is already set.

## test_importers.py

Pure parser tests — no database required.

Covers [[attestra/importers/zap.py#parse]], [[attestra/importers/nuclei.py#parse]], [[attestra/importers/trivy.py#parse]], [[attestra/importers/sarif.py#parse]], and the dispatch layer [[attestra/importers/__init__.py#parse]].

Key assertions: ZAP confidence-0 items skipped; multi-instance XSS expands to separate findings; nuclei CVEs and CVSS populated; trivy DS002 misconfiguration gets CWE-16; SARIF CWE-89 present; unsupported tool raises `ValueError`.

## test_testssl_gaps.py

R17/R18 detection-gap coverage for [[attestra/importers/testssl.py#parse]] and [[attestra/runner/scanners/testssl.py#_flags]].

SHA224 INFO yields the fixed weak-signature title (Low, CWE-327); OCSP stapling not offered is emitted only when `cert_ocspURL` is set; baseline argv omits `-U` / `--vulnerable`.

## test_scope.py

Authorization validity, asset URL rules, `match_asset` label-boundary logic, environment-gated import refusal, and duplicate asset detection.

Key assertions: `is_valid()` and `covers()` respect date windows and environment lists; `web_app` without full URL raises `ServiceError`; `staging.shop.example.com` does not match the `shop.example.com` production target; import refused when a matched asset's environment is not authorized; adding the same identifier twice raises `ServiceError`.

## test_services.py

Business-rule tests for [[attestra/services.py]].

Key assertions: import gate refuses without auth; fingerprint dedup on reimport yields zero new findings; KEV enrichment sets `kev=True`; EPSS populates scores; `transition()` enforces the TRANSITIONS graph; `false_positive` and `risk_accepted` require a note; a `fixed` finding reopened on reimport; [[attestra/audit.py#verify]] returns `(True, None)` for untampered chain, `(False, id)` after direct hash mutation.

## test_api.py

HTTP integration tests via `TestClient` (context-manager form, no deprecation warnings).

Key assertions: `GET /api/health` returns `{"status":"ok"}`; write endpoints without Bearer token return 401; engagement created returns 201; findings endpoint returns list with expected shape; `status` filter works; invalid transition returns 409; compliance endpoint returns control list; audit verify endpoint reports chain intact.

## test_compliance_reports.py

Compliance engine rollup, assessor overrides, report generation, four-eyes approval, and report verification.

Key assertions: PCI DSS 4, ISO 27001, SOC 2 evaluations return non-empty lists with valid status values; critical CDE findings drive at least one control to `not_met`; confirmed status overrides engine proposal; unknown framework raises `ValueError`; `generate_report` writes HTML to disk; `approve_report` signs with different actor; same actor rejected by four-eyes rule; `verify_report` confirms hash and HMAC.

## test_migrations.py

Alembic baseline builds an empty SQLite DB whose tables match SQLAlchemy metadata.

Calls `alembic upgrade head` then `downgrade base` via [[attestra/db.py#upgrade]] config paths. Asserts every table in [[attestra/db.py#Base]] metadata appears after upgrade and disappears after downgrade.

## Phase 1 security and runner tests

Comprehensive Phase 1 test coverage in `tests/security/`, `tests/runner/`, `tests/jobs/`, and `tests/e2e/`.

### tests/security/test_authorization.py

Validates [[attestra/runner/authorization.py#authorize_target]], [[attestra/runner/authorization.py#validate_url_target]], [[attestra/runner/authorization.py#validate_image_target]], and [[attestra/runner/authorization.py#assert_safe_cli_arg]] using the `engagement` fixture. Covers off-list host, wrong scheme, path outside prefix, unsafe CLI metacharacters, expired auth via [[attestra/runner/authorization.py#scope_for_engagement]], and exact image match (`nginx:1.25` allowed; `nginx-evil` rejected).

### tests/security/test_ssrf_policy.py

Parametrized tests for [[attestra/runner/authorization.py#is_blocked_ip]] and [[attestra/runner/authorization.py#validate_resolved_ips]]. CGNAT, metadata (169.254.169.254), unspecified (0.0.0.0/8), and IPv4-mapped loopback are all blocked. Public IP 8.8.8.8 passes when `allow_private=False`.

### tests/security/test_dns_pinning.py

Mock resolver tests for [[attestra/runner/dns_pin.py#pin_url]]. Verifies PinnedTarget fields on success; verifies AuthorizationError with "blocked IP" when resolver returns 169.254.169.254 or CGNAT address.

### tests/security/test_redirect_reauth.py

Loopback HTTP server that issues a 302 to `https://evil.example.com`. Asserts `safe_get` with a scope restricting to 127.0.0.1 raises AuthorizationError. Uses manually constructed `AuthorizedScope` with `allow_private=True` and `private_ok_hosts`.

### tests/security/test_zap_pin_egress.py

Tests [[attestra/runner/scanners/zap.py#ZapAdapter]] `build_argv` includes `--add-host host:ip`; and `quarantine_if_out_of_scope` returns a reason string for an extra out-of-scope site, None for in-scope, and "invalid ZAP JSON" for bad bytes.

### tests/runner/test_adapters_argv.py

Verifies argv for trivy, semgrep, nuclei, and zap contains no shell metacharacters. Tests that [[attestra/runner/scanners/base.py#require_digest_image]] raises for floating tags and that each adapter's `image_ref()` raises when `SCANNER_IMAGES` contains a non-digest reference.

### tests/runner/test_scan_run.py

Tests [[attestra/jobs/durable.py#_hash_file]] produces the same hex digest as `hashlib.sha256` for files up to and exceeding 1 MB.

### tests/runner/test_gate.py

Tests [[attestra/runner/gate.py#check]] raises `GateError` for before-window, after-window, expired auth, intrusive profile without flag, and rate limit exceeded. Verifies `scan.refused` audit events are recorded. Tests nuclei active profile is allowed when `intrusive_allowed=True`.

### tests/runner/test_scope_rules.py

Verifies deny rules beat allow-list entries via [[attestra/runner/authorization.py#validate_url_target]]. Verifies [[attestra/services.py#remove_scope_rule]] writes a `scope_rule.remove` audit event.

### tests/jobs/test_durable.py

Covers [[attestra/jobs/durable.py#enqueue]], [[attestra/jobs/durable.py#claim_job]], [[attestra/jobs/durable.py#complete_job]], [[attestra/jobs/durable.py#recover_interrupted_jobs]], and [[attestra/jobs/durable.py#resume_queued_jobs]]. Stale heartbeat jobs (past `JOB_STALE_HEARTBEAT_S`) are re-queued. Jobs whose window has passed are refused on resume.

### tests/jobs/test_kill_switch.py

Spawns a 60-second `python -c "time.sleep"` process via [[attestra/runner/scanners/base.py#run_process]] with a pre-set cancel `threading.Event`; asserts the process is killed and the result has `cancelled=True`.

### tests/e2e/test_runner_e2e.py

`@pytest.mark.integration` tests skipped unless the required tool binary is present. Minimal stubs for trivy fs scan and nuclei argv construction.

## Phase 2 auth tests

Identity, RBAC, tenant matrix, OIDC claim checks, and API security middleware.

### tests/auth/test_keys.py

Covers [[attestra/auth/keys.py#hash_api_key]], revocation via [[attestra/auth/keys.py#revoke_api_key]], password scrypt roundtrip, and four-eyes by user id in [[attestra/reports/render.py#approve_report]] (spoofed actor name cannot bypass).

### tests/auth/test_tenant_matrix.py

Parametrized role permissions plus cross-tenant get/list returning 404 for client viewers and membership-scoped staff.

### tests/auth/test_oidc.py

[[attestra/auth/oidc.py#validate_id_token_claims]] rejects bad nonce, wrong audience, and expired tokens; [[attestra/auth/oidc.py#map_oidc_role]] maps Keycloak roles/groups.

### tests/auth/test_api_security.py

Asserts CSP / X-Frame-Options headers and that [[attestra/api_security.py#RateLimiter]] / [[attestra/api_security.py#RateLimitMiddleware]] return 429 after the limit.

## Phase 3 compliance tests

Library integrity, ASV/segmentation process rules, risk expiry, OWASP mapping, SLA ageing, and quarterly schedules.

### tests/test_library_integrity.py

Fails if any CWE mapping lacks `strength` in `{full, partial}` or a non-empty rationale, or references an unknown objective / untitled control. Asserts Phase 3 PCI/ISO/SOC refs exist.

### tests/test_phase3_compliance.py

Covers ASV → PCI 11.3.2 `met`, risk acceptance expiry reopening findings, CWE-89 → A03, SLA breach listing, scan schedule enqueue, segmentation → 11.4.5, and `iso_soa` / `ageing` report renders.

## Phase 4 report tests

Report workflow, retest false-close, letters, DOCX/PDF, SARIF/OSCAL, packs, and Ed25519 signing.

### tests/test_report_workflow.py

Reject loop; same user cannot QA their own draft; three distinct actors for submit → QA → sign with role enforcement on sign.

### tests/test_retest_false_close.py

[[attestra/retest.py#finalize_retest]] never returns `fixed` when the ScanRun targeted a different asset; returns `fixed` when asset ids match.

### tests/test_phase4_exports.py

Closure/attestation letters (no finding IDs), DOCX/PDF sha storage, SARIF structure, OSCAL min schema, framework pack zip, executive trend SVG, signature verify.

## Phase 5 evidence hardening

Masking corpus, storage immutability, retention purge, append-only audit, backup manifests, and offline feed refresh.

### Masking corpus

Generated corpus of 1,000 PAN/credential strings leaves zero unmasked; non-Luhn digit strings untouched ([[tests/evidence/test_mask_corpus.py]]).

### Storage immutability

[[attestra/storage/local.py#LocalStorage]] refuses overwrite of differing content; identical puts are idempotent.

### Evidence masking wired

[[attestra/services.py#add_evidence]] stores masked bytes and records `masking_applied`.

### Retention purge

[[attestra/ops/retention.py#purge_expired]] deletes only expired items, audits each deletion, and keeps reports under `legal_hold`.

### Append-only audit

SQLite triggers abort UPDATE on `audit_events`.

### Download audit

Evidence download creates an `evidence.download` audit event.

### Audit export

`GET /api/audit/export` returns JSON/CSV with chain proof fields.

### Backup restore

[[attestra/ops/backup.py#backup]] writes `manifest.json`; tampered restore raises [[attestra/ops/backup.py#BackupError]].

### Feed refresh offline

[[attestra/ops/feeds.py#refresh_feeds]] with fixture files (mocked download) populates catalog dates and enrich counts.
