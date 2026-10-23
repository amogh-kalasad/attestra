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
| `testssl/gaps_r17_handshake.json` | Strong cert ECDSA SHA384 plus `FS_TLS12_sig_algs` offering SHA1 (C8 handshake R17) |
| `testssl/gaps_strong.json` | All-strong TLS protocols/ciphers/certs for empty finding + summary coverage |
| `testssl/gaps_expired.json` | CRITICAL `cert_expirationStatus` expired certificate |
| `testssl/engine_problem.json` | WARN `engine_problem` GOST/engine note plus one real TLS1 finding |
| `burp/burp_issues.xml` | Hand-made Burp Issues XML: SQLi + XSS on `shop.example.com`, one out-of-scope host |
| `burp/xxe_billion_laughs.xml` | Hostile entity-expansion XML that must be refused |
| `nessus/sample.nessus` | Hand-made Nessus v2: TRACE + SSL + service info + 19506 note; one out-of-scope host |
| `nessus/xxe_billion_laughs.nessus` | Hostile entity-expansion Nessus XML that must be refused |

## conftest.py

Shared fixtures that isolate each test from real data and from other tests.

- `fresh_db`: patches [[attestra/config.py#DATA_DIR]] and [[attestra/config.py#DATABASE_URL]], resets `db._engine`/`db._SessionLocal` to `None`, and calls [[attestra/db.py#init]] with a fresh `tmp_path` SQLite URL. Disposes the engine on teardown.
- `engagement`: creates an engagement with a valid authorization covering `production`+`staging`, and four assets (web app, container image, two repos).
- `loaded`: extends `engagement` by importing all four fixture tool files and applying KEV+EPSS enrichment.
- `api_credentials` / `auth_headers`: lead + reviewer users with Bearer API keys.
- `client`: wraps `fresh_db` in a `TestClient(app)` with a lead Bearer token; the lifespan's `db.init()` call is a no-op because the engine is already set.

## test_importers.py

Pure parser tests ÔÇö no database required.

Covers [[attestra/importers/zap.py#parse]], [[attestra/importers/nuclei.py#parse]], [[attestra/importers/trivy.py#parse]], [[attestra/importers/sarif.py#parse]], and the dispatch layer [[attestra/importers/__init__.py#parse]].

Key assertions: ZAP confidence-0 items skipped; multi-instance XSS expands to separate findings; nuclei CVEs and CVSS populated; trivy DS002 misconfiguration gets CWE-16; SARIF CWE-89 present; unsupported tool raises `ValueError`.

## test_testssl_gaps.py

R17/R18 detection-gap coverage for [[attestra/importers/testssl.py#parse]] and [[attestra/runner/scanners/testssl.py#_flags]].

SHA224 INFO yields the fixed weak-signature title (Low, CWE-327); OCSP stapling not offered is emitted only when `cert_ocspURL` is set; baseline argv omits `-U` / `--vulnerable`.

## test_site_grade.py

Phase 1 Observatory-style site grade helpers in [[attestra/grade.py#score_from_findings]], [[attestra/grade.py#grade_from_score]], and [[attestra/grade.py#MODIFIERS]].

### All good scores A

No findings keeps score 100 and grade A+.

### Missing CSP HSTS TLS legacy

Missing CSP, missing HSTS and TLS 1.0 together score 35 (D).

### Expired cert caps F

An expired certificate sets cap_f so the letter is F.

### False positive ignored

False-positive findings do not take points off.

### Bonus only above 90

Bonuses are skipped when the running score is below 90.

### Grade band edges

Band edges match A+, A, A-, B+, B, B-, D-, F including cap_f.

### Modifiers table present

The MODIFIERS table includes csp_missing at -25 and the grade band list starts at A+.

## test_sites_dashboard.py

Phase 12 sites dashboard: tenant list, open counts, trend, sort, and live HarmonyPM check for [[attestra/services.py#list_tenant_sites]].

### Tenant isolation

API and `/sites` show only the signed-in tenant’s targets.

### Counts and trend

Open severity counts match findings; trend is up then down across finished scans; cancelled scans do not drive trend.

### Not graded and single scan

No finished scan → not graded and trend dash; one finished scan → graded with trend dash; failed-only stays not graded.

### Sort worst grade first

Default sort puts F before A.

### Live data HarmonyPM

Temp copy of the live DB: HarmonyPM rows render on `/sites` with grade, last scan, counts, and trend.

## test_asset_history.py

C11 per-target history helpers in [[attestra/history.py#diff_fingerprints]], [[attestra/history.py#scan_letter_grade]], and [[attestra/history.py#trend_svg]].

### Diff new fixed still-open

Two fingerprint sets where one finding is fixed and one is new give fixed=1, new=1, still-open=the rest.

### Letter grades A through F

AÔÇôF grade follows critical/high/medium thresholds.

### Trend svg renders

`trend_svg` returns an SVG comparing current and previous severity bars.

## test_webcheck_dns.py

Mocked DNS posture tests for [[attestra/runner/scanners/webcheck_dns.py#dns_checks]] and [[attestra/runner/scanners/webcheck_dns.py#dns_posture]] (CAA/AAAA/SPF/TLSA plus email and DNSSEC). Never uses live DNS.

### Email DNS severities and N/A

DMARC/DKIM/MTA-STS/TLS-RPT/DNSSEC findings use the prompt severities; no MX marks email checks not applicable; out-of-scope apex skips lookups.

### DKIM selectors and MTA-STS fetch gate

DKIM queries only the fixed selector list; MTA-STS policy is fetched once and only when `mta-sts.<apex>` is in scope.

### Fingerprint stable across runs

The same mocked answers produce identical finding fingerprints on two runs.

## test_csp_policy.py

C10 CSP analysis for [[attestra/runner/scanners/webcheck.py#check_csp_policy]] and ZAP alertRef fingerprint merge.

### Strong policy yields no findings

A tight CSP produces no findings and a passed check row.

### Unsafe-eval http and wildcard

`script-src` with `'unsafe-eval'`, `http://x.com` and `*` yields three findings with the right evidence.

### Missing required directives

CSP with only `default-src` flags missing `object-src`, `base-uri` and `frame-ancestors`.

### Webcheck and ZAP CSP fingerprints merge

webcheck unsafe-eval and ZAP 10055-10 share the same fingerprint via alertRef variant.

## test_cookie_flags.py

C9 cookie flag coverage for [[attestra/runner/scanners/webcheck.py#check_cookies]] and multi Set-Cookie handling in [[attestra/runner/http_safe.py#safe_request]].

### Two cookies three missing flags

One cookie missing Secure and another missing HttpOnly and SameSite yield three findings with session Low vs non-session Info.

### Fully flagged cookie is passed

A cookie with Secure, HttpOnly and SameSite yields no finding and a C5 passed row.

### No cookies is skipped

No Set-Cookie header yields a skipped not-tested row and no findings.

### Evaluate primary includes cookie checks

`evaluate_primary` merges cookie findings and failed check rows.

### Importer keeps cookie variant

The webcheck importer stores `cookie:{name}:{flag}` as the finding variant.

### Http_safe keeps multiple set-cookie

`safe_request` joins multiple Set-Cookie response headers with newlines.

## test_fix_snippets.py

Phase 10 library fix text: importance, effort, fix steps and nginx/Apache/IIS/Cloudflare snippets on header/TLS/cookie/CSP writeups.

### Header TLS cookie CSP seed fields present

Every header/TLS/cookie/CSP seed writeup has non-empty importance, effort, fix steps and four server snippets.

### Snippet syntax sanity

nginx directive lines end with `;` and IIS snippets parse as XML.

### Report picks server snippet

A known server type keeps one snippet; unknown server type shows nginx and Apache.

### Finding page and report render with and without

Finding page and technical report show snippets when present and still render when fix fields are empty.

### API finding includes fix fields

`GET /api/engagements/{eid}/findings` always includes the fix fields; matched header findings are non-empty.

### Empty fix fields still render

Legacy library rows with blank fix columns serialize and update without error.

### Live HarmonyPM report snippets

On a temp live DB copy, the HarmonyPM technical report includes fix snippets for header findings.

## test_finding_comments.py

Phase 17 finding comment threads: API/UI add-list-delete, roles, XSS escape, audit, and exclusion from share/default report.

### API add list delete

API create/list/soft-delete round-trip on a finding for an authorized writer.

### UI add list delete and XSS

UI form posts escape HTML in comment bodies and support soft-delete from the finding page.

### Other tenant denied

Cross-tenant principals cannot list or add comments on another tenant's finding.

### Read-only cannot delete others

Reviewers and auditors cannot delete another user's comment.

### Audit rows

Add and delete write `finding.comment.added` and `finding.comment.deleted` audit rows.

### Absent from share and default report

Comment bodies never appear in [[attestra/comments.py#finding_fields_for_share]] or default technical report HTML (`include_comments` off).

### Live HarmonyPM comment

Optional offline note against a HarmonyPM DB copy; skipped when that copy is not present.

## test_safe_browsing.py

Phase 13 Google Safe Browsing lookup via [[attestra/runner/scanners/safe_browsing.py#check_safe_browsing]] (mocked HTTP; key never logged).

### No key skips with note

Flag on without `ATTESTRA_GSB_API_KEY` adds the skip note, a skipped check, and makes zero HTTP calls.

### Off by default

With the flag unset, the check is silent even when a key is present (no note, no network).

### Listed yields high finding

Mocked matches for MALWARE / SOCIAL_ENGINEERING yield one High finding and a failed check.

### Clean yields passed check

Empty API matches yield the passed check `Not on Google Safe Browsing list`.

### API error is a note

Timeouts and API failures become a scan note and skipped check; the fake key is stripped from the note.

### Key never in logs or report

Captured logs and a saved `webcheck.json` never contain the fake key `TESTKEY123`.

### Batch one request

Several URLs produce a single POST whose `threatEntries` lists every URL.

### Mask secret helper

[[attestra/runner/scanners/safe_browsing.py#mask_secret]] replaces the raw key in strings.

### Importer keeps variant

The webcheck importer stores `webcheck/safe-browsing` with variant `safe-browsing`.

## test_sri_mixed_content.py

Phase 14 SRI and mixed-content checks on already-fetched HTML via [[attestra/runner/scanners/webcheck.py#check_sri]] and [[attestra/runner/scanners/webcheck.py#check_mixed_content]].

### Bad SRI yields finding

External script/style without integrity yields one Medium SRI finding listing both CDN URLs.

### Integrity present is clean

Cross-origin tags with integrity yield no SRI finding and a passed check.

### Good page passes SRI and mixed

A page with relative assets and integrity-backed CDN links passes both SRI and mixed-content checks.

### Active mixed content

An https page with `http://` script/style/iframe yields active mixed content (Medium).

### Passive mixed content

An https page with `http://` image/media yields passive mixed content (Low).

### Relative and protocol-relative

Relative URLs need no SRI; protocol-relative `//cdn` is treated as https on https pages (SRI may still apply; not mixed content).

### Http page skips mixed content

Mixed-content checks are skipped when the page scheme is http.

### Fingerprints stable across runs

SRI and mixed-content fingerprints stay stable per target and finding type across runs and URL list changes.

### Importer keeps sri variant

The webcheck importer stores `sri` / `mixed-content-*` as the finding variant.

### Evaluate primary wires body

`evaluate_primary` with `body=` merges SRI/mixed findings; without `body` those checks are omitted.

### Evidence caps at twenty URLs

Evidence lists at most 20 URLs then `... and N more`.

### Scan request count unchanged

HTML SRI/mixed checks do not add HTTP requests beyond the usual webcheck set.

## test_http_redirect.py

HTTP → HTTPS upgrade checks for [[attestra/runner/scanners/webcheck.py#check_http_no_redirect]] and grade key `http_no_https_redirect`.

### 301 same host passes

301 to https:// on the same host yields no finding.

### 308 same host passes

308 to https:// on the same host yields no finding.

### 302 temporary low

302 to https:// on the same host is Low temporary redirect.

### 307 temporary low

307 to https:// on the same host is Low temporary redirect.

### Other host low

HTTPS Location on a different host is Low other-host.

### Http target medium

Redirect to http:// is Medium.

### 200 no redirect medium

HTTP 200 with no redirect is Medium does-not-redirect.

### Connection refused passed

No HTTP answer yields note `HTTP not served` and no finding.

### Grade penalty on no redirect

`http_no_https_redirect` is −20 for no-upgrade and other-host; temporary same-host HTTPS does not take that penalty.

### Adapter one request redirects off

WebcheckAdapter sends exactly one http:// request with `follow_redirects=False` and stores Location.

### Out of scope not requested

When plain HTTP is refused by scope, no http:// request is sent and the check is skipped.

### Adapter connection refused passed

Connection refused on the http probe marks the upgrade check passed with `HTTP not served`.

### Live data HarmonyPM offline

Stored HarmonyPM webcheck.json http:// 301 is classified offline with no new network request.

## test_testssl_c8.py

C8 TLS coverage for handshake R17, expiry titles, and [[attestra/importers/testssl.py#summarize]].

### Handshake R17 when cert is strong

Strong cert ECDSA SHA384 with handshake offering SHA1 yields one Low finding with variant `handshake`.

### Strong TLS yields no findings

All-strong fixture produces an empty finding list.

### Expired certificate finding

CRITICAL `cert_expirationStatus` becomes a clear expiry finding.

### TLS summary from strong fixture

`summarize()` fills protocols, best/weakest cipher, cert expiry, chain, signatures and OCSP.

### TLS summary empty means not scanned

Empty input yields `scanned=False` for the report "not scanned" row.

### Cert and handshake R17 can both show

Weak cert signature and weak handshake hashes produce two findings with different variants.

## test_burp_nessus.py

Burp Issues XML and Nessus `.nessus` importers: fields, notes, scope skip, XXE refuse, re-import.

### Burp fixture fields

Hand-made Burp XML yields SQL injection (high) and XSS (medium) on `shop.example.com` with request evidence in the description.

### Nessus fixture fields

Hand-made `.nessus` maps plugin id, severity 0–4, CVE/CVSS and `host:port` location; plugin 19506 is absent from findings.

### Nessus scan info is a note

[[attestra/importers/nessus.py#extract_notes]] keeps plugin 19506 text; parse does not emit it as a finding.

### Reimport same fingerprints

Re-parsing Burp and Nessus fixtures produces identical fingerprint sets with no collisions inside one file.

### XXE refused

Billion-laughs Burp and Nessus fixtures raise `ValueError` from [[attestra/importers/_xmlutil.py#parse_xml]].

### Out of scope hosts skipped

[[attestra/services.py#import_results]] imports only in-scope Burp/Nessus hosts, counts the rest in `unmatched_findings`, and stores Nessus scan-info on `notes_json`.

### Reimport no duplicates

Second Burp import merges the same fingerprints with zero new findings.

### Dispatch registry

[[attestra/importers/__init__.py#parse]] accepts tool keys `burp` and `nessus`.

## test_testssl_engine_note.py

Phase 3: testssl scanner diagnostics are import/scan notes, not findings.

### Engine problem is not a finding

Fixture with `engine_problem` WARN plus TLS1: parse yields only TLS1; [[attestra/importers/testssl.py#extract_notes]] keeps the GOST/engine text.

### Import stores notes not findings

[[attestra/services.py#import_results]] writes GOST/engine text to `notes_json` and does not create an `engine_problem` finding row.

## test_caa_merge.py

R15: webcheck `dns-caa` and testssl `DNS_CAArecord` merge through the shared CAA fingerprint.

### Canonical CAA fingerprints match

[[attestra/fingerprint.py#canonicalize_for_merge]] maps both tool variants to the same key (variant `dns-caa`, CWE-16, bare host).

### Import both tools one finding

Importing webcheck then testssl CAA reports leaves one finding whose `tools` list is both `webcheck` and `testssl`.

### Legacy testssl CAA still merges

An older `DNS_CAArecord` fingerprint (`host:port` + param) is adopted and upgraded when webcheck `dns-caa` is imported.

## test_site_grade.py

Unit tests for the Observatory-style site grade in [[attestra/grade.py]].

### All good scores A

No open findings keeps score 100 and grade A+.

### Missing CSP HSTS TLS legacy

Missing CSP, HSTS and legacy TLS together drop the score into the D band.

### Expired cert caps F

An expired certificate sets the F cap even when other scores are high.

### False positive ignored

Findings marked false_positive do not change the score.

### Bonus only above 90

Positive modifiers only apply when the score is already at least 90.

### Grade band edges

Letter bands and the F cap match the documented cutoffs.

### Modifiers table present

`MODIFIERS` and `GRADE_BANDS` expose the expected CSP penalty and A+ band.

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

## test_cancel_scan_typo_ui.py

Phase 7 cancel scan, portal typo check, and the four partly-fixed UI audit points (tests/test_cancel_scan_typo_ui.py).

### Cancel queued scan

[[attestra/services.py#cancel_scan]] on a queued scan sets status `cancelled`, ends the run, and writes `scan.cancelled`.

### Cancel running signals stop

Cancelling a running scan calls [[attestra/jobs/durable.py#signal_job_cancel]] so the in-flight adapter Event is set.

### Cancel refused finished tenant role

Finished scans return 409; other-tenant and read-only roles are refused.

### Cancel sends no finished webhook

A cancelled scan does not queue `scan.finished` deliveries ([[attestra/webhooks/service.py#safe_emit_scan]]).

### Protal gone from seed

Seed, demo, templates and fixtures contain no `protal` string.

### UI points six forty-seven fifty-five eighty-seven

Read-only HTML POST redirects to the portal; edit renames client and engagement; finding detail and FP tool drill-down pages render.

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

## Phase 2 bug fixes

Regression coverage for invite email hints, SoA/PDF display, and workflow-rule soft-deactivate (tests/test_phase2_bugs.py).

### Known emails skip revoked used invites

[[attestra/alerts/service.py#known_tenant_emails]] returns only unused, non-revoked invite emails for a tenant.

### iso_soa framework display name

Generated iso_soa HTML shows the library framework display name, not the raw key `iso_27001_2022`.

### PDF human times use display TZ

[[attestra/reports/pdf.py#_human_times]] formats timestamps in `ATTESTRA_DISPLAY_TZ` including the zone abbreviation.

### Workflow rule deactivate

`DELETE /api/workflow-rules/{id}` and `POST /api/workflow-rules/{id}/deactivate` both set `active=False`; [[attestra/webhooks/service.py#rule_matches]] then returns false.

## CLI key and user admin

Local CLI coverage for API key list/revoke and lead-scoped user disable.

### tests/test_cli_keys_users.py

Checks `attestra key list` and `attestra key revoke` (including the `api_key.revoke` audit row), `attestra user disable` for a lead disabling a same-tenant reviewer, and that a lead cannot disable another lead.

## Phase 3 compliance tests

Library integrity, ASV/segmentation process rules, risk expiry, OWASP mapping, SLA ageing, and quarterly schedules.

### tests/test_library_integrity.py

Fails if any CWE mapping lacks `strength` in `{full, partial}` or a non-empty rationale, or references an unknown objective / untitled control. Asserts Phase 3 PCI/ISO/SOC refs exist.

### tests/test_phase3_compliance.py

Covers ASV ÔåÆ PCI 11.3.2 `met`, risk acceptance expiry reopening findings, CWE-89 ÔåÆ A03, SLA breach listing, scan schedule enqueue, segmentation ÔåÆ 11.4.5, and `iso_soa` / `ageing` report renders.

## Phase 4 report tests

Report workflow, retest false-close, letters, DOCX/PDF, SARIF/OSCAL, packs, and Ed25519 signing.

### tests/test_report_workflow.py

Reject loop; same user cannot QA their own draft; three distinct actors for submit ÔåÆ QA ÔåÆ sign with role enforcement on sign.

### tests/test_retest_false_close.py

[[attestra/retest.py#finalize_retest]] never returns `fixed` when the ScanRun targeted a different asset; returns `fixed` when asset ids match.

### tests/test_phase4_exports.py

Closure/attestation letters (no finding IDs), DOCX/PDF sha storage, SARIF structure, OSCAL min schema, framework pack zip (including sealed-path rebuild), executive trend SVG, signature verify.

## Phase 4 market exports

PDF engine probe, OSCAL AR/POA&M validation, Word re-export, JSON engagement export, and XLSX sheets ([[tests/test_phase4_market_exports.py]]).

### PDF engine status probe

[[attestra/reports/pdf.py#pdf_engine_status]] returns `available`, `engine` (`weasyprint`|`xhtml2pdf`|`none`), and a clear install message when neither engine loads.

### Health PDF engine fields

`GET /api/health` includes `pdf`, `pdf_engine`, and `pdf_message` from [[attestra/reports/pdf.py#pdf_engine_status]] so admins see a clear missing-engine message.

### API and UI Excel JSON routes

`GET /api/engagements/{eid}/export/xlsx` and `/export/json` return the workbook and JSON payload; engagement page links and UI routes download the same formats.

### OSCAL AR and POA&M schema validation

Min schema plus [[attestra/reports/oscal.py#schema_for_oscal_kind]] validates assessment-results and POA&M exports; deliberately broken docs yield nested-key errors.

### Word re-export twice every kind

Calling [[attestra/reports/export.py#export_report_formats]] twice for every [[attestra/reports/render.py#KINDS]] yields DOCX bytes starting with `PK` without error.

### JSON engagement export shape

[[attestra/reports/engagement_export.py#export_engagement_json]] includes version fields, engagement (VA + PT label), findings, controls, evidence, and reports; audits `engagement.exported` with `format=json`.

### JSON engagement export evidence metadata only

Evidence rows expose only kind/filename/sha256/note/finding_id — never body, path, bytes, or content keys.

### JSON engagement export formula and secret absence

Secrets from evidence bodies do not appear in the JSON dump; formula-like finding titles stay plain strings (no CSV quote-prefix).

### XLSX three sheets

[[attestra/reports/xlsx_export.py#export_engagement_xlsx]] workbook has Findings, Controls, and Evidence sheets with expected headers, freeze panes, and auto-filter.

### XLSX formula guard

A finding title of `=cmd()` is prefixed with a single quote in the Findings sheet so Excel does not treat it as a formula.

### XLSX evidence metadata only

Evidence sheet lists metadata only; evidence body bytes and secrets never appear in the workbook.

### XLSX export audit

[[attestra/reports/xlsx_export.py#export_engagement_xlsx]] records `engagement.exported` with `format=xlsx`.

## Phase 1 stability

Medium export bugs and UX fixes from the Gap Implementation Plan.

### Report re-export succeeds

Exporting the same report to DOCX/PDF twice succeeds; the sealed HTML hash is unchanged.

### CSV target column filled

Findings CSV includes the linked asset identifier (for example shop.example.com) in the target column.

### Shared ISO and SOC 2 sample sizes

[[attestra/services.py#default_sample_size]] and the SOC 2 path both match [[attestra/compliance/sampling.py#sample_size_for]] for representative population sizes.

## Phase 0 integrity

Critical integrity and security fixes from the Gap Implementation Plan (auditor confirm ownership, open-finding met block, risk-acceptance record, share untested grade, metrics auth, risk-acceptance partial evidence).

### Auditor ownership of confirmations

Lead role cannot confirm or overwrite; auditor can confirm. Refused attempts are audited as `control.confirm_refused` (API returns 403).

### Block met with open findings

Confirming `met` with open mapped critical/high/medium findings raises and names those findings unless an explicit override is passed; low/info alone do not block; override rationale is stored.

### Risk acceptance record required

Bare `transition` to `risk_accepted` is refused; [[attestra/services.py#accept_risk]] creates the record and status together (API, UI, and CLI `accept-risk`).

### Share untested grade

A public share for a target with no scan or findings shows "Not yet tested" with no letter grade on the page and badge.

### Metrics require auth

Unauthenticated `GET /metrics` returns 401 unless a bearer token or anon opt-in is configured.

### Risk acceptance is partial evidence

A single risk acceptance does not propose SOC 2 CC3.2 or DORA Art.6 as `met`.

## Report coverage enhancements

Stored-not-rendered DOCX Phase 1 fields, retest report kind, nine-framework load, and template metadata.

### Stored fields rendered in technical report

Technical HTML includes document control, environment, test types/standards, CVSS vector, OWASP/ASVS/WSTG, findings overview, disclaimer, conclusion, and DRAFT mark when those fields are populated.

### Retest report kind

`retest` is a registered kind; a finalized retest appears with result and unresolved-risk section without claiming historical evidence was overwritten.

### Nine frameworks load

`load_library()` exposes the three built-ins plus six packs (ISO 42001, CERT-In, NIST CSF 2, RBI, SEBI, DORA); each can render a compliance report.

### Template config metadata

[[attestra/reports/template_config.py#load_template_config]] lists all five assessment types and nine frameworks and defines the `retest` kind sections.

## Phase 3 reports

Template, evidence, branding, and Word/PDF gaps for technical and related report kinds ([[tests/test_phase3_reports.py]]).

### Change column in document control

Document-control tables on technical and retest reports include a Change column (history rows carry a change label; missing values show an em dash).

### Screenshots end-to-end

Attaching a tiny PNG screenshot embeds Fig. captions and data:image in technical HTML; DOCX contains a drawing/image part; PDF export completes without crash (text assert soft when pypdf missing).

### List of figures

Technical reports expose a List of figures section and TOC link built from screenshot captions via [[attestra/reports/render.py#_figures_list]].

### Risk legend in Word

Technical and executive DOCX exports include Risk rating / CVSS range text; executive HTML gets a legend injected by [[attestra/reports/docx_export.py#_ensure_risk_legend]] when absent.

### Impact affected URLs references

When a finding has impact, affected_urls, or references set, the technical finding detail renders those rows/sections.

### HTTP request response in report

`http_pair` evidence is hash-verified, defensively re-masked, pretty-printed under each finding as `pre.http-pair` without leaking stored secrets ([[attestra/reports/render.py#_http_pair_embeds]]).

### Logo on cover

A ReportTemplate logo PNG appears as a data:image on the technical cover along with the cover title.

### Disclaimer branding override

A tenant ReportTemplate disclaimer override replaces the template-config default in the technical disclaimer section.

### DOCX TOC update note

Styled Word TOC page instructs readers to right-click / Update Field or use References › Update Table.

### Finding fields round-trip

Library apply fills empty impact and references; affected_urls round-trip through [[attestra/api.py#_finding_dict]]; description compose fallback still includes Impact.

### CVSS vector validation

[[attestra/scoring.py#validate_cvss_vector]] accepts empty and CVSS 3.x vectors and rejects garbage; [[attestra/scoring.py#soft_cvss_vector]] clears bad import values.

### History change key

[[attestra/reports/render.py#_report_history]] rows include a `change` string derived from status (for example Submitted for QA).

### Date check before window

[[attestra/reports/render.py#generate_report]] raises ServiceError when today is before engagement `window_start`; missing window start still allows generate.

### Front back matter

Technical reports include distribution, sign-off placeholders, and an appendix; methodology and conclusion stay in the TOC.

Distribution rows come from [[attestra/reports/render.py#_distribution_list]] (tenant contact plus authorized recipients). The in-report sign-off table has Author/QA/Approved placeholders; live status remains the Attestra sign-off banner. The appendix lists tool imports and scan runs.

## Phase 5 workflow

Finding assignment, ticket two-way sync, outbound webhooks, AI key hygiene, ownership token reuse, and optional GRC push ([[tests/test_phase5_assignment.py]], [[tests/test_phase5_tickets.py]], [[tests/test_phase5_webhooks.py]], [[tests/test_phase5_ai.py]], [[tests/test_phase5_ownership.py]], [[tests/test_phase5_grc.py]]).

### Assign and audit

[[attestra/assignments.py#assign_finding]] inserts a [[attestra/models.py#FindingAssignment]] and writes a `finding.assigned` audit row with the assignee.

### Unassign and audit

[[attestra/assignments.py#unassign_finding]] clears the current assignee (`assignee=""`) and writes `finding.unassigned`; [[attestra/assignments.py#current_assignee]] then returns `None`.

### Assigned-to-me filter

[[attestra/assignments.py#findings_assigned_to]] returns only findings whose current assignee matches the username (unassigned and other assignees excluded).

### Reject cross-tenant or unknown user

Assign rejects unknown usernames and users outside the finding tenant; platform `admin` and same-tenant memberships are allowed.

### AI key never in drafts or errors

With OpenAI provider enabled via env, the API key is sent only in the Authorization header and never appears in draft JSON, logs, `repr()`, or scrubbed exception messages.

### AI defaults to ollama when unset

When `ATTESTRA_AI_NARRATIVES=on` and `ATTESTRA_AI_PROVIDER` is unset, [[attestra/ai_narratives.py#provider_from_env]] builds Ollama; the feature stays off unless narratives are explicitly on.

### Ownership token set clears verification

[[attestra/services.py#set_ownership_token]] changes the token, clears `ownership_verified_at`, and audits `asset.ownership_token_set` with a four-character suffix only.

### Ownership token format rejected

Empty, short, or non-urlsafe tokens raise [[attestra/services.py#ServiceError]].

### Ownership reuse same token no clear

Saving the same token again leaves `ownership_verified_at` unchanged.

### Ownership target page routes

Target page shows set-token and Verify now forms; POSTs redirect back to the target with flash messages.

### Jira create via mock HTTP

[[attestra/integrations/tickets.py#client_from_env]] builds a Jira client; [[attestra/integrations/tickets.py#sync_ticket]] posts once and stores `jira:<key>`.

### GitHub create via mock HTTP

GitHub Issues create via injected HTTP mock stores `github:<repo>#<number>` on the finding.

### Webhook closed fixes and requests retest

When a closed webhook successfully transitions a validated finding to `fixed`, [[attestra/integrations/tickets.py#apply_ticket_state]] ensures a pending [[attestra/retest.py#request_retest]] and audits `finding.ticket_retest`.

### Disallowed transition stays audit only

A closed ticket on a `new` finding is audit-only (`finding.ticket_state`, `applied=False`); status and retests stay unchanged.

### Webhook signature still required

`POST /api/integrations/tickets/{backend}/webhook` returns 404 without `ATTESTRA_TICKETS_WEBHOOK_SECRET`, 401 on bad HMAC, and 200 when the signature matches.

### Unknown backend and disabled stay safe

Empty `ATTESTRA_TICKETS_BACKEND` disables sync; unknown backend names raise [[attestra/integrations/tickets.py#TicketError]]; unknown webhook paths return 404.

### ServiceNow and Azure DevOps stubs

`servicenow` and `azure_devops` are registered in [[attestra/integrations/tickets.py#BACKENDS]]; `from_env` raises until required env vars are set, then minimal `create()` works behind HTTPS mocks.

### Existing open retest is not duplicated

If an unfinalized retest already exists, a successful ticket→`fixed` transition does not create another.

### GRC off by default

[[attestra/integrations/grc.py#connector_from_env]] returns None when `ATTESTRA_GRC_BACKEND` is unset.

### GRC push signed metadata

Enabled connector POSTs report id/sha256/kind/signed_at/download hint with HMAC signature; secret never logged or audited in full.

### GRC safe push no-op when off

[[attestra/integrations/grc.py#safe_push_grc_report]] returns None without auditing when the backend is unset.

### GRC rejects unsigned

Push raises when the report is not signed or the backend name is unknown.

### GRC connector names

Vanta, Drata, and Sprinto factories share [[attestra/integrations/grc.py#WebhookGrcConnector]]; `repr` hides the secret.

### Successful signed delivery

[[attestra/webhooks/service.py#deliver]] marks status `delivered`, sends `X-Attestra-Signature` / `X-Attestra-Timestamp`, and [[attestra/webhooks/formats.py#verify]] accepts the body.

### Retry backoff then failed

A non-2xx response keeps status `pending`, sets `next_attempt_at` from [[attestra/webhooks/service.py#BACKOFF_SECONDS]], and increments attempts; after [[attestra/webhooks/service.py#MAX_ATTEMPTS]] the delivery is `failed`.

### Inactive endpoint fails cleanly

Private destination URLs are refused at create time; a deactivated endpoint fails delivery with `endpoint inactive` and never calls the sender.

### Verify rejects bad signature and expired timestamp

[[attestra/webhooks/formats.py#verify]] returns false for a wrong MAC, wrong secret, mutated body, non-digit timestamp, or timestamp outside the tolerance window.

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

## Engagement type label

Display label for stored type key `vapt` is `VA + PT`; reports must not print the legacy acronym.

### Maps key and legacy label

[[attestra/models.py#normalize_engagement_type]] and [[attestra/models.py#engagement_type_label]] map `vapt` and the old string that lowercases to `vapt (va + pt)` to the new label.

### Create accepts legacy label

[[attestra/services.py#create_engagement]] accepts the old label and stores the canonical key `vapt`.

### No legacy acronym in report titles

Rendered technical, executive, compliance, closure, and attestation reports for a `vapt` engagement contain `VA + PT` and never the legacy acronym.

## Feature tests

Test modules for features added on top of the core flow. Each line says what the file checks.

- `tests/test_ai_narratives.py`: AI drafts are off by default, never touch the network unless set up, hide evidence, need tester approval, and can be turned off per tenant.
- `tests/test_phase5_ai.py`: OpenAI API key never appears in drafts, logs, or errors; default provider is Ollama when unset; feature still off unless narratives are on.
- `tests/test_phase5_ownership.py`: set/reuse ownership token clears verification, audits suffix only, and target-page Verify now routes work.
- `tests/test_phase5_grc.py`: GRC webhook push is off by default, posts signed report metadata only, and never logs the webhook secret.
- `tests/test_ai_routes.py`: AI draft pages and API return 404 when off, and only approved drafts reach a report.
- `tests/test_ai_drafts_page.py`: the AI drafts page uses the normal layout, shows a friendly off message, and asks before Reject.
- `tests/test_c7_c11_mapping_soc2.py`: mapping strength and reason show in compliance output, and SOC 2 Type II sampling is repeatable.
- `tests/test_c9_c10_pci_iso.py`: ASV import, PCI calendar, segmentation records, ISO SoA, nonconformity and corrective action, and audit sampling.
- `tests/test_control_libraries.py`: PCI, ISO and SOC 2 crosswalks cover every objective, and OSCAL and SCF control libraries import correctly.
- `tests/test_iso42001_pack.py`: the ISO/IEC 42001 pack loads with all 38 Annex A items, clauses 4 to 10, and the LLM Top 10 map.
- `tests/test_phase8_framework_packs.py`: extra framework packs load from YAML, bad packs are refused, and reports render them.
- `tests/test_phase8_library_certin.py`: CERT-In 2022 pack titles and compliance, findings-library JSON/CSV template import, and idempotent seed.
- `tests/test_findings_library.py`: the findings library (search, add, apply without overwrite) and tenant report templates with a safe sandbox.
- `tests/test_fix_snippets.py`: header/TLS/cookie/CSP library entries carry importance, effort, fix steps and four server snippets; finding page, report and API show them; empty fields still render.
- `tests/test_fingerprint_variant.py`: an empty `variant` keeps the fingerprint exactly the same as before the field existed.
- `tests/test_phase7_importers.py`: Prowler, kube-bench, testssl.sh, Gitleaks, Checkov and naabu parsers; Gitleaks never keeps the secret.
- `tests/test_phase5_tickets.py`: Jira/GitHub mock create, closed webhook → fixed + pending retest, signature gate, ServiceNow/Azure DevOps stubs, unknown/disabled backends.
- `tests/test_phase7_portal_tickets.py`: CycloneDX and Dependency-Track imports, Jira and GitHub ticket sync, signed webhooks, and the client portal and auditor view.
- `tests/test_phase7_tuning.py`: per-tenant risk weights, suppression rules that expire, and false-positive rate by tool.
- `tests/test_postgres_rls.py`: every tenant table has a PostgreSQL row-level security policy; the live cross-tenant check runs only when a test Postgres is set.
- `tests/test_proof_replay.py`: HTTP request and response proof is redacted and hashed, and replay stays in scope and refuses changed proof.
- `tests/test_trust_center.py`: the trust center is off by default, publishes only by hand, accepts only signed reports, and gates items behind an NDA.
- `tests/test_user_management.py`: invites, roles, expiry, one-time tokens, password rules, last admin guard, disabled login and password reset.
- `tests/test_webhooks.py`: outbound webhooks block private addresses, are signed, retry with backoff, and follow workflow rules.
- `tests/test_phase5_webhooks.py`: fake-sender delivery marks delivered with verifiable signatures; non-2xx retries then fails; bad/inactive endpoints fail cleanly; verify rejects bad or expired signatures.
- `tests/test_phase2_bugs.py`: known alert emails skip revoked/used invites; iso_soa uses framework display name; PDF times use `ATTESTRA_DISPLAY_TZ`; workflow rule DELETE/POST deactivate sets `active=False`.
- `tests/test_email_alerts.py`: SMTP off skips quietly; grouped Critical/High email; header before/after; SLA once; password never logged; settings role checks; unrestricted lead default tenant; HarmonyPM live header compare on a DB copy.
- `tests/test_ui_audit_fixes.py`: friendly 403, 404 and 422 pages, nav links by role, sign-in `next=` redirect, confirm before destructive actions, and `_back` flash query joining.
- `tests/runner/test_phase7_adapters.py`: command lines for the extra scanner adapters; network tools use the pinned IP and nothing runs.

## Scan, ownership and sign-off tests

Tests for real scan runs, target ownership, and the report sign-off buttons. Nothing here touches the network or starts Docker.

- `tests/runner/test_scanner_docker_runs.py`: Docker command lines, exit codes, report file checks and timeouts for each queued scanner, with a fake process runner.
- `tests/jobs/test_queue_scan_worker.py`: a queued scan goes from run to saved and hashed report to import to Done, or fails with a clear reason.
- `tests/test_ownership_verify.py`: the engagement page shows the ownership token, and Check now works by DNS TXT or the well-known file.
- `tests/test_ownership_private_confirm.py`: a lead or admin can record the owner's confirmation for a private IP only, and the scan gate then allows it.
- `tests/test_ui_report_lifecycle.py`: Submit for QA, QA approve or reject, and Approve and sign buttons, with three different people and no self-approval.
- `tests/test_report_signoff_record.py`: the report view shows the sign-off record, the sealed file stays byte-identical, a changed file is flagged, and `user set-password` works.
- `tests/test_vapt_label_rename.py`: engagement type label is `VA + PT`; legacy label maps to key `vapt`; rendered report titles never contain the legacy acronym.
- `tests/test_findings_csv_ct.py`: findings CSV columns and formula guard, tenant check, mocked CT filters (one request, no scope/scan change), CT button off when apex out of scope, HarmonyPM live CSV row count on a DB copy.

## test_email_alerts.py

Email alerts for new Critical/High findings, header changes, and missed SLA (tests/test_email_alerts.py).

### No SMTP skips quietly

Without SMTP env and without a fake deliver, alerts return false and do not crash.

### Grouped new high findings

Five new Critical/High findings produce exactly one email and one `alert.email.sent` audit row.

### Header change before after

A security header value change between the last two scans sends one email that includes before and after.

### SLA missed once

An overdue open finding emails once; a second scheduler run does not send again.

### Password not in logs

The SMTP password never appears in log output when an alert is sent through the fake deliver path.

### Settings role checks

A lead can read and update alert settings; a reviewer cannot.

### Unrestricted lead default tenant

A platform lead with no home tenant still loads and updates alert settings via the default-tenant picker.

### Header snapshot helpers

Diff helpers report added, removed, and value-changed security headers.

### Live HarmonyPM header compare

On a temp copy of the live DB, the header-change compare runs for HarmonyPM targets and prints what would be emailed (nothing is sent).

## test_ui_audit_fixes.py

Friendly HTML errors, role nav, and flash redirect helpers for the server-rendered UI (tests/test_ui_audit_fixes.py).

### Back preserves existing query

[[attestra/web/ui.py#_back]] appends `msg`/`error` with `&` when the redirect URL already has a query string (for example `/settings/alerts?tenant_id=1`).

## test_cert_expiry.py

Certificate expiry warning bands, daily job and fixture parses (tests/test_cert_expiry.py).

### Band edges

Day thresholds map to the documented 30 / 14 / 7 warning bands.

### Acceptance severities

Each band maps to the expected severity for the cert expiry finding.

### Band change keeps finding id

Moving to a nearer band updates the same finding instead of creating a duplicate.

### Renew closes finding

A renewed certificate closes the open expiry finding.

### Daily job one webhook per band

The daily job emits at most one webhook when a cert enters a new band.

### Fingerprint stable across tools

The expiry finding fingerprint stays stable whether the end date came from webcheck or testssl.

### Parse with frozen clock

Parsing uses a frozen clock so band selection is deterministic in tests.

### Expired fixture still high

An already-expired fixture still produces a High finding.

## test_share_link_badge.py

Read-only share links and SVG grade badges (tests/test_share_link_badge.py).

### Create stores hash only

Creating a share link stores only a hash of the token, never the raw secret.

### Valid view works

A valid unexpired link returns the public grade view.

### Expired revoked fail same

Expired and revoked links fail the same way so attackers cannot tell them apart.

### Forbidden fields absent

The public HTML omits evidence text, user email, tenant markers, internal notes, and API key prefixes seeded into the test data.

### SVG badge valid

The badge endpoint returns valid SVG with the grade and no `<script>`.

### Role checks

Read-only users cannot create links; another tenant cannot revoke.

### Audit events

Share create, view and revoke write the expected audit actions.

### Live HarmonyPM share

Against a temp copy of live data, a HarmonyPM target can be shared and viewed.

## test_http_redirect.py

Phase 15 HTTP to HTTPS redirect checks with mocked HTTP only (tests/test_http_redirect.py).

### 301 same host passes

A permanent 301 to the same host over HTTPS is treated as a pass (no finding).

### 308 same host passes

A permanent 308 to the same host over HTTPS is treated as a pass (no finding).

### 302 temporary low

A temporary 302 to the same host is a Low finding (prefer permanent redirects).

### 307 temporary low

A temporary 307 to the same host is a Low finding (prefer permanent redirects).

### Other host low

A redirect that leaves the expected host is a Low finding.

### Http target medium

An http:// Location (or no HTTPS upgrade) is a Medium finding.

### 200 no redirect medium

HTTP 200 with no redirect to HTTPS is a Medium finding.

### Connection refused passed

When the HTTP probe cannot connect, the check is recorded as passed/skipped without a finding.

### Grade penalty on no redirect

Missing HTTPS redirect applies the documented grade modifier points.

### Adapter one request redirects off

The webcheck adapter makes one HTTP request with redirects off for this check.

### Out of scope not requested

When the http:// URL is out of signed scope, no request is made.

### Adapter connection refused passed

Adapter path records a passed/skipped check when the HTTP probe is refused.

### Live data HarmonyPM offline

Live-data check uses a DB copy only and does not open a network connection.

## Phase 19 small extras

Findings CSV export and CT subdomain suggestions (tests/test_findings_csv_ct.py).

### CSV export columns and formula guard

Export columns match the triage set and a title of `=cmd()` is prefixed with a single quote; `findings.exported` is audited.

### CSV tenant check

A client viewer from another tenant gets 404 on findings CSV export.

### CT filters and one request

A mocked crt.sh answer drops wildcards, duplicates and out-of-apex names; the asset table and scan table stay unchanged; exactly one HTTP request is made; `scope.suggestions.fetched` is audited.

### CT button off when apex out of scope

When only a subdomain is in scope, the suggestions status endpoint reports disabled and a fetch for the apex is refused (R14).

### Live HarmonyPM CSV row count

On a temp copy of the live ui_data database, HarmonyPM engagement findings export to CSV with the expected row count. No real CT lookup.

## Phase 6 auth web

Authenticated website testing: Fernet credential store, profiles, crawl scope, evidence redaction, checklists, and coverage ([[tests/test_phase6_credentials.py]], [[tests/test_phase6_auth_web_crawl.py]], [[tests/test_phase6_checklists_coverage.py]], [[tests/test_phase6_auth_profiles_api.py]], [[tests/test_phase6_auth_mock_smoke.py]], [[tests/test_phase6_screenshot_redact.py]]).

### Credential put/get round-trip

[[attestra/credentials/store.py#put_secret]] returns an opaque `cred:` ref; [[attestra/credentials/store.py#get_secret]] round-trips the value without putting plaintext in the ref.

### Missing key fails closed

Without `ATTESTRA_CREDENTIAL_FERNET_KEY` and without ephemeral allow, [[attestra/credentials/store.py#resolve_fernet_key]] and put raise SecretsError.

### Ephemeral key when allowed

With `ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL=1`, put/get works using a process-local Fernet key for tests and local dev.

### Delete removes secret

[[attestra/credentials/store.py#delete_secret]] removes ciphertext; subsequent get raises; delete is idempotent.

### Rotate keeps ref

[[attestra/credentials/store.py#rotate_secret]] overwrites ciphertext at the same `secret_ref`.

### Secrets never logged or repr

Store `repr` and debug logs never contain the plaintext secret value.

### Screenshot DOM prep JS

[[attestra/proof/screenshot_redact.py#prepare_page_for_capture]] returns a JS snippet that masks password inputs and sensitive selectors with bullets and `data-attestra-redact`.

### Screenshot PNG ASCII scan

[[attestra/proof/screenshot_redact.py#scan_png_for_plaintext_ascii]] and [[attestra/proof/screenshot_redact.py#assert_no_secret_in_png_metadata]] find forbidden strings in PNG bytes/text chunks; strip removes tEXt leaks.

### Screenshot attach redaction status

[[attestra/proof/screenshot_redact.py#attach_redacted_screenshot]] stores via [[attestra/proof/store.py#attach_screenshot]] and records `redaction_status=redacted|skipped` in the note.

### Screenshot pixel region redaction

With Pillow installed, [[attestra/proof/screenshot_redact.py#redact_png_regions]] blacks out regions and clears text-chunk secrets from the PNG payload.

### Screenshot redact without Pillow

Without Pillow, pixel redact raises [[attestra/proof/screenshot_redact.py#RedactionError]]; attach skips pixel paint, strips text chunks, and notes `redaction_status=skipped`.

### Profile create does not return secret

[[attestra/auth_web/profiles.py#create_profile]] plus POST `/api/auth-web/.../auth-profiles` return [[attestra/auth_web/profiles.py#profile_dict]] metadata and `has_secret` only; plaintext never appears in the JSON body.

### Profile list never contains secret

List endpoints for auth-web profiles never echo stored secrets; rows expose `has_secret` and a truncated `secret_ref` via [[attestra/auth_web/profiles.py#profile_dict]].

### Profile rotate revoke delete

[[attestra/auth_web/profiles.py#rotate_secret]] keeps the same `secret_ref`, [[attestra/auth_web/profiles.py#revoke_profile]] marks status revoked, and [[attestra/auth_web/profiles.py#delete_profile]] removes the profile and ciphertext.

### Profile cross-tenant denied

Staff limited to one tenant get 404 on another engagement's profiles; viewers may read home profiles but cannot write.

### SSO bootstrap validate blocked

[[attestra/auth_web/profiles.py#validate_profile]] sets method `sso_bootstrap` to `blocked_sso` with a redacted MFA/SSO note and no secret echo.

### Method none validates valid

A profile with method `none` and no secret validates to status `valid` for unauthenticated baseline coverage.

### SSRF localhost blocked

[[attestra/auth_web/scope.py#scope_from_seeds]] and [[attestra/auth_web/scope.py#assert_url_in_scope]] reject localhost, loopback, and link-local metadata hosts.

### Out-of-scope redirect blocked

[[attestra/auth_web/scope.py#assert_redirect_in_scope]] rejects cross-origin and same-host path redirects outside the seed prefix.

### Route normalization dedup

[[attestra/auth_web/crawl.py#normalize_url]] lowercases host, sorts/caps query params, and drops fragments so equivalent URLs dedupe.

### Crawler respects max_routes

[[attestra/auth_web/crawl.py#crawl]] stops visiting once [[attestra/auth_web/limits.py#CrawlLimits]] `max_routes` is reached.

### Synthetic data never echoes secrets

[[attestra/auth_web/forms.py#synthetic_value]] and [[attestra/auth_web/forms.py#fill_form_values]] never copy JWT/password/API-key-looking field values into filled payloads.

### Role compare read-only by default

[[attestra/auth_web/roles.py#is_read_only_comparison]] is true unless intrusive is enabled; [[attestra/auth_web/roles.py#compare_roles]] stays non-mutating by default; [[attestra/auth_web/roles.py#plan_object_access_probes]] raises unless ``intrusive=True``.

### Checklist seeds defaults

[[attestra/auth_web/checklists.py#ensure_checklist]] inserts [[attestra/auth_web/checklists.py#DEFAULT_CHECKLIST]] as `not_started` and is idempotent (never marks passed).

### Checklist rejects skipped as passed

[[attestra/auth_web/checklists.py#update_checklist_item]] refuses `status=passed` when notes start with "skipped"; the row stays unchanged.

### Checklist blocked needs evidence

Moving from `blocked` to `passed` via [[attestra/auth_web/checklists.py#update_checklist_item]] requires `evidence_ids`; without them the update raises ServiceError.

### Checklist accepts real pass

A genuine pass with notes is accepted; an invalid status such as `skipped` is rejected by [[attestra/auth_web/checklists.py#update_checklist_item]].

### Coverage math and incomplete

[[attestra/auth_web/coverage.py#coverage_summary]] computes `routes.coverage_pct` as visited/discovered, keeps skipped≠passed for checklist counts, and sets `incomplete` when work remains.

### Coverage empty engagement

An engagement with no inventories reports zero `coverage_pct` and `incomplete` true with [[attestra/auth_web/coverage.py#EXCLUSIONS_NOTE]].

### Mock login succeeds

[[tests/fixtures/auth_web_mock_app.py#create_app]] accepts synthetic viewer credentials and grants `/app` after form login.

### Unauthenticated app gate

Unauthenticated `GET /app` returns 302 to `/login` (or 401) on the local mock.

### Admin role gate

Viewer sessions receive 403 on `/admin`; admin sessions receive 200.

### Public home and settings

`GET /` is public; `/app/settings` requires an authenticated session on the mock app.

## Phase 7 testing depth

CLI scan queue path, ZAP auth contexts, multi-role comparison, gated intrusive IDOR probes, auto screenshots on findings, and checklist rows in technical reports ([[tests/test_phase7_checklist_report.py]], [[tests/test_phase7_screenshots.py]]).

### Multi-role comparison

[[attestra/auth_web/role_scan.py#run_role_comparison]] loads two [[attestra/models.py#AuthCredentialProfile]] roles, captures read-only snapshots (mock fetcher or prebuilt), and calls [[attestra/auth_web/roles.py#compare_roles]] with ``intrusive=False`` ([[tests/test_phase7_role_scan.py]]).

### Multi-role same responses no findings

Identical status/redirect/controls across roles produce no Finding rows.

### Multi-role status diff creates finding

A status mismatch persists a ``tools=["auth_web_roles"]`` finding (severity low, CWE-862) with reproducible steps; a second run dedupes by fingerprint.

### Multi-role cross-tenant denied

A principal scoped to another tenant receives LookupError from [[attestra/services.py#get_engagement]] and creates no findings.

### Multi-role disabled flag

When [[attestra/config.py#AUTH_WEB_ENABLED]] is off, [[attestra/auth_web/role_scan.py#run_role_comparison]] raises ServiceError.

### Multi-role secrets never in finding

Credential plaintext loaded for the fetcher never appears in finding title, description, recommendation, location, or the returned result dict.

### Auto screenshot from PNG bytes

[[attestra/proof/screenshots.py#capture_finding_screenshot]] stores a `screenshot` evidence row with a sha256 when given PNG bytes.

### Auto screenshot redaction status

Evidence notes include `redaction_status=` and must not echo secret strings from PNG metadata.

### Auto screenshot skip existing

A second capture for a finding that already has a screenshot returns None and does not duplicate evidence.

### Auto screenshot capture_fn registry

[[attestra/proof/screenshots.py#register_screenshot_capture]] supplies bytes from a URL; batch capture strips location params before calling it.

### Auto screenshot secret not in note

Secret substrings from PNG text chunks must not appear in the evidence note or stored file bytes.

### Auto screenshot import stays network-free

Without a registered capture function, [[attestra/proof/capture.py#capture_from_import]] attaches nothing and performs no network IO.

### Auto screenshot via import registry

With a registered capture function, import-time capture attaches a screenshot for findings that have locations.

### Checklist refs in technical report

When [[attestra/models.py#AuthChecklistItem]] rows exist, [[attestra/reports/render.py#generate_report]] technical HTML includes `#auth-checklist` with WSTG/ASVS refs and statuses.

### Blocked not labeled passed

Blocked checklist rows (including notes that say skipped) render their real status in the technical report and are not labeled Passed.

### Checklist section absent when off

With [[attestra/config.py#AUTH_WEB_ENABLED]] off and no checklist rows, the authenticated security testing checklist section is omitted from technical HTML.

### No secrets in checklist report

Technical HTML with a checklist must not contain auth profile `secret_ref` values or credential plaintext from profile metadata.

### Auth web on seeds checklist for report

When [[attestra/config.py#AUTH_WEB_ENABLED]] is on and the engagement has no checklist rows, report generation seeds defaults via [[attestra/auth_web/checklists.py#ensure_checklist]] and renders them.

### CLI scan queues through request_scan

`attestra scan` calls [[attestra/services.py#request_scan]] (same path as the UI); a path tool on a repo asset queues and writes `scan.request`.

### CLI scan refused without authorization

Expired authorization yields `status=refused` with a refuse reason and `scan.refused` audit; GateError is absorbed, not a CLI crash.

### CLI scan actor attribution

`--user` resolves via [[attestra/cli.py#_resolve_actor]] so `requested_by` and the `scan.request` audit actor match the username.

### ZAP auth contexts

[[attestra/auth_web/zap_auth.py]] builds mounted ZAP auth config from credential profiles without putting secrets on argv or in ScanRun rows ([[tests/test_phase7_zap_auth.py]]).

#### Form header cookie omit secret

Form, header, and cookie builders keep secrets out of ``repr``/``str`` of public metadata; secrets exist only in restrictive files under ``out_dir``.

#### SSO bootstrap blocked

Method ``sso_bootstrap`` yields blocked status with an MFA/SSO reason and no secret-bearing file bodies.

#### Baseline argv unchanged without auth

With [[attestra/config.py#AUTH_WEB_ENABLED]] off, [[attestra/runner/scanners/zap.py#ZapAdapter#build_argv]] baseline argv stays unauthenticated (no ``-n`` / ``-U``).

#### get_secret used missing ref raises

[[attestra/auth_web/zap_auth.py#load_profile_secret]] uses [[attestra/credentials/store.py#get_secret]] and raises a clean [[attestra/auth_web/zap_auth.py#ZapAuthError]] when the ref is missing.

### Baseline profile refused

[[attestra/auth_web/tamper.py#assert_intrusive_allowed]] raises when the scan profile is `baseline` (not active/intrusive).

### Intrusive without flag refused

Intrusive probes are refused when the asset's `intrusive_allowed` flag is false.

### Without ownership refused

Intrusive probes are refused when target ownership has not been verified.

### Plan only never fetches

With `execute=False`, [[attestra/auth_web/tamper.py#plan_and_maybe_execute_probes]] returns a plan and never calls `fetch_fn`.

### Execute bounded after gate

After the intrusive gate passes, execute runs at most [[attestra/auth_web/tamper.py#MAX_EXECUTE_OBJECT_IDS]] GETs.

### Sensitive marker redacts and stops

A response containing a sensitive marker is redacted, recorded, and stops further probe execution.

## Phase 8 packs portal dashboards

ASVS pack and Top 10 report view, client remediation portal, severity/SLA/trend dashboards, library seed and CERT-In verification, public report verify with QR, Safe-to-Host letter and SEBI testing timeline.

### Public verify valid signature

Signed report with a correct HMAC `sig` returns 200 and shows the SHA-256, signer, and kind on the public page.

### Public verify bad signature

A wrong `sig` query value returns 404 without leaking report metadata.

### Public verify unsigned not public

Draft/unsigned reports return 404 even when the HMAC is computed from their sha256.

### Public verify no grade when untested

When the engagement has no completed scan, the verify page omits letter grades and scores (P0-4).

### Public verify QR present

Valid verify HTML includes an inline SVG QR and the absolute `/verify/reports/{rid}?sig=` URL.

### Client remediation portal

Portal P6-2: client_viewer comment, fix evidence, retest, branding; auditor read-only ([[tests/test_phase8_portal_remediation.py]], [[interfaces#Client remediation portal]]).

#### Client can comment

A client_viewer posts a comment on a visible finding via the portal route; the body is stored and linked to their user.

#### Client can upload evidence

A client_viewer uploads a small file as kind `client_fix` (never screenshot); actor is the principal.

#### Client can request retest

On a validated finding, client_viewer requests a retest with a note; an open Retest row is created.

#### Cannot retest new finding

Untriaged (`new`) findings are hidden (404) and retest POST is refused for client_viewer.

#### Cross-tenant 404

A client_viewer from another tenant gets 404 on engagement and finding portal routes (including comment POST).

#### Auditor cannot write

Auditor can open the portal finding page but cannot POST comment, evidence, or retest (403); write forms are omitted.

#### Tenant branding

A tenant ReportTemplate logo and cover title appear on portal home, engagement, and finding pages.

### Safe-to-Host attestation letter

Attestation HTML includes a Safe-to-Host block with client, authorization, environments, open critical/high count, and a non-certification hosting decision statement using security-testing wording only.

### SEBI security testing timeline

Timeline milestones expose planning through retest statuses; the SEBI pack still loads; the staff UI page renders without secrets.

### Metrics dashboard

Phase 8 P6-3 staff metrics page: open-by-severity, SLA ageing, trend, site grades ([[tests/test_phase8_dashboard.py]], [[attestra/dashboards.py#summary_for_principal]]).

#### Empty tenant zeros

A tenant with no engagements returns zero severity and SLA counts, empty site grade lists, and zeroed trend weeks.

#### Overdue counted

Open findings past `sla_due` land in `sla_ageing.overdue`; due-within-7d and on-track/no-SLA fill `due_soon` and `ok`.

#### Severity totals

Open findings are tallied by severity; closed statuses do not add to `open_by_severity` or `trend.current_open`.

#### Role redirect

`client_viewer` and `auditor` hitting `/dashboard` are redirected to `/portal`.

### ASVS pack loads

`asvs_4_0` appears in [[attestra/compliance/engine.py#load_library]] with V1–V14 chapter titles from `attestra/compliance/data/packs/asvs_4_0.yaml`.

### ASVS compliance rollup

[[attestra/services.py#compliance]] for `asvs_4_0` returns titled control results with unique chapter refs.

### OWASP Top 10 report view

Kind `owasp_top10` renders HTML with Top 10 2021 category headings and no user-facing "VAPT" string.

### LLM Top 10 optional block

When the engagement includes `iso_42001_2023`, the Top 10 report also shows OWASP LLM Top 10 2025 headings.

### Client remediation portal

Client viewers can comment, upload fix evidence, and request retests; auditors stay read-only.

#### Client can comment

A `client_viewer` may post a finding comment on a triaged finding in their tenant.

#### Client can upload evidence

Portal fix-evidence upload stores a capped `client_fix` evidence item on the finding.

#### Client can request retest

Client viewers may request a retest for an eligible triaged finding.

#### Cannot retest new finding

Untriaged `new` findings are rejected for client retest requests.

#### Cross-tenant 404

Portal actions on another tenant's engagement return 404.

#### Auditor cannot write

Auditor role cannot post comments, upload evidence, or request retests.

#### Tenant branding

Portal pages show the tenant's configured branding when present.

### Public verify valid signature

A signed report with a correct HMAC sig returns a public verify page that confirms the seal.

### Public verify bad signature

A wrong or truncated sig does not show a successful public verification.

### Public verify unsigned not public

Draft or unsigned reports are not exposed on the public verify route.

### Public verify no grade when untested

When no graded scan exists, the public page omits a site grade claim.

### Public verify QR present

The public verify page embeds a QR SVG pointing at the verify URL.

### Library seed import and CERT-In

[[tests/test_phase8_library_certin.py]] checks CERT-In 2022 pack titles (Dir.(i)/(ii)/(iv)/(v), Annex I), compliance on a `cert_in_2022` engagement, JSON/CSV template convert, oversized reject, idempotent [[attestra/library/service.py#seed_defaults]], and `POST /api/library/import` with `library.import` audit.


