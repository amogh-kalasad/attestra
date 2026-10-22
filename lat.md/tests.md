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
- `tests/test_ai_routes.py`: AI draft pages and API return 404 when off, and only approved drafts reach a report.
- `tests/test_ai_drafts_page.py`: the AI drafts page uses the normal layout, shows a friendly off message, and asks before Reject.
- `tests/test_c7_c11_mapping_soc2.py`: mapping strength and reason show in compliance output, and SOC 2 Type II sampling is repeatable.
- `tests/test_c9_c10_pci_iso.py`: ASV import, PCI calendar, segmentation records, ISO SoA, nonconformity and corrective action, and audit sampling.
- `tests/test_control_libraries.py`: PCI, ISO and SOC 2 crosswalks cover every objective, and OSCAL and SCF control libraries import correctly.
- `tests/test_iso42001_pack.py`: the ISO/IEC 42001 pack loads with all 38 Annex A items, clauses 4 to 10, and the LLM Top 10 map.
- `tests/test_phase8_framework_packs.py`: extra framework packs load from YAML, bad packs are refused, and reports render them.
- `tests/test_findings_library.py`: the findings library (search, add, apply without overwrite) and tenant report templates with a safe sandbox.
- `tests/test_fix_snippets.py`: header/TLS/cookie/CSP library entries carry importance, effort, fix steps and four server snippets; finding page, report and API show them; empty fields still render.
- `tests/test_fingerprint_variant.py`: an empty `variant` keeps the fingerprint exactly the same as before the field existed.
- `tests/test_phase7_importers.py`: Prowler, kube-bench, testssl.sh, Gitleaks, Checkov and naabu parsers; Gitleaks never keeps the secret.
- `tests/test_phase7_portal_tickets.py`: CycloneDX and Dependency-Track imports, Jira and GitHub ticket sync, signed webhooks, and the client portal and auditor view.
- `tests/test_phase7_tuning.py`: per-tenant risk weights, suppression rules that expire, and false-positive rate by tool.
- `tests/test_postgres_rls.py`: every tenant table has a PostgreSQL row-level security policy; the live cross-tenant check runs only when a test Postgres is set.
- `tests/test_proof_replay.py`: HTTP request and response proof is redacted and hashed, and replay stays in scope and refuses changed proof.
- `tests/test_trust_center.py`: the trust center is off by default, publishes only by hand, accepts only signed reports, and gates items behind an NDA.
- `tests/test_user_management.py`: invites, roles, expiry, one-time tokens, password rules, last admin guard, disabled login and password reset.
- `tests/test_webhooks.py`: outbound webhooks block private addresses, are signed, retry with backoff, and follow workflow rules.
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
