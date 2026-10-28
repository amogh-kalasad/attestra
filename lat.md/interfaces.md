# Interfaces

Three surfaces share [[attestra/services.py]] so business rules stay in one place.

## REST API

FastAPI routes and actor header for write operations.

[[attestra/api.py]] — FastAPI app with OpenAPI at `/docs`.

Notable routes:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Liveness plus PDF engine probe (`pdf` / `pdf_engine` / `pdf_message`) |
| GET | `/api/catalog` | Asset kinds + test types |
| POST/GET | `/api/engagements` | Create / list |
| POST | `/api/engagements/{eid}/authorizations` | Upload signed auth |
| POST | `/api/engagements/{eid}/assets` | Add target |
| POST | `/api/engagements/{eid}/imports` | Import scanner file |
| GET | `/api/engagements/{eid}/findings` | List findings |
| GET | `/api/engagements/{eid}/findings/export` | Findings CSV (formula-safe); optional `asset_id` |
| GET | `/api/engagements/{eid}/export/xlsx` | Excel Findings/Controls/Evidence workbook |
| GET | `/api/engagements/{eid}/export/json` | Full engagement JSON (`version` + `export_schema_version`) |
| GET | `/api/engagements/{eid}/export/markdown` | Consolidated findings Markdown |
| POST | `/api/findings/{fid}/assign` | Assign finding to a tenant username (audited) |
| POST | `/api/findings/{fid}/unassign` | Clear finding assignee (audited) |
| GET | `/api/findings/{fid}/assignee` | Current assignee username |
| GET | `/api/engagements/{eid}/scope/suggestions` | Which apexes may run CT suggestions |
| POST | `/api/engagements/{eid}/scope/suggestions` | One CT lookup; suggestions only |
| POST | `/api/findings/{fid}/transition` | Lifecycle change |
| GET | `/api/engagements/{eid}/compliance` | Control roll-up |
| POST | `/api/engagements/{eid}/reports` | Generate report |
| POST | `/api/reports/{rid}/submit` | Submit for QA |
| POST | `/api/reports/{rid}/qa-approve` | QA approve |
| POST | `/api/reports/{rid}/qa-reject` | QA reject with a note |
| POST | `/api/reports/{rid}/sign` | Approve and sign |
| POST | `/api/reports/{rid}/approve` | Four-eyes approve |
| GET | `/reports/{rid}` | View report with sign-off record on top |
| GET | `/reports/{rid}/sealed` | Download the sealed file unchanged |
| GET | `/api/audit/verify` | Audit chain check |
| GET | `/api/audit/export` | Audit export JSON/CSV + chain proof |
| GET | `/api/evidence/{eid}/download` | Download evidence (audited) |
| GET | `/api/findings/{fid}/evidence/gallery` | Grouped evidence cards (no paths) |
| POST | `/api/findings/{fid}/evidence/{eid}/annotate` | Annotated screenshot derivative |
| POST | `/api/scans/{sid}/cancel` | Cancel a queued or running scan (`scan.start`) |

Writes require [[attestra/api.py#get_principal]] (Bearer or session) and [[attestra/api.py#require]] for the route permission. Service errors map via [[attestra/api.py#_run]].

## CLI

Command-line entrypoint sharing the same services layer.

[[attestra/cli.py]] — `attestra` entrypoint: init, demo, user add, user set-password, user disable, key create, key list, key revoke, migrate-storage, serve, worker, import, scan, enrich (`--refresh`), purge, backup, restore, transition, compliance, report, approve, verify-report, verify-audit, findings. Identity via `--api-key` / `ATTESTRA_API_KEY` or `--user`.

`attestra scan <engagement> <asset> --tool <tool> [--profile baseline|active|intrusive]` ([[attestra/cli.py#cmd_scan]]) queues through [[attestra/services.py#request_scan]] — the same gate and audit path as the UI scan POST. Tool choices come from [[attestra/runner/scanners/registry.py#list_adapters]]. Prints `scan_run`, `status`, `requested_by`, and `refuse_reason` when refused.

`attestra user set-password <username>` ([[attestra/cli.py#cmd_user_set_password]]) sets a local user's password. Without `--password` it asks twice at a hidden prompt and stops if the two do not match. [[attestra/users/service.py#set_password]] finds the user by name (exact, then case-insensitive), refuses SSO users, applies the same rules as [[attestra/users/service.py#validate_password]] (at least 12 characters, not the username, not too simple), revokes open reset links, and writes a `user.password_set` audit event with the CLI login name as actor. If the account is disabled, the command says it cannot sign in until an admin enables it.

`attestra user disable <username>` ([[attestra/cli.py#cmd_user_disable]]) needs `--api-key` or `--user` so the caller is known. [[attestra/users/service.py#disable_by_username]] looks up the account and calls [[attestra/users/service.py#set_active]]. Admins may disable any user (except the last admin). Leads may only disable tester, reviewer, or client_viewer accounts in their tenant scope. The change writes a `user.disable` audit row.

`attestra key list` ([[attestra/cli.py#cmd_key_list]]) prints id, username, prefix, status, and timestamps via [[attestra/auth/keys.py#list_api_keys]] (optional `--username`). `attestra key revoke <id>` ([[attestra/cli.py#cmd_key_revoke]]) calls [[attestra/auth/keys.py#revoke_api_key]], which sets `revoked_at` and writes an `api_key.revoke` audit row.

## Web dashboard

Server-rendered UI served alongside the API. Login at `/login` ([[attestra/web/ui.py#login]]); session cookie replaces the old free-text actor bar.

[[attestra/web/ui.py]] — server-rendered UI mounted with the API. Form POSTs redirect via [[attestra/web/ui.py#_back]], which appends `msg`/`error` with `?` or `&` so existing query strings (for example `tenant_id`) stay intact.

Report lifecycle buttons post to `/engagements/{eid}/reports/{rid}/submit`, `/qa-approve`, `/qa-reject` and `/sign`; see [[reports#Workflow]]. Report links open `/reports/{rid}` in a new tab with the sign-off record on top ([[reports#Sign-off record]]).

When [[attestra/config.py#AUTH_WEB_ENABLED]] is on, engagement pages link to authenticated coverage (`engagement_auth_coverage.html`) and profile creates go through [[attestra/auth_web/routes.py#create_auth_profile]]; when off those routes return 404. See [[architecture#Authenticated website testing]].

Staff SEBI CSCRF security-testing timeline is at `GET /engagements/{eid}/sebi-timeline` ([[attestra/web/sebi_routes.py#ui_sebi_timeline]], included from [[attestra/api.py]]); see [[compliance#SEBI security testing timeline]].

### Sites dashboard

Tenant-wide list of every target with grade, open counts, last scan, and score trend.

`/sites` ([[attestra/web/ui.py#sites_dashboard]], template `sites.html`) and `GET /api/sites` call [[attestra/services.py#list_tenant_sites]]. Each row shows name/URL, Observatory grade and score (or “not graded” when there is no finished scan), last scan date/status, open Critical/High/Medium/Low counts (one grouped query), and a trend arrow from the last two finished scans’ Observatory scores via [[attestra/history.py#observatory_score_for_scan]]. Cancelled and failed scans are excluded from grade and trend. Default sort is worst grade first ([[attestra/grade.py#grade_rank]]); name and last-scan sorts and a name filter are available. Rows link to the target page. Sidebar Work nav includes Sites.

### Metrics dashboard

Staff roll-up of open severity, SLA ageing, weekly inflow, and worst/best site grades.

`GET /dashboard` (template `dashboard.html`) calls [[attestra/dashboards.py#summary_for_principal]]. Keys: `open_by_severity`, `sla_ageing` (`ok` / `due_soon` within 7d / `overdue` via `Finding.sla_due`), `trend` (last N weeks opened plus current vs previous open), and `site_grades` (worst/best from [[attestra/services.py#list_tenant_sites]]). Read-only roles redirect to `/portal`. Nav links Dashboard; the page links to `/sites`.

### Finding comments

Comment thread on the finding detail page and matching REST routes.

Staff finding page (`/engagements/{eid}/findings/{fid}`, template `finding.html`) shows author, time in the display zone, escaped plain text, add form, and delete for authors or lead/admin. Routes: [[attestra/web/ui.py#ui_add_finding_comment]], [[attestra/web/ui.py#ui_delete_finding_comment]]. API: `GET/POST /api/findings/{fid}/comments`, `DELETE /api/findings/{fid}/comments/{cid}` via [[attestra/comments.py]]. See [[findings#Comments]].

### Cancel a scan

Staff can cancel a queued or running scan from the scan list or the scan page.

[[attestra/services.py#cancel_scan]] needs `scan.start`, same tenant as the engagement. It reuses [[attestra/jobs/durable.py#request_cancel]] and [[attestra/jobs/durable.py#signal_job_cancel]], marks the scan and job `cancelled`, keeps any results already saved, and writes `scan.cancelled`. Finished, failed, or already-cancelled scans are refused. UI: Cancel on the engagement scans table and on `/engagements/{eid}/scans/{sid}` ([[attestra/web/ui.py#scan_page]], [[attestra/web/ui.py#ui_cancel_scan]]). API: `POST /api/scans/{sid}/cancel`. Cancelled scans do not emit `scan.finished` ([[attestra/webhooks/service.py#safe_emit_scan]]) and are excluded from history grade/trend (`done`/`quarantined` only).

### Finding detail and FP drill-down

Finding detail and per-tool false-positive lists finish the partly-done UI audit items.

[[attestra/web/ui.py#finding_page]] at `/engagements/{eid}/findings/{fid}` shows description, recommendation, evidence gallery and status change (UI audit #55). Evidence cards come from [[attestra/evidence/gallery.py#build_gallery]] (roles, capture failures, visually-verified badge), download via [[attestra/web/ui.py#ui_download_evidence]] (`GET /engagements/{eid}/evidence/{evid}/download`) or [[attestra/api.py#download_evidence]], and show the latest [[attestra/models.py#ProofReplay]] status per item. False-positive rates link each tool to `/tuning/false-positives/{tool}` ([[attestra/web/ui.py#false_positive_tool_findings]], [[attestra/tuning.py#findings_for_tool]], UI audit #87). Edit engagement also renames the client ([[attestra/services.py#update_engagement]]); HTML read-only POSTs redirect to `/portal?error=...` ([[attestra/web/errors.py#install]], UI audit #6).

### Edit engagement under CSP

`Edit engagement` links to `<details id="edit">` inside the Overview tab; Save is a normal form POST.

CSS tab panels use `:target` / `:has(:target)` so `#edit` reveals Overview without JS. Native hash navigation does not open `<details>`, so [[attestra/web/static/attestra.js]] `openDetailsFromHash` (and the hash-link click handler) sets `details.open` on load and click. Page helpers (auth env check, target-kind defaults, scan profile gate, edit window min sync) also live in `attestra.js` via `initEngagementPage`; the template only ships `application/json` data blocks because [[attestra/api_security.py#SecurityHeadersMiddleware]] uses `default-src 'self'` (no `script-src 'unsafe-inline'`). POST `/engagements/{eid}/edit` ([[attestra/web/ui.py#edit_engagement]]) updates name, client name, window, and frameworks through [[attestra/services.py#update_engagement]].

### Findings filter on the engagement page

Client-side severity/status/tool/target filters on the findings card; the API supports the same filters.

`engagement.html` `#findings` rows carry `data-severity`, `data-status`, `data-tools`, and `data-asset`. A filter bar updates visibility and an “N shown” count; optional query params (`severity`, `status`, `tool`, `asset`) are mirrored via `history.replaceState` and passed through [[attestra/web/ui.py#_engagement_ctx]] as `findings_filter`. Export CSV stays available. `GET /api/engagements/{eid}/findings` accepts `status`, `severity`, `tool`, and `asset_id` via [[attestra/services.py#list_findings]].

### In-page confirmation dialog

Shared accessible confirm modal replaces browser `confirm()` for destructive actions.

`_layout.html` hosts `#confirm-backdrop` (title, message, Cancel, Confirm). [[attestra/web/static/attestra.js]] intercepts forms/buttons with `data-confirm="…"` and proceeds only on Confirm. Templates (engagement halt/cancel/remove/schedules, users, scan, AI drafts, library) name the entity in the message.

### Target history (C11)

Per-target page at `/engagements/{eid}/targets/{aid}` ([[attestra/web/ui.py#target_page]], template `asset.html`).

The page opens with the Observatory-style **site grade** from [[attestra/services.py#asset_site_grade]] (letter, score, breakdown). When the target kind needs ownership proof, an ownership section shows the token, DNS TXT value (`attestra-verify=<token>`), and well-known file URL with Copy buttons (same pattern as the engagement ownership block). Lead/admin can set or reuse a token (`POST .../ownership-token`) and run **Verify now** (`POST .../verify-ownership-now`) on this page. [[attestra/history.py#asset_scan_history]] then lists finished scans for that target with date, tool, per-scan severity letter ([[attestra/history.py#scan_letter_grade]]), severity counts, and new/fixed/still-open vs the previous scan of the **same tool** ([[attestra/history.py#diff_fingerprints]]). Snapshots come from each scan’s saved raw/import file. The page shows a small trend chart via [[attestra/history.py#trend_svg]] (same chart the technical report uses). Engagement target rows link to this page. API: `GET /api/engagements/{eid}/assets/{aid}/grade`.

Shared look-and-feel lives in `attestra/web/templates/_layout.html` (staff/portal) and `attestra/web/templates/_public.html` (Trust Center). Authenticated pages use a light app shell: white sidebar (Work / Library / Ops), sticky top bar, and content workspace. `attestra/web/templates/login.html` is a standalone split-screen sign-in (brand panel + form) matching the product login sample; it still posts username/password to [[attestra/web/ui.py#login]]. Visual system uses Geist + Geist Mono and indigo `#4338CA`. Page templates (engagements home, engagement detail, new engagement, PCI calendar, users, report templates, library, portal) follow that shell with KPI strips, status pills, breadcrumbs, and stepped progress where the product UI samples define them. Routes, forms, and permissions are unchanged. Display labels for common snake_case keys (for example `secure_config` → “Secure configuration”, `web_dast` → “Web application scan”) live in [[attestra/models.py#DISPLAY_LABELS]] and [[attestra/web/ui.py#label]].

## Scheduled scans and CI gates

Recurring scan schedules and a pass/fail check that CI pipelines can call.

- Schedules: `GET/POST /api/engagements/{eid}/schedules`, `PATCH/DELETE /api/engagements/{eid}/schedules/{sid}`, and `POST /api/engagements/{eid}/schedules/run-due` ([[attestra/api.py#run_due_schedules]]). Cadence is `quarterly` or `monthly` ([[attestra/services.py#update_scan_schedule]]); due schedules are queued by [[attestra/services.py#enqueue_due_schedules]] through the normal scan gate. Managing them needs `scan.start`; listing needs `scan.read`.
- CI gate: `GET /api/engagements/{eid}/gate` runs [[attestra/services.py#ci_gate]]. It fails when open findings at or above `fail_on` (default `high`) are more than `max_findings` (default 0). `tool` limits the check to one importer. Accepted-risk, fixed and false-positive findings never block. The answer lists counts by severity and up to 50 blocking findings.

Spacing tokens (`--space-1`…`--space-7`) keep section gaps, card stacks inside forms, QA action stacks, and post-table generate forms consistent with the product UI samples.

[[attestra/services.py#list_scan_schedules]], [[attestra/services.py#update_scan_schedule]], and [[attestra/services.py#remove_scan_schedule]] manage cadence and due dates.

## Client remediation portal

Client viewers comment, upload fix evidence, and request retests; auditors stay read-only; tenant branding on portal pages.

[[attestra/web/portal.py]] serves `/portal`, `/portal/engagements/{eid}`, and `/portal/engagements/{eid}/findings/{fid}` (template `portal_finding.html`). `new` / `false_positive` stay hidden from `client_viewer`. Comment POST calls [[attestra/comments.py#add_comment]] (same `can_add_comment` gate). Evidence POST requires `portal.evidence`, always stores kind `client_upload` (in [[attestra/services.py#EVIDENCE_KINDS]], never `screenshot`), caps size via [[attestra/web/portal.py#PORTAL_EVIDENCE_MAX_BYTES]], and uses [[attestra/services.py#add_evidence]]. Client downloads of scanner evidence are refused ([[authorization#Evidence file security]]). Retest POST requires `portal.retest_request` and a note, then [[attestra/retest.py#request_retest]] (validated/fixed only) plus a `portal.retest_request` audit. Auditor GETs omit write forms; POSTs return 403. Cross-tenant access is 404 via [[attestra/services.py#get_engagement]]. Branding from [[attestra/web/portal.py#tenant_branding]] (tenant `ReportTemplate` logo/cover via [[attestra/library/templates.py#_pick]]); no logo keeps the Attestra shell default.

## Public report verification

Public HMAC URL to confirm a sealed report hash and signature without login.

Route `GET /verify/reports/{rid}?sig=…` ([[attestra/verify/routes.py#public_verify_report]], mounted from [[attestra/api.py]]). [[attestra/verify/service.py#make_sig]] / [[attestra/verify/service.py#check_sig]] HMAC `{rid}:{sha256}` with the session secret; [[attestra/verify/service.py#public_view]] loads only signed reports, verifies hash+Ed25519/HMAC via [[attestra/reports/render.py#verify_report]], and returns kind, engagement name, sha256, signer, signed_at, validity flags, verify URL, and QR SVG — never findings, evidence, or grades. Template `verify_public.html` extends `_public.html` with no-cache / noindex headers.

### QR

Minimal dependency-free QR SVG for absolute verify URLs.

[[attestra/verify/qr_svg.py#qr_svg]] encodes byte-mode ECC-M codes (versions 1–10) for typical verify links and renders dark modules as SVG rects (no `qrcode` package, no external QR image host).

## Share links

Tokenized read-only links for one target grade or one scan, plus an SVG badge.

[[attestra/share/service.py#create_share]] issues a long random token (`secrets`, at least 32 bytes) and stores only [[attestra/share/service.py#hash_token]] on [[attestra/share/models.py#ShareLink]]. Default expiry is 7 days (max 90). [[attestra/share/service.py#revoke_share]] and expiry both make the link invalid. Public page `/share/{token}` and badge `/share/{token}/badge.svg` ([[attestra/share/routes.py]]) show only target name, grade, score breakdown, and finding title/severity/status/tool (via [[attestra/comments.py#finding_fields_for_share]]); never evidence, comments, emails, tenant id, notes, API keys, or paths ([[attestra/share/service.py#FORBIDDEN_PUBLIC_KEYS]]). Invalid, expired, and revoked tokens return the same “link not valid” answer (410) with `noindex` and no-cache headers. Audits: `share.created`, `share.revoked`, and rate-limited `share.viewed`. Roles: `share.create` / `share.manage` for admin, lead, tester. UI list/revoke at `/shares`; API under `/api/v1/shares`. `GET /api/v1/shares` takes optional `tenant_id`; when omitted, [[attestra/share/routes.py#_default_share_tenant]] picks the caller’s home tenant, else the first allowed membership, else (unrestricted lead/admin) the first tenant by name.

## Auth-web credential profiles

Engagement-scoped test-account metadata for authenticated website testing; secrets stay in the credential store.

[[attestra/auth_web/profiles.py#create_profile]] accepts `secret_value` once (or an existing `secret_ref`), calls [[attestra/credentials/store.py#put_secret]], and stores only the opaque ref on [[attestra/models.py#AuthCredentialProfile]]. [[attestra/auth_web/profiles.py#profile_dict]] returns metadata, `has_secret`, and a truncated ref — never plaintext. [[attestra/auth_web/profiles.py#validate_profile]] is low-impact: `none` → `valid`, form/header/cookie without a live check → `pending`, `sso_bootstrap` → `blocked_sso` (never bypass MFA/SSO). Rotate/revoke/delete audit and delete ciphertext via [[attestra/credentials/store.py#delete_secret]]. API router [[attestra/auth_web/routes.py]] prefix `/api/auth-web` (mounted by the parent app): list/create under `/engagements/{eid}/auth-profiles`, plus `validate` / `rotate` / `revoke` / DELETE on `/{pid}`. Object-level tenant checks use [[attestra/services.py#get_engagement]]; permissions `engagement.read` / `engagement.write`.

## Email alerts

Optional SMTP notifications that reuse the same event points as outbound webhooks.

[[attestra/users/mailer.py#send_email]] sends plain plus HTML mail when `ATTESTRA_SMTP_HOST` is set (also `_PORT`, `_USER`, `_PASSWORD`, `_FROM`, `_TLS` / `_STARTTLS`). Off by default: one info log and no error. The password is never logged. Tests install an in-memory deliver function via [[attestra/users/mailer.py#set_deliver]].

Events (same hooks as webhooks):

1. New Critical or High findings — [[attestra/alerts/service.py#notify_new_high_findings]] after import ([[attestra/proof/hooks.py#after_import]]); many findings from one import become **one** email.
2. Security header changed — [[attestra/alerts/service.py#notify_header_change]] on `scan.finished` ([[attestra/webhooks/service.py#safe_emit_scan]]); compares the last two saved scans of the same tool via [[attestra/alerts/headers.py#diff_headers]]. Webcheck stores a `headers` snapshot in its report.
3. SLA missed — [[attestra/alerts/service.py#run_sla_missed_alerts]] (`attestra sla-alert-check`); one email per finding, recorded in [[attestra/models.py#EmailAlertSent]].

Per-tenant toggles and recipient list live in [[attestra/models.py#EmailAlertSettings]]. Admin/lead UI at `/settings/alerts` ([[attestra/alerts/routes.py]]); API `GET/PUT /api/alerts/settings` needs `webhook.manage`. When `tenant_id` is omitted, [[attestra/alerts/routes.py#_default_tenant]] uses the principal's home tenant, else the first allowed tenant, else (unrestricted lead/admin) the first tenant by name — not an error. [[attestra/alerts/service.py#known_tenant_emails]] hints only unused, non-revoked invite emails (same filter as [[attestra/users/service.py#list_invites]]). Audit: `alert.settings.update` and `alert.email.sent` (event, count, recipients count — not the body). Finding links use `ATTESTRA_PUBLIC_URL` or `ATTESTRA_URL` when set.

## Configuration

Environment variables and on-disk data layout.

[[attestra/config.py]]:

- `ATTESTRA_DATA_DIR` — evidence/imports/reports/keys/feeds (default `./data`)
- `ATTESTRA_DATABASE_URL` — SQLite by default; PostgreSQL via `postgresql+psycopg://…`
- `ATTESTRA_STORAGE` — `local` (default) or `s3` ([[attestra/storage/__init__.py#get_storage]])
- `ATTESTRA_S3_BUCKET` / `ATTESTRA_S3_ENDPOINT` / `ATTESTRA_S3_OBJECT_LOCK` — S3 backend
- `ATTESTRA_KEV_URL` / `ATTESTRA_EPSS_URL` — feed URLs for `enrich --refresh`
- `ATTESTRA_GSB_ENABLED` — `1`/`true`/`yes` turns on Google Safe Browsing in webcheck (off by default)
- `ATTESTRA_GSB_API_KEY` — Safe Browsing API key; required with the flag; never logged or stored in reports
- `ATTESTRA_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_FROM` / `_TLS` (or `_STARTTLS`) — optional SMTP for invites and email alerts; off when host is unset; password never logged
- `ATTESTRA_PUBLIC_URL` (or `ATTESTRA_URL`) — base URL used in alert email links to findings and targets
- `SUBSCRIPTION_SERVICE` — see [[interfaces#Configuration#Subscription service flag]]
- `APP_ENV` / `BYPASS_SIGNED_AUTHORIZATION_VERIFICATION` — see [[interfaces#Configuration#Signed authorization flag]]
- `APP_ENV` / `BYPASS_TARGET_OWNERSHIP_VERIFICATION` — see [[interfaces#Configuration#Ownership verification flag]]

Template: `.env.example`. Operator checklist of where the ownership and signed-authorization bypasses reflect: `docs/OWNERSHIP_AND_AUTHORIZATION_FLAGS.md`.

### Subscription service flag

Centralized ON/OFF switch for organization test-run credit enforcement.

[[attestra/config.py#parse_subscription_service]] accepts only `ON` and `OFF` (case-insensitive). Missing or blank defaults to `ON`. Invalid values raise [[attestra/config.py#ConfigurationError]]. [[attestra/config.py#subscription_enforcement_enabled]] is the single helper credit admission uses. [[attestra/config.py#validate_runtime_config]] runs at API lifespan ([[attestra/api.py]]), `attestra init`, `attestra serve`, and `attestra worker` so API, CLI, schedules, and workers share one path. Changing the variable requires restarting the API and workers; Attestra does not hot-reload subscription mode. `OFF` bypasses only subscription credit checks; auth, tenant isolation, scope, SSRF, signed authorization, and audit stay enforced.

### Signed authorization flag

Local-testing bypass for import/scan signed-authorization environment gates.

See [[authorization#Signed authorization flag]]. [[attestra/config.py#signed_authorization_required]] is false only when [[attestra/config.py#signed_authorization_bypass_active]] (requested `BYPASS_SIGNED_AUTHORIZATION_VERIFICATION` and allowlisted `APP_ENV`). Documented in `.env.example` and `README.md`.

### Ownership verification flag

Local-testing bypass for the dispatch gate ownership check on web_app/api/host targets.

[[attestra/config.py#parse_bypass_target_ownership_verification]] accepts true/false/1/0/yes/no (default false). Bypass activates only with allowlisted `APP_ENV` (`local`/`test`/`development`). [[attestra/config.py#ownership_verification_required]] is the helper [[attestra/runner/gate.py#policy_input]] passes as `ownership_required`. [[attestra/config.py#validate_runtime_config]] rejects bypass outside the allowlist. Bypass skips only that ownership gate; UI verify/confirm and audit stay available. Engagement/asset UI shows **Bypassed (local testing)** via [[attestra/config.py#ownership_bypass_active]] and [[attestra/config.py#BYPASS_STATUS]], never as Verified.

### Organization test-run credits

Shared per-tenant balance consumed once at successful scan admission.

[[attestra/credits/service.py#ensure_account]] grants [[attestra/config.py#INITIAL_TEST_RUN_CREDITS]] (default 3) when a tenant is first created. [[attestra/services.py#create_engagement]] does not debit. [[attestra/services.py#request_scan]] is the only charging point (API, UI, CLI, and schedules all call it): after the runner gate accepts, [[attestra/credits/service.py#consume_for_scan_admit]] atomically decrements with optional idempotency; queue/dispatch failure refunds when [[attestra/config.py#CREDIT_REFUND_ON_PRE_START_FAILURE]] is on. Exhausted balance raises [[attestra/services.py#ServiceError]] (HTTP 402) only when enforcement is on. UI header and `/credits` show [[attestra/credits/service.py#balance_view]]; renewal requests and Super Admin (`admin`) allocation live in [[attestra/credits/service.py#request_renewal]] / [[attestra/credits/service.py#allocate_credits]] (no payment gateway). Schema: migration `0023_subscription_credits`.

## Product marketing page

Standalone AntHive-branded HTML describing implemented Attestra capabilities for the public website.

`docs/marketing/attestra.html` is a self-contained product page (hero, problem, solution workflow, features, advantages, report deliverables, audiences, CTA). Claims track `README.md`, [[architecture]], [[reports]], and report templates under `attestra/reports/templates`. Readable copy uses "security testing" or "VA + PT" and never the legacy acronym (stored type key `vapt` is unchanged). It is not served by the app; drop it into anthive.tech when integrating.
