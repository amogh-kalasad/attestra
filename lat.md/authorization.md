# Authorization and scope

No valid signed client authorization means no import when [[attestra/config.py#signed_authorization_required]] is true (default). Runner dispatch adds URL/path/image checks, deny rules, and ownership verification ([[runner#Scope authorization]]).

## Authorization record

Fields and validity rules for the signed client authorization document.

[[attestra/models.py#Authorization]] stores:

- Hashed signed document (write-once path + SHA-256)
- Signer, rules of engagement text
- `signed_on` / `expires_on` validity window
- Optional `environments` allow-list (empty means all, for older records)

Validity: [[attestra/models.py#Authorization#is_valid]]. Environment coverage: [[attestra/models.py#Authorization#covers]].

Created through [[attestra/services.py#add_authorization]].

A demo upload file for AntHive is served at `/static/samples/anthive-signed-authorization.pdf` (file under `attestra/web/static/samples/`); the engagement Signed authorization panel links to it.

### Super Admin document access

Only role `admin` may download or open the signed authorization file bytes.

[[attestra/auth/roles.py]] permission `authorization.document` is admin-only. [[attestra/services.py#open_authorization_document]] checks that permission, engagement tenant access, and path containment under the tenant data root; errors never include `document_path`. API: `GET /api/authorizations/{aid}/document` and list metadata via `GET /api/engagements/{eid}/authorizations` using [[attestra/services.py#authorization_public_dict]] (no storage path). UI download: `/engagements/{eid}/authorizations/{aid}/document`. Lead and tester may record authorizations and see non-file metadata; they cannot retrieve file contents. Remains enforced when `SUBSCRIPTION_SERVICE=OFF`.

## Import gate

Business rule that blocks result ingestion without a live authorization.

When [[attestra/config.py#signed_authorization_required]] is true, [[attestra/services.py#import_results]] fails if no currently valid authorization exists on the engagement. Findings matched to assets must land in environments covered by [[attestra/services.py#authorized_environments]]. Otherwise the import is rejected. When [[attestra/config.py#signed_authorization_bypass_active]] is true, those checks are skipped; document download RBAC, tenant isolation, ownership, and SSRF stay enforced. UI may still record authorizations and never claims cryptographic signature verification for a bypass.

## Signed authorization flag

APP_ENV-gated local-testing bypass for import and scan signed-authorization gates.

[[attestra/config.py#parse_bypass_signed_authorization_verification]] accepts true/false/1/0/yes/no (default false). [[attestra/config.py#signed_authorization_bypass_active]] requires the requested flag and allowlisted `APP_ENV` (`local`/`test`/`development`). [[attestra/config.py#signed_authorization_required]] drives import gates, [[attestra/runner/authorization.py#scope_for_engagement]] empty-auth refusal, and `authorization_required` in [[attestra/runner/gate.py#policy_input]]. Engagement UI shows **Signature verification bypassed (local testing)** / signed authorization gate bypassed with [[attestra/config.py#BYPASS_STATUS]] when active. [[attestra/config.py#validate_runtime_config]] rejects bypass when `APP_ENV` is missing, unknown, or `staging`/`production`. Restart API and workers after changing.

## Assets as allow-list

In-scope targets for an engagement and how import locations are matched.

[[attestra/models.py#Asset]] records in-scope targets: kind, identifier, environment, criticality, exposure, `in_cde`, `intrusive_allowed`, `test_types`.

Asset matching for imported locations: [[attestra/services.py#match_asset]] (host/URL normalization via [[attestra/services.py#_asset_key]]).

## Identity

Bearer API keys and signed session cookies identify callers; roles gate every route.

[[attestra/api.py#get_principal]] resolves `Authorization: Bearer` via [[attestra/auth/keys.py#authenticate_api_key]] or the `attestra_session` cookie via [[attestra/auth/session.py#read_session]]. [[attestra/api.py#require]] checks [[attestra/auth/roles.py#has_permission]] against the six roles in [[attestra/auth/roles.py#ROLES]]. Share links use `share.create` and `share.manage` (admin, lead, tester); see [[interfaces#Share links]]. Portal remediation uses narrow `portal.evidence` and `portal.retest_request` (admin, lead, tester, client_viewer) without granting `finding.write` to clients; see [[interfaces#Client remediation portal]].

UI login: [[attestra/web/ui.py#login]]. Passwords use scrypt ([[attestra/auth/keys.py#hash_password]]). Report workflow enforces distinct author / QA / signer user ids ([[attestra/reports/render.py#sign_report]]).

Optional Keycloak OIDC sits behind `ATTESTRA_OIDC_ENABLED` ([[attestra/auth/oidc.py#oidc_enabled]], [[attestra/auth/oidc.py#validate_id_token_claims]]).

## Tenant isolation

Queries and storage are scoped per tenant for non-admin principals.

[[attestra/services.py#scoped]] and [[attestra/services.py#tenant_ids_for]] filter engagement access. Evidence/imports/reports land under `DATA_DIR/tenants/<id>/` via [[attestra/services.py#_store]]. Finding-id write routes (evidence upload, status transition, assign, annotate) call [[attestra/services.py#assert_engagement_access]] so a foreign finding id cannot mutate another tenant. Rate limits and security headers: [[attestra/api_security.py#RateLimitMiddleware]], [[attestra/api_security.py#SecurityHeadersMiddleware]]. Webhook and workflow-rule creates ([[attestra/webhooks/routes.py#_tenant_ok]]) require the tenant row to exist — `tenant_ids_for` returning `None` (unrestricted lead/admin) means all tenants, not skip existence; missing ids return 404. Workflow rules are soft-deactivated via [[attestra/webhooks/service.py#deactivate_rule]] (`POST …/deactivate` or `DELETE`; `active=False`, no hard delete).

## Runner scope

URL/path/image allow-list and SSRF checks used before scanner dispatch.

See [[runner#Scope authorization]]. [[attestra/runner/authorization.py#authorize_target]] and [[attestra/runner/gate.py#check]] enforce engagement scope at enqueue and resume.

## CT subdomain suggestions

Passive Certificate Transparency suggestions for an in-scope apex; never auto-added to scope.

[[attestra/runner/ct_suggestions.py#suggestions_for_engagement]] runs only when the user clicks Find subdomain suggestions. [[attestra/runner/ct_suggestions.py#apex_in_scope]] requires the apex itself on the signed allow-list (R14). One crt.sh JSON request goes through [[attestra/runner/http_safe.py#passive_get]]. [[attestra/runner/ct_suggestions.py#parse_ct_entries]] strips wildcards, drops duplicates and names outside the apex. Results are suggestions only (copy or dismiss) — never added to scope and never scanned or resolved. Audited as `scope.suggestions.fetched`.

## Target ownership

Before the first scan, a lead or admin must prove the client controls each target. Three ways: DNS TXT record, well-known file, or owner confirm for private IPs.

Only users with the `asset.verify_ownership` permission (lead and admin, see [[attestra/auth/roles.py#ROLES]]) can check or confirm ownership. Each target gets a token from [[attestra/runner/ownership.py#ensure_token]]. The page shows what to publish using [[attestra/runner/ownership.py#instructions]]. When [[attestra/config.py#ownership_bypass_active]] ([[interfaces#Configuration#Ownership verification flag]]), the dispatch gate skips ownership via `ownership_required=false`; UI verify/confirm and audit remain. Engagement and asset pages show **Bypassed (local testing)** with [[attestra/config.py#BYPASS_STATUS]] when bypass is active and `ownership_verified_at` is unset — never as Verified — and keep Verify ownership details available. Bypass never invents `ownership_verified_at`. [[attestra/web/ui.py]] passes `ownership_bypass_active`, `signed_authorization_bypass_active`, and `bypass_status` into those templates; scan intro copy still branches on `*_required` helpers.

### DNS or file check

The Check now button does one DNS TXT lookup and at most one plain GET of the well-known file. It never scans and never follows redirects.

[[attestra/web/ui.py#verify_target_ownership]] calls [[attestra/services.py#verify_asset_ownership]], which runs [[attestra/runner/ownership.py#check]]. The DNS step looks for `attestra-verify=<token>` on the host, asking the resolvers from [[attestra/runner/ownership.py#dns_resolvers]] in order (public resolvers first, then the system one). The file step fetches [[attestra/runner/ownership.py#well_known_url]] only when the target is inside a valid signed authorization and in scope. Every result is explained in plain words. Success is audited as `asset.ownership_verified`, failure as `asset.ownership_check_failed`.

### Owner confirm for private IPs

Private network addresses have no DNS name and the file check refuses non-global IPs, so the owner can confirm control by hand instead (Option C).

[[attestra/web/ui.py#confirm_target_ownership]] calls [[attestra/services.py#confirm_private_ownership]]. It is allowed only when [[attestra/runner/authorization.py#owner_confirm_host]] returns a host: a literal IP inside [[attestra/runner/authorization.py#OWNER_CONFIRM_CIDRS]] (10/8, 172.16/12, 192.168/16, loopback, fc00::/7) or `localhost`. Public IPs, domain names, IP ranges and [[attestra/runner/authorization.py#BLOCKED_CIDRS]] never qualify. The target's environment must be in a valid signed authorization, the user must tick the confirm box, and must type who is confirming (name and role, at most 200 characters). No network call is made.

The confirmation sets `ownership_verified_at` and is audited as `asset.ownership_confirmed` with method [[attestra/runner/authorization.py#OWNER_CONFIRMED]] and the `confirmed_by` text. [[attestra/services.py#ownership_methods]] reads the audit log to show which method verified each target. There is no REST API route for these checks; they are in the web UI only.

### Set or reuse token

A lead or admin can paste another target's token on the target page so several hosts share one DNS TXT or well-known file.

[[attestra/services.py#set_ownership_token]] validates format via [[attestra/runner/ownership.py#set_token]] (16–64 urlsafe characters). Changing the token clears `ownership_verified_at` so the proof must be checked again. Audit `asset.ownership_token_set` stores only a four-character suffix, never the full token. [[attestra/web/ui.py#verify_target_ownership]] runs the ownership check from the target page.

## Evidence gallery

Finding evidence cards group originals, annotated derivatives, and honest capture failures without exposing storage paths.

[[attestra/models.py#Evidence]] stores provenance fields (`content_type`, `source_tool`, `observation_id`, `import_run_id`, `parent_evidence_id`, `role`, `redaction_status`, `capture_status`, `capture_failure_reason`, `annotation_meta`) via migration `0026_evidence_provenance`. [[attestra/services.py#add_evidence]] accepts those kwargs; screenshots skip text masking. [[attestra/services.py#record_capture_failure]] stores kind `capture_failure` without fabricating media. [[attestra/evidence/gallery.py#build_gallery]] partitions rows for UI/API and sets `visually_verified` only when a successful screenshot exists. Finding page [[attestra/web/ui.py#finding_page]] and `GET /api/findings/{fid}/evidence/gallery` both use the gallery helper. Downloads stay session/API authenticated ([[attestra/web/ui.py#ui_download_evidence]], [[attestra/api.py#download_evidence]]) and never return raw paths in JSON. See [[authorization#Evidence file security]].

### Annotated derivatives

Annotated screenshots are separate hashed rows linked to the original; the original bytes stay unchanged.

[[attestra/evidence/annotate.py#annotate_png]] draws non-obstructive borders and numbered markers with an optional caption strip (requires Pillow). [[attestra/services.py#attach_annotated_screenshot]] verifies the original SHA-256 under [[attestra/services.py#assert_evidence_path_readable]], writes role `annotated` with `parent_evidence_id`, and refuses annotating an already-annotated row. API: `POST /api/findings/{fid}/evidence/{eid}/annotate`.

## Evidence file security

Tenant checks, size caps, path containment, and client download limits for evidence uploads and downloads.

`POST /api/findings/{fid}/evidence` and `POST /api/findings/{fid}/transition` call [[attestra/services.py#assert_engagement_access]] before mutating a finding (same pattern as assign/gallery). API and proof screenshot uploads enforce [[attestra/config.py#EVIDENCE_MAX_BYTES]] (default 20 MB; portal keeps [[attestra/web/portal.py#PORTAL_EVIDENCE_MAX_BYTES]] at 5 MB). [[attestra/services.py#add_evidence]] accepts kind `client_upload` for portal remediation. Downloads use [[attestra/services.py#assert_evidence_path_readable]] / [[attestra/services.py#path_under_roots]] (`Path.is_relative_to`) instead of string `startswith`. Role `client_viewer` may download only [[attestra/services.py#CLIENT_DOWNLOADABLE_KINDS]] (`client_upload`) via [[attestra/services.py#client_may_download_evidence]].
