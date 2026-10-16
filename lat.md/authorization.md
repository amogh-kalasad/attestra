# Authorization and scope

No valid signed client authorization means no import. Runner dispatch adds URL/path/image checks, deny rules, and ownership verification ([[runner#Scope authorization]]).

## Authorization record

Fields and validity rules for the signed client authorization document.

[[attestra/models.py#Authorization]] stores:

- Hashed signed document (write-once path + SHA-256)
- Signer, rules of engagement text
- `signed_on` / `expires_on` validity window
- Optional `environments` allow-list (empty means all, for older records)

Validity: [[attestra/models.py#Authorization#is_valid]]. Environment coverage: [[attestra/models.py#Authorization#covers]].

Created through [[attestra/services.py#add_authorization]].

## Import gate

Business rule that blocks result ingestion without a live authorization.

[[attestra/services.py#import_results]] fails if no currently valid authorization exists on the engagement.

Findings matched to assets must land in environments covered by [[attestra/services.py#authorized_environments]]. Otherwise the import is rejected.

## Assets as allow-list

In-scope targets for an engagement and how import locations are matched.

[[attestra/models.py#Asset]] records in-scope targets: kind, identifier, environment, criticality, exposure, `in_cde`, `intrusive_allowed`, `test_types`.

Asset matching for imported locations: [[attestra/services.py#match_asset]] (host/URL normalization via [[attestra/services.py#_asset_key]]).

## Identity

Bearer API keys and signed session cookies identify callers; roles gate every route.

[[attestra/api.py#get_principal]] resolves `Authorization: Bearer` via [[attestra/auth/keys.py#authenticate_api_key]] or the `attestra_session` cookie via [[attestra/auth/session.py#read_session]]. [[attestra/api.py#require]] checks [[attestra/auth/roles.py#has_permission]] against the six roles in [[attestra/auth/roles.py#ROLES]]. Share links use `share.create` and `share.manage` (admin, lead, tester); see [[interfaces#Share links]].

UI login: [[attestra/web/ui.py#login]]. Passwords use scrypt ([[attestra/auth/keys.py#hash_password]]). Report workflow enforces distinct author / QA / signer user ids ([[attestra/reports/render.py#sign_report]]).

Optional Keycloak OIDC sits behind `ATTESTRA_OIDC_ENABLED` ([[attestra/auth/oidc.py#oidc_enabled]], [[attestra/auth/oidc.py#validate_id_token_claims]]).

## Tenant isolation

Queries and storage are scoped per tenant for non-admin principals.

[[attestra/services.py#scoped]] and [[attestra/services.py#tenant_ids_for]] filter engagement access. Evidence/imports/reports land under `DATA_DIR/tenants/<id>/` via [[attestra/services.py#_store]]. Rate limits and security headers: [[attestra/api_security.py#RateLimitMiddleware]], [[attestra/api_security.py#SecurityHeadersMiddleware]]. Webhook and workflow-rule creates ([[attestra/webhooks/routes.py#_tenant_ok]]) require the tenant row to exist — `tenant_ids_for` returning `None` (unrestricted lead/admin) means all tenants, not skip existence; missing ids return 404.

## Runner scope

URL/path/image allow-list and SSRF checks used before scanner dispatch.

See [[runner#Scope authorization]]. [[attestra/runner/authorization.py#authorize_target]] and [[attestra/runner/gate.py#check]] enforce engagement scope at enqueue and resume.

## CT subdomain suggestions

Passive Certificate Transparency suggestions for an in-scope apex; never auto-added to scope.

[[attestra/runner/ct_suggestions.py#suggestions_for_engagement]] runs only when the user clicks Find subdomain suggestions. [[attestra/runner/ct_suggestions.py#apex_in_scope]] requires the apex itself on the signed allow-list (R14). One crt.sh JSON request goes through [[attestra/runner/http_safe.py#passive_get]]. [[attestra/runner/ct_suggestions.py#parse_ct_entries]] strips wildcards, drops duplicates and names outside the apex. Results are suggestions only (copy or dismiss) — never added to scope and never scanned or resolved. Audited as `scope.suggestions.fetched`.

## Target ownership

Before the first scan, a lead or admin must prove the client controls each target. Three ways: DNS TXT record, well-known file, or owner confirm for private IPs.

Only users with the `asset.verify_ownership` permission (lead and admin, see [[attestra/auth/roles.py#ROLES]]) can check or confirm ownership. Each target gets a token from [[attestra/runner/ownership.py#ensure_token]]. The page shows what to publish using [[attestra/runner/ownership.py#instructions]].

### DNS or file check

The Check now button does one DNS TXT lookup and at most one plain GET of the well-known file. It never scans and never follows redirects.

[[attestra/web/ui.py#verify_target_ownership]] calls [[attestra/services.py#verify_asset_ownership]], which runs [[attestra/runner/ownership.py#check]]. The DNS step looks for `attestra-verify=<token>` on the host, asking the resolvers from [[attestra/runner/ownership.py#dns_resolvers]] in order (public resolvers first, then the system one). The file step fetches [[attestra/runner/ownership.py#well_known_url]] only when the target is inside a valid signed authorization and in scope. Every result is explained in plain words. Success is audited as `asset.ownership_verified`, failure as `asset.ownership_check_failed`.

### Owner confirm for private IPs

Private network addresses have no DNS name and the file check refuses non-global IPs, so the owner can confirm control by hand instead (Option C).

[[attestra/web/ui.py#confirm_target_ownership]] calls [[attestra/services.py#confirm_private_ownership]]. It is allowed only when [[attestra/runner/authorization.py#owner_confirm_host]] returns a host: a literal IP inside [[attestra/runner/authorization.py#OWNER_CONFIRM_CIDRS]] (10/8, 172.16/12, 192.168/16, loopback, fc00::/7) or `localhost`. Public IPs, domain names, IP ranges and [[attestra/runner/authorization.py#BLOCKED_CIDRS]] never qualify. The target's environment must be in a valid signed authorization, the user must tick the confirm box, and must type who is confirming (name and role, at most 200 characters). No network call is made.

The confirmation sets `ownership_verified_at` and is audited as `asset.ownership_confirmed` with method [[attestra/runner/authorization.py#OWNER_CONFIRMED]] and the `confirmed_by` text. [[attestra/services.py#ownership_methods]] reads the audit log to show which method verified each target. There is no REST API route for these checks; they are in the web UI only.
