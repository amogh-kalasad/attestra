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

[[attestra/api.py#get_principal]] resolves `Authorization: Bearer` via [[attestra/auth/keys.py#authenticate_api_key]] or the `attestra_session` cookie via [[attestra/auth/session.py#read_session]]. [[attestra/api.py#require]] checks [[attestra/auth/roles.py#has_permission]] against the six roles in [[attestra/auth/roles.py#ROLES]].

UI login: [[attestra/web/ui.py#login]]. Passwords use scrypt ([[attestra/auth/keys.py#hash_password]]). Report workflow enforces distinct author / QA / signer user ids ([[attestra/reports/render.py#sign_report]]).

Optional Keycloak OIDC sits behind `ATTESTRA_OIDC_ENABLED` ([[attestra/auth/oidc.py#oidc_enabled]], [[attestra/auth/oidc.py#validate_id_token_claims]]).

## Tenant isolation

Queries and storage are scoped per tenant for non-admin principals.

[[attestra/services.py#scoped]] and [[attestra/services.py#tenant_ids_for]] filter engagement access. Evidence/imports/reports land under `DATA_DIR/tenants/<id>/` via [[attestra/services.py#_store]]. Rate limits and security headers: [[attestra/api_security.py#RateLimitMiddleware]], [[attestra/api_security.py#SecurityHeadersMiddleware]].
