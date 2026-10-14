# Authorization and scope

No valid signed client authorization means no import. This is the v0.1 scope gate (ISO A.8.34 / PCI 11.4.1 spirit).

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

## Identity placeholder

Temporary actor identity until SSO lands.

Write APIs require `X-Attestra-Actor` ([[attestra/api.py#actor]]). This is not SSO. Replace with Keycloak OIDC and RBAC before shared deployment.
