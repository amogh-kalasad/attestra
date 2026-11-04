# Source-to-target mapping

SQL table → Mongo collection mapping used by Phases 3–5 implementation. Integer `_id` equals legacy PK.

| SQL table | Mongo collection | Repository (initial) | Notes |
|---|---|---|---|
| tenants | tenants | TenantRepository | |
| users | users | UserRepository | |
| tenant_memberships | tenant_memberships | MembershipRepository | |
| api_keys | api_keys | ApiKeyRepository | global |
| engagements | engagements | EngagementRepository | tenant filtered |
| assets | assets | AssetRepository | via engagement |
| authorizations | authorizations | AuthorizationRepository | via engagement |
| scope_rules | scope_rules | ScopeRuleRepository | via engagement |
| findings | findings | FindingRepository | via engagement |
| jobs | jobs | JobRepository | atomic claim |
| audit_events | audit_events + audit_chain_head | AuditRepository | serialized append |
| tenant_credit_accounts / credit_transactions | same names | CreditRepository | multi-doc txn |
| (files) | GridFS `attestra_artifacts` + artifacts | MongoStorage / ArtifactRepository | `mongo://` URIs |
| credential ciphertext | credential_secrets | EncryptedMongoStore | Fernet key outside DB |

Remaining SQL tables are declared in `collections.DOMAIN_COLLECTIONS` and indexed in `indexes.ensure_indexes`; dedicated repository modules land in later phases as services are converted.
