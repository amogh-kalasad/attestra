# Security and tenancy validation

Evidence for Phase 5 tenant isolation work on the Mongo repository layer.

## Enforcement model

| Concern | Implementation |
|---|---|
| Scope type | `tenant_ids: frozenset[int] \| None` (`None` = unrestricted) |
| Direct tenant fields | `tenant_filter()` |
| Via engagement | `via_engagement_filter()` / `EngagementRepository.assert_access` |
| Cross-tenant read | `TenantAccessDenied` (LookupError) — same “not found” posture as SQL services |
| Automated executions | `tenant_id` index + filter required (closes SQL RLS gap in Mongo layer) |
| Secrets | Fernet ciphertext only in `credential_secrets`; signing keys stay on filesystem/KMS |

## Automated evidence

```text
pytest tests/persistence/test_mongo_foundation.py -q
# includes test_cross_tenant_isolation, test_asset_authorization_finding_scoped

pytest tests/persistence/ -q
# 2026-11-03: 14 passed (foundation + phase6_8 + backup) against replica set
```

Phase 9 backup restore refuses on SHA-256 manifest mismatch (`test_mongo_backup_restore_roundtrip`).

## Remaining (not yet VERIFIED)

- Full conversion of every SQLAlchemy service/route to Mongo repositories
- Staff “platform operator unrestricted when no memberships” parity review for Mongo UoW
- Webhook secret encryption-at-rest
- End-to-end API cross-tenant matrix against Mongo-backed app process
