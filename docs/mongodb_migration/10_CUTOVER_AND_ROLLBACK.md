# Cutover and rollback

**Production cutover is not automatic.** Execute only with explicit authorization after backups and validation succeed.

## Preconditions

1. `attestra mongo-migrate validate` is green for source→target counts (document any known audit-chain historical break).
2. Mongo logical backup (`attestra backup`) and/or `mongodump` of the replica set verified restoreable.
3. Signing keys copied and report verify smoke-tested.
4. Application image/config uses `ATTESTRA_PERSISTENCE=mongo`, `ATTESTRA_STORAGE=mongo`, replica-set URI.
5. Workers and API drained / write freeze agreed.

## Cutover steps

1. Verify source backup + Mongo backup manifests.
2. Freeze source writes (maintenance window) or apply final incremental `mongo-migrate import --resume`.
3. Re-run `mongo-migrate validate`.
4. Quiesce API and workers.
5. Deploy Mongo-configured app + worker.
6. Smoke: `/api/health` (mongo ok), login, open engagement, verify-audit, verify-report if samples exist.
7. Reopen traffic and workers; monitor job claim / credit / audit errors.
8. Keep source DB read-only for rollback window.

## Rollback

- **Before Mongo accepts new writes:** point config back to `ATTESTRA_PERSISTENCE=sql` and prior SQL backup; discard unused Mongo DB if desired.
- **After Mongo accepted writes:** do **not** assume connection-string flip is enough. Restore SQL from pre-cutover backup **or** reverse-export (not shipped) plus reconcile post-cutover Mongo deltas. Prefer forward-fix on Mongo.

## RPO / RTO (deployment-dependent)

Logical `attestra backup` is crash-consistent for a quiet system, not a substitute for replica-set oplog PITR. State RPO/RTO from your MongoDB ops standards; do not invent guarantees.
