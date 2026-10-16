# Audit log

Append-only, hash-chained event log. Every business write should call [[attestra/audit.py#record]].

## Chain

How each event links to the previous hash.

Each [[attestra/models.py#AuditEvent]] stores `prev_hash` and `hash`. Genesis is 64 zero hex digits ([[attestra/audit.py#GENESIS]]).

Digest covers previous hash, timestamp, actor, action, entity, entity_id, and details ([[attestra/audit.py#_digest]]).

## Verification

Detecting tampering or broken chains.

[[attestra/audit.py#verify]] walks events in id order and returns `(ok, first_bad_event_id)`.

Exposed at `GET /api/audit/verify` and CLI `verify-audit`.

## Storage

Where audit rows and related blobs live.

Audit rows live in the same SQLAlchemy database as engagements and findings ([[attestra/db.py]]). Evidence blobs live on disk under [[attestra/config.py#DATA_DIR]] subdirs created by [[attestra/config.py#ensure_dirs]].

## Append-only enforcement

Database triggers refuse UPDATE/DELETE on audit events.

SQLite triggers `audit_events_no_update` / `audit_events_no_delete` are installed by Alembic [[migrations/versions/0006_evidence_hardening.py]] and by [[attestra/db.py#_install_audit_triggers]] after `create_all`. Downloads of evidence and reports call [[attestra/audit.py#record]]. `GET /api/audit/export` returns events plus chain proof.

## Ownership, scan and user actions

Audit actions written by target ownership, scan requests and user accounts.

- `asset.ownership_verified` and `asset.ownership_check_failed`: result of a DNS TXT or well-known file check.
- `asset.ownership_confirmed`: a lead or admin recorded the owner's confirmation for a private IP.
- `scan.request` and `scan.refused`: a scan was queued, or the gate refused it with a reason.
- `user.invite`, `user.invite_accept`, `user.invite_revoke`, `user.role_change`, `user.enable` and `user.disable`: user account changes.
- `user.password_reset_issued`, `user.password_reset` and `user.password_set`: password changes; `user.password_set` comes from the CLI.
- `report.download`: a report download; the sealed file download adds `sealed=True`.