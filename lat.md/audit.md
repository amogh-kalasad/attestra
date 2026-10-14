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
