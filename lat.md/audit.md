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
- `scan.cancelled`: a queued or running scan was cancelled ([[attestra/services.py#cancel_scan]]); details include tool and profile.
- `user.invite`, `user.invite_accept`, `user.invite_revoke`, `user.role_change`, `user.enable` and `user.disable`: user account changes.
- `finding.comment.added` and `finding.comment.deleted`: comment thread writes on a finding ([[findings#Comments]]).
- `share.created`, `share.revoked`, and rate-limited `share.viewed`: tokenized share links ([[interfaces#Share links]]); view rows include time and IP.
- `alert.settings.update` and `alert.email.sent`: email alert settings and sends ([[interfaces#Email alerts]]); sent rows include event, count, and recipients count, never the body or SMTP password.
- `user.password_reset_issued`, `user.password_reset` and `user.password_set`: password changes; `user.password_set` comes from the CLI.
- `api_key.revoke`: an API key was revoked ([[attestra/auth/keys.py#revoke_api_key]]); details include `user_id` and `prefix`.
- `report.download`: a report download; the sealed file download adds `sealed=True`.
- `findings.exported`: a findings CSV download ([[attestra/reports/findings_csv.py#export_findings_csv]]); details include optional `asset_id` and `row_count`.
- `engagement.exported`: an engagement-level export (SARIF/OSCAL UI buttons, JSON via [[attestra/reports/engagement_export.py#export_engagement_json]], or Excel via [[attestra/reports/xlsx_export.py#export_engagement_xlsx]]); details include `format` (e.g. `json`, `xlsx`) and optional counts/`framework`.
- `scope.suggestions.fetched`: a CT subdomain suggestion lookup ([[attestra/runner/ct_suggestions.py#suggestions_for_engagement]]); details include `apex`, `count` and `requests`.
