# Data migration runbook

Safe, repeatable SQL → MongoDB import. **Never mutates the source database.**

## Prerequisites

- Source backup verified (see `02_BASELINE_AND_INTEGRITY.md`)
- MongoDB replica set reachable (`ATTESTRA_MONGODB_URI`)
- `pymongo` installed

## Commands

```bash
attestra mongo-migrate assess [--source URL] [--data-dir PATH]
attestra mongo-migrate plan [--source URL]
attestra mongo-migrate import [--source URL] [--mongo-uri URI] [--mongo-db NAME] [--run-id ID] [--resume] [--dry-run]
attestra mongo-migrate validate [--source URL] [--mongo-uri URI] [--mongo-db NAME]
attestra mongo-migrate status --run-id ID
```

## Modes

| Mode | Behavior |
|---|---|
| Dry-run | Counts / plan only (`--dry-run` on import) |
| Test migration | Import into isolated `ATTESTRA_MONGODB_DB` |
| Resume | `--resume --run-id` continues from checkpoints |
| Production | **Requires explicit human authorization** — not automatic |

## Integrity checks (`validate`)

- Per-table source vs target counts
- Max primary-key comparison
- Target audit-chain verify (historical breaks preserved; not rewritten)

## Artifact note

Binary GridFS copy is staged separately (Phase 4 storage); this engine migrates relational rows and seeds ID sequences. File trees under `DATA_DIR` should be copied with hash verification before cutover.
