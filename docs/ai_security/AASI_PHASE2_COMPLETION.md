# AASI Phase 2 completion report

Branch: `attestra-asi-bundle`. Date: 2026-11-23.

## Summary

AI-security scanners execute through Attestra's existing adapter SDK. Images remain digest-pinned (placeholders refused until operators pin real digests). Coverage ledger gains `origin=catalogue|aasi`.

## Components

- Adapters: `garak`, `promptfoo`, `safelabs` registered (17 total adapters)
- `ai_app` authorized as URL target in `runner/authorization.py`
- Placeholder image keys in `config._PLACEHOLDER_IMAGES` + comments in `docker/scanner-digests.env`
- Coverage `origin` field + `ai_tool_outcome_to_status` → `NOT_TESTED`

## Tests

31 passed (adapter unit + coverage origin). `lat check` passed.

## Limits

- Real image digests not yet verified via `docker inspect` (placeholders refused at runtime)
- End-to-end container execution against a local synthetic AI target deferred until digests + lab target exist

## Next

Phase 3 — native `attestra/aasi/` recommend-only orchestration.
