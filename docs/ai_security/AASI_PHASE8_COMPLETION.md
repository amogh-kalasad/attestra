# AASI Phase 8 completion report

Branch: `attestra-asi-bundle`. Date: 2026-11-23.

## Summary

Phase 8 environment templates landed: operator-facing `.env.example` gained AI narratives, AASI knobs, and commented AI scanner image placeholders; `.env.production.example` was created with production-safe defaults (AASI/AI off, bypasses false, secret placeholders only). Inventory and draft docs remain the reference for the full 118-variable list.

## Deliverables

| Item | State |
|---|---|
| `docs/ai_security/AASI_ENV_INVENTORY.md` | Existing (118 vars) |
| `docs/ai_security/AASI_PHASE8_ENV_DRAFT.md` | Existing (V4 safe-defaults table) |
| `.env.example` AASI / AI / image blocks | **Updated** (placeholders only) |
| `.env.production.example` | **Created** |
| Real Garak / Promptfoo / SafeLabs digests | Deferred to Phase 9 (`REPLACE_AFTER_INSPECT`) |
| Proposed `ATTESTRA_AASI_THIRD_PARTY_DATA` / `ATTESTRA_AASI_EXTERNAL_JUDGE` | Not shipped in examples until implemented in config |

## Variables added to examples

### AI narratives (`docs/AI_NARRATIVES.md`)

- `ATTESTRA_AI_NARRATIVES=off`
- `ATTESTRA_AI_PROVIDER=ollama`
- `ATTESTRA_AI_BASE_URL` (local default in `.env.example`; internal placeholder comment in production example)
- `ATTESTRA_AI_MODEL=llama3.1`
- `ATTESTRA_AI_API_KEY` (commented placeholder; prefer `secret_store` / Vault)
- `ATTESTRA_AI_TENANTS_OFF` (commented)

### AASI (`attestra/config.py`)

- `ATTESTRA_AASI=off`
- `ATTESTRA_AASI_MAX_ITERATIONS=8`
- `ATTESTRA_AASI_MAX_TASKS=32`
- `ATTESTRA_AASI_MAX_MODEL_CALLS=40`
- `ATTESTRA_AASI_MAX_TOKENS=50000`
- `ATTESTRA_AASI_MAX_WALL_CLOCK_S=1800`
- `ATTESTRA_AASI_RETRY_LIMIT=2`
- `ATTESTRA_AASI_REQUIRE_APPROVAL=on`

### AI scanner images (commented)

- `ATTESTRA_IMAGE_GARAK=…@sha256:REPLACE_AFTER_INSPECT`
- `ATTESTRA_IMAGE_PROMPTFOO=…@sha256:REPLACE_AFTER_INSPECT`
- `ATTESTRA_IMAGE_SAFELABS=…@sha256:REPLACE_AFTER_INSPECT`

## Production safety defaults

- `APP_ENV=production`
- Bypass flags `false`
- Feature flags fail-closed (`ATTESTRA_AUTOMATED_VAPT_*` / probes / discovery off)
- Intrusive allowlist without `production`
- AASI and AI narratives **off**; approval **on** when AASI is later enabled
- No real API keys, Mongo passwords, or signing secrets in either example file

## Secret handling

- Examples contain placeholders only.
- Do not commit real `.env` / `.env.production` values.
- Prefer Vault/`secret_store` for `ai_api_key` over `ATTESTRA_AI_API_KEY` in shared environments.
- K-04: staging/production refuse default session/pepper secrets.

## Next

1. Phase 9: replace AI image `REPLACE_AFTER_INSPECT` digests after `docker inspect`; reconcile Promptfoo registry string (`docker.io` vs `ghcr.io`).
2. Optionally inject AASI/AI flags into `compose.yaml` (still default off).
3. Wire proposed third-party-data / external-judge flags only when implemented.
4. Refresh `AASI_IMPLEMENTATION_STATUS.md` Phase 8 row when operators accept these templates.
