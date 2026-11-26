# Production safe-mutation (ShieldByte Gap #3)

Supervised, one-time, four-eyes authorization for **T22-style** body mutation against a **customer-designated synthetic production test record**.

## Defaults

| Flag | Default | Meaning |
|---|---|---|
| `ATTESTRA_AUTOMATED_VAPT_MUTATION` | off | Ordinary T22 (dev/demo allowlist only) |
| `ATTESTRA_AUTOMATED_VAPT_PRODUCTION_SAFE_MUTATION` | off | Supervised production path |

Ordinary intrusive tests (**SSRF**, **UPLOAD**, **XSSSTORE**, and T22 without a grant) remain **hard-forbidden** on `production` / `prod` / `live` / `prd`.

## Requirements for a production T22 send

1. Both mutation flags as needed (`MUTATION` for T22 env flag + `PRODUCTION_SAFE_MUTATION`).
2. Execution profile `active` or `intrusive`.
3. Scope policy allows (signed auth, ownership, window, intrusive_allowed).
4. Four-eyes approval record (`attestra.automated_vapt.core.mutation_approval`):
   - Exact tenant, engagement, asset
   - Exact origin, endpoint, method (`POST`/`PUT`/`PATCH` only — **never DELETE**)
   - Exact synthetic `test_record_id`
   - Explicit `approved_fields` (+ optional values)
   - Cleanup/restore plan
   - Unexpired, status `approved`, one-time `nonce`
5. Requester ≠ approver (user id and username).
6. Grant consumed once at execution; replay denied.

## Module

- Store: `DATA_DIR/mutation_approvals/engagement_{id}.json`
- Policy: `intrusive_policy.decide_from_policy_input(..., production_grant=...)`
- Reason codes: `production_safe_mutation_allowed` / `production_safe_mutation_denied`

## Safety

- No arbitrary body injection — only approved fields/values.
- No agent/scanner boolean as approval.
- Cross-tenant access denied.
- Restoration verification must succeed before claiming safe restore; failures stop further mutations (caller responsibility).

## Tests

`tests/automated_vapt/test_mutation_approval.py`

Do **not** run live mutations against real customer production data during development.
