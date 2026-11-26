# Operator runbook — Production safe-mutation (Gap #3)

Supervised, one-time, four-eyes authorization for **T22** body mutation against a **customer-designated synthetic production test record**.

**Default: OFF.** Do not enable in production deployments without an explicit customer-authorized change window.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `ATTESTRA_AUTOMATED_VAPT_PRODUCTION_SAFE_MUTATION` | `0` | Master switch for the supervised path |
| `ATTESTRA_AUTOMATED_VAPT_MUTATION` | `0` | Ordinary T22 flag (still required for module registration paths) |
| `ATTESTRA_AUTOMATED_VAPT_ENABLED` | per deploy | Elite automated testing must be on |

Ordinary intrusive tests (SSRF, UPLOAD, XSSSTORE, and T22 without a grant) remain **hard-forbidden** on `production` / `prod` / `live` / `prd`.

## Roles and permissions

| Action | Roles |
|---|---|
| Request approval | `tester`, `lead`, `admin`, `super_admin` (+ `engagement.write`) |
| Approve / reject | `lead`, `admin`, `super_admin` — **must differ from requester** (user id and username) |
| Revoke | Approver roles, or the original requester |
| Queue execution with grant | `engagement.write` |

Server-side authorization is authoritative. The UI never grants mutation by itself.

## Approval lifecycle

1. **Request** — engagement UI card *Production safe-mutation approvals* or `POST /api/automated-vapt/engagements/{id}/mutation-approvals`.
2. **Approve** — separate lead/admin identity.
3. **Queue** — automated test form: select T22 (and active profile), paste/select the **approved** grant id in *Mutation approval id*.
4. **Execute** — worker runs orchestrator → policy validates grant → executor consumes nonce → before GET → mutate → after GET → restore → verify.
5. **Consume** — approval becomes `consumed`; replay fails.
6. **Restore failure** — execution stops further mutations; approval records `restore_verified=false`; treat as a high-priority ops incident.

Statuses: `pending` → `approved` | `denied` | `revoked` | `expired` → `consumed`.

## Storage and audit

- Approvals: `DATA_DIR/mutation_approvals/engagement_{id}.json`
- Lifecycle audit: `mutation_approval.{requested|approved|rejected|revoked}` via Attestra audit log
- Evidence: executor embeds before/mutation/after/restore/verified payloads in the case result

Retain approval JSON and audit rows per your tenant retention policy (recommend ≥ engagement retention).

## Monitoring / alerting

Alert when:

- `restore_verified` is false on a consumed approval
- Case status `FAILED` with skip_reason `restoration_verification_failed` or `production_safe_mutation_stop`
- Repeated `production_safe_mutation_denied` with unexpected reasons during an authorized window

## Failure recovery (manual restoration)

1. Open the approval row (UI or JSON store); note `test_record_id`, `approved_fields`, `baseline` from evidence if present.
2. Manually restore the synthetic record to baseline using the documented cleanup plan.
3. Independently GET-verify.
4. Record the manual restore in the engagement comments / ops ticket.
5. Do **not** re-use the consumed approval; request a new grant if a retest is needed.

## Rollback

1. Set `ATTESTRA_AUTOMATED_VAPT_PRODUCTION_SAFE_MUTATION=0` and restart workers/API.
2. Revoke any `pending`/`approved` grants via UI or API.
3. Ordinary production hard-ban for intrusive tests remains in force.

## Security constraints (non-negotiable)

- No DELETE
- No bulk / unrelated-record writes
- Only approved fields/values on the named synthetic record
- No silent fallback to ordinary intrusive T22 on production
- No automatic retries that could duplicate a mutation
- Fail closed when flag, approval, scope, evidence transport, or restore verification is missing/uncertain

## Known limitations

- Approvals are file-backed JSON (not a DB table); multi-node deploys need shared `DATA_DIR` or a future store migration.
- Synthetic HTTP transport requires a ready auth session + httpx client on the execution.
- Customer production validation remains a **separate, explicitly authorized** activity outside development tests.

## Related docs

- `docs/ai_security/PRODUCTION_SAFE_MUTATION.md`
- `docs/ai_security/SHIELDBYTE_GAP_CLOSURE_AUDIT.md`
- Tests: `tests/automated_vapt/test_mutation_approval.py`, `test_production_safe_executor.py`, `test_mutation_approval_api.py`
