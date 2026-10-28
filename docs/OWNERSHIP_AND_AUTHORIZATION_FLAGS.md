# Ownership and signed-authorization flags

Runtime ON/OFF switches (default **ON** when unset). Invalid values fail startup via `validate_runtime_config`. Changing either flag requires restarting the API and any workers (no hot reload).

| Variable | Helper | Default |
| --- | --- | --- |
| `OWNERSHIP_VERIFICATION` | `ownership_verification_required()` | ON |
| `SIGNED_AUTHORIZATION` | `signed_authorization_required()` | ON |

Documented in `.env.example`, `README.md` Settings, and `SETUP_GUIDE.md`.

## Where each flag reflects

### `OWNERSHIP_VERIFICATION`

| Location | Behavior when OFF |
| --- | --- |
| `attestra/config.py` | Parse / validate; refreshed in `validate_runtime_config` |
| `attestra/runner/gate.py` → `policy_input` | Passes `ownership_required=false` |
| `attestra/runner/policy.py` + `policy/scope.rego` | Skips “asset ownership not verified” for web_app/api/host |
| `attestra/web/ui.py` + `engagement.html` / `asset.html` | Shows “not required” notice; verify/confirm UI still available |
| Tests | `tests/test_ownership_verification_flag.py`, OPA case `ownership_not_required_allows` |

**Unchanged (not gated by this flag):** token issue/set, DNS/file/owner-confirm verify paths, ownership audit events, storage of `ownership_verified_at`.

### `SIGNED_AUTHORIZATION`

| Location | Behavior when OFF |
| --- | --- |
| `attestra/config.py` | Parse / validate; refreshed in `validate_runtime_config` |
| `attestra/services.py#import_results` | Skips “must have valid authorization” and env allow-list on findings |
| `attestra/runner/authorization.py#scope_for_engagement` | Skips empty-auth refusal; still builds allow-list from engagement assets (SSRF) |
| `attestra/runner/gate.py` → `policy_input` | Passes `authorization_required=false` |
| `attestra/runner/policy.py` + `policy/scope.rego` | Skips “no valid authorization for asset environment” |
| `attestra/services.py` verify/confirm ownership | Skips “environment must be covered by auth” when recording ownership proof |
| `attestra/auth_web/role_scan.py` | Skips pre-check requiring a valid authorization |
| `attestra/web/ui.py` + `engagement.html` | Scan/import warnings and form disable respect `auth_required` |
| Tests | `tests/test_signed_authorization_flag.py`, OPA case `auth_not_required_allows` |

**Unchanged (not gated by this flag):** authorization document download RBAC (`authorization.document`), tenant isolation, path containment, SSRF/deny rules, ability to record authorizations in the UI, compliance process checks that *report* whether an auth exists.

### Entrypoints

`validate_runtime_config()` (all three ON/OFF flags) is called from:

- API lifespan — `attestra/api.py`
- CLI `init` / `serve` / `worker` — `attestra/cli.py`

## Soft gaps (messaging / status only)

These still mention authorization or ownership without branching on the flags. They are informational, not enforcement holes:

| File | Note |
| --- | --- |
| `attestra/web/templates/engagement.html` (~scan intro copy) | Static text still says scans need valid signed authorization and verified ownership |
| `attestra/web/templates/engagement.html` (target `<option>` labels) | May show “environment not authorized” / “not verified” even when the matching gate is OFF |
| `attestra/api.py` engagement payload `authorized` | Reflects whether any auth `is_valid()`, not the env flag |
| `attestra/compliance/engine.py` `has_valid_authorization` | Compliance evidence status; intentionally independent of the runtime bypass |

## Intentional non-gates

- Super Admin–only authorization **document download** stays enforced when `SIGNED_AUTHORIZATION=OFF`.
- Ownership **UI verify/confirm** stays available when `OWNERSHIP_VERIFICATION=OFF`.
- `SUBSCRIPTION_SERVICE=OFF` does not turn these flags off.

## Checklist for operators

1. Set `OWNERSHIP_VERIFICATION` / `SIGNED_AUTHORIZATION` to `ON` or `OFF` in the process environment (see `.env.example`).
2. Restart API and workers.
3. Confirm `attestra init` / `serve` / `worker` start (invalid values abort startup).
4. With `OFF`, confirm only the matching gate is skipped; auth login, tenant isolation, and SSRF still apply.
