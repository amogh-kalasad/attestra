# Ownership and signed-authorization local bypasses

Secure local-testing bypasses (default **false** when unset). Bypass is effective only when `APP_ENV` is allowlisted (`local`, `test`, or `development`). Invalid values or bypass in `staging`/`production` fail startup via `validate_runtime_config`. Changing flags requires restarting the API and any workers (no hot reload).

| Variable | Helper | Default |
| --- | --- | --- |
| `APP_ENV` | `get_app_env()` | unset (OK when both bypasses false) |
| `BYPASS_TARGET_OWNERSHIP_VERIFICATION` | `ownership_bypass_active()` / `ownership_verification_required()` | false |
| `BYPASS_SIGNED_AUTHORIZATION_VERIFICATION` | `signed_authorization_bypass_active()` / `signed_authorization_required()` | false |

Status label when a gate is bypassed: `BYPASS_STATUS` (`BYPASSED_LOCAL`). Documented in `.env.example`, `README.md` Settings, and `SETUP_GUIDE.md`.

Legacy `OWNERSHIP_VERIFICATION` / `SIGNED_AUTHORIZATION` ON\|OFF flags were removed; accessing them raises `ConfigurationError` with a migration message.

## Effective bypass

```
ownership_bypass_active() = BYPASS_TARGET_OWNERSHIP_VERIFICATION AND APP_ENV in {local, test, development}
signed_authorization_bypass_active() = BYPASS_SIGNED_AUTHORIZATION_VERIFICATION AND APP_ENV in {local, test, development}
ownership_verification_required() = NOT ownership_bypass_active()
signed_authorization_required() = NOT signed_authorization_bypass_active()
```

## Where each flag reflects

### `BYPASS_TARGET_OWNERSHIP_VERIFICATION`

| Location | Behavior when bypass active |
| --- | --- |
| `attestra/config.py` | Parse / validate; refreshed in `validate_runtime_config` |
| `attestra/runner/gate.py` → `policy_input` | Passes `ownership_required=false` |
| `attestra/runner/policy.py` + `policy/scope.rego` | Skips “asset ownership not verified” for web_app/api/host |
| `attestra/web/ui.py` + `engagement.html` / `asset.html` | Shows `BYPASSED_LOCAL`; verify/confirm UI still available |
| Tests | `tests/test_ownership_verification_flag.py`, OPA case `ownership_not_required_allows` |

**Unchanged (not gated by this flag):** token issue/set, DNS/file/owner-confirm verify paths, ownership audit events, storage of `ownership_verified_at` (never fabricated by bypass).

### `BYPASS_SIGNED_AUTHORIZATION_VERIFICATION`

| Location | Behavior when bypass active |
| --- | --- |
| `attestra/config.py` | Parse / validate; refreshed in `validate_runtime_config` |
| `attestra/services.py#import_results` | Skips “must have valid authorization” and env allow-list on findings |
| `attestra/runner/authorization.py#scope_for_engagement` | Skips empty-auth refusal; still builds allow-list from engagement assets (SSRF) |
| `attestra/runner/gate.py` → `policy_input` | Passes `authorization_required=false` |
| `attestra/runner/policy.py` + `policy/scope.rego` | Skips “no valid authorization for asset environment” |
| `attestra/services.py` verify/confirm ownership | Skips “environment must be covered by auth” when recording ownership proof |
| `attestra/auth_web/role_scan.py` | Skips pre-check requiring a valid authorization |
| `attestra/web/ui.py` + `engagement.html` | Scan/import warnings and form disable respect `auth_required` / bypass banners |
| Tests | `tests/test_signed_authorization_flag.py`, OPA case `auth_not_required_allows` |

**Unchanged (not gated by this flag):** authorization document download RBAC (`authorization.document`), tenant isolation, path containment, SSRF/deny rules, ability to record authorizations in the UI, compliance process checks that *report* whether an auth exists.

### Entrypoints

`validate_runtime_config()` (subscription + APP_ENV + both bypass flags) is called from:

- API lifespan — `attestra/api.py`
- CLI `init` / `serve` / `worker` — `attestra/cli.py`

## Intentional non-gates

- Super Admin–only authorization **document download** stays enforced when signed-auth bypass is active.
- Ownership **UI verify/confirm** stays available when ownership bypass is active.
- `SUBSCRIPTION_SERVICE=OFF` does not turn these bypasses on.

## Checklist for operators

1. Set `APP_ENV=local` (or `test` / `development`) and the desired `BYPASS_*=true|false` in the process environment (see `.env.example`).
2. Restart API and workers.
3. Confirm `attestra init` / `serve` / `worker` start (invalid values or staging/production + bypass abort startup).
4. With bypass active, confirm only the matching gate is skipped; auth login, tenant isolation, and SSRF still apply. UI should show `BYPASSED_LOCAL`, not a verified status.
