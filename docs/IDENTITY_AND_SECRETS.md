# Identity (Keycloak / OIDC) and secrets (Vault / OpenBao) - Step 6.4

Both features are **off by default**. Local auth (API keys + signed session cookies) and
environment-variable secrets keep working unchanged.

## 1. OIDC bearer tokens

When `ATTESTRA_OIDC_ENABLED=true`, `/api/*` also accepts an IdP **access token** as
`Authorization: Bearer <jwt>`. API keys are tried first; a token that looks like a JWT is then
validated by `attestra/auth/oidc.py` (`validate_access_token`) with `attestra/auth/jwt_verify.py`:

- signature against the realm JWKS (RS256 / ES256 only; `none` and HMAC are refused), with caching
  and a rate-limited refetch on an unknown `kid` (key rotation);
- `iss` must equal `ATTESTRA_OIDC_ISSUER`;
- `aud` must contain `ATTESTRA_OIDC_AUDIENCE` (default: the client id), or `azp` must equal it;
- `exp` / `nbf` with 60 s leeway.

| Variable | Default | Meaning |
|---|---|---|
| `ATTESTRA_OIDC_ENABLED` | `false` | Turn OIDC on |
| `ATTESTRA_OIDC_ISSUER` | - | e.g. `https://sso.example.com/realms/attestra` |
| `ATTESTRA_OIDC_CLIENT_ID` | - | Keycloak client id |
| `ATTESTRA_OIDC_AUDIENCE` | client id | Expected audience |
| `ATTESTRA_OIDC_JWKS_URL` | `<issuer>/protocol/openid-connect/certs` | JWKS endpoint |
| `ATTESTRA_OIDC_ALGORITHMS` | `RS256,ES256` | Allowed algorithms |
| `ATTESTRA_OIDC_USERNAME_CLAIM` | `preferred_username` | Username claim (falls back to `sub`) |
| `ATTESTRA_OIDC_TENANT_CLAIM` | `attestra_tenant_id` | Integer tenant id for client users |
| `ATTESTRA_OIDC_AUTO_PROVISION` | `true` | Create a local user row on first login |

**Role mapping** (`map_oidc_role`): realm roles, client roles or groups named `admin`, `lead`,
`tester`, `reviewer`, `client_viewer`, `auditor` (or `attestra-<role>`), first match in that order;
no match means `client_viewer`. A `client_viewer` **must** carry a tenant claim for an existing
tenant, otherwise the token is refused. Role and tenant are refreshed from the token on every
request (the IdP is the source of truth). Provisioned users get `password_hash="oidc"`, so they
can never log in with a local password.

**Keycloak:** `deploy/keycloak/attestra-realm.example.json` is an example realm with the six
roles, TOTP as a default required action (MFA), a confidential PKCE client, an audience mapper
and the `attestra_tenant_id` user-attribute mapper. Import it (VERIFY on your Keycloak version):

    kc.sh import --file attestra-realm.example.json

Not done yet: the browser login (authorization-code + PKCE callback) in the web UI; it still
uses local passwords. `build_authorization_url` exists for that step.

## 2. Secrets provider

`attestra/secret_store.py` resolves `api_key_pepper`, `session_secret` (and
`oidc_client_secret` for the future UI flow). Used by `auth/keys.py` (API key pepper) and
`auth/session.py` (cookie signing).

| Variable | Default | Meaning |
|---|---|---|
| `ATTESTRA_SECRETS_BACKEND` | `env` | `env` or `vault` (alias `openbao`) |
| `ATTESTRA_VAULT_ADDR` | - | `https://vault.example:8200` |
| `ATTESTRA_VAULT_TOKEN_FILE` / `ATTESTRA_VAULT_TOKEN` | - | Token (file preferred: Vault Agent sink) |
| `ATTESTRA_VAULT_KV_MOUNT` | `secret` | KV v2 mount |
| `ATTESTRA_VAULT_KV_PATH` | `attestra` | Secret path |
| `ATTESTRA_VAULT_NAMESPACE` | - | Optional namespace header |

The provider reads `GET /v1/<mount>/data/<path>` once and caches it for 5 minutes. A key missing
in Vault falls back to the env value. Tokens and values are never logged; errors show only the
URL and exception type.

Store the values (OpenBao CLI shown; `vault` is identical):

    bao kv put secret/attestra api_key_pepper=<random> session_secret=<random>

Rotating `api_key_pepper` invalidates all API keys; rotating `session_secret` logs everyone out.

Local smoke test without Docker (dev server, in-memory, throwaway root token):

    bao server -dev -dev-root-token-id=<throwaway>
    $env:BAO_ADDR="http://127.0.0.1:8200"; bao kv put secret/attestra api_key_pepper=dev1 session_secret=dev2
    $env:ATTESTRA_SECRETS_BACKEND="vault"; $env:ATTESTRA_VAULT_ADDR="http://127.0.0.1:8200"

## 3. Helm

`values.yaml` gains `oidc.*` and `secretsStore.*`. With `secretsStore.backend=vault` the chart
no longer requires `secrets.apiKeyPepper`/`sessionSecret`; the Vault token comes from an existing
Kubernetes Secret (`secretsStore.vault.tokenSecret`). Add the Keycloak and Vault CIDRs to
`networkPolicy.appEgressCIDRs`.

## Still open for 6.4

- Per-tenant data keys from Vault/OpenBao **Transit** for envelope encryption of raw evidence
  (`attestra/storage`) - not implemented.
- Web UI OIDC login flow (above).
- Kubernetes auth method for Vault (instead of a token Secret).
