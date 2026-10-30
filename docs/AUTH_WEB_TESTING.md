# Authenticated website testing (Phase 6)

Optional security-testing workflow for authorized, authenticated crawling of in-scope web applications. **Off by default.**

## Feature flags

| Variable | Default | Meaning |
|---|---|---|
| `ATTESTRA_AUTH_WEB_ENABLED` | off | Enable authenticated website testing (`1` / `true` / `yes`) |
| `ATTESTRA_AUTH_WEB_MAX_ROUTES` | `100` | Cap on discovered/visited routes per run |
| `ATTESTRA_AUTH_WEB_MAX_DEPTH` | `5` | Max crawl depth from the start URL |
| `ATTESTRA_AUTH_WEB_MAX_DURATION_S` | `600` | Soft time budget for an auth-web run (seconds) |
| `ATTESTRA_AUTH_WEB_RATE_PER_HOST` | `2` | Requests per second per host |
| `ATTESTRA_AUTH_WEB_CONCURRENCY` | `2` | Parallel request workers |

## Credential encryption

Test-account passwords and similar secrets are stored outside normal DB columns via the engagement credential store (`attestra.credentials.store`). Rows keep only an opaque `secret_ref`.

| Variable | Default | Meaning |
|---|---|---|
| `ATTESTRA_CREDENTIAL_FERNET_KEY` | unset | URL-safe base64 32-byte Fernet key (required in production) |
| `ATTESTRA_CREDENTIAL_ALLOW_EPHEMERAL` | off | Dev/tests only: generate a process-local key when the Fernet key is unset |

Generate a key (do not commit it):

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Local mock website

`tests/fixtures/auth_web_mock_app.py` is a synthetic FastAPI app for offline smoke tests (no external network):

- `GET /` — public
- `GET` / `POST /login` — form login; sets session cookies
- `GET /app`, `GET /app/settings` — require an authenticated session (unauthenticated callers get 302 to `/login`)
- `GET /admin` — requires role `admin` (403 otherwise)
- `GET /logout` — clears session cookies

Synthetic users (not real credentials): `viewer` / `viewer-pass`, `admin` / `admin-pass`.

Run the smoke suite:

```bash
pytest tests/test_phase6_auth_mock_smoke.py -q
```

## Elite secure / vulnerable mocks

For Elite automated security-testing fixtures (Account A/B, `proj-a`/`proj-b`, intentional BOLA and exposure cases), use:

- `tests/automated_vapt/fixtures/mock_secure_app.py` — negative control
- `tests/automated_vapt/fixtures/mock_vulnerable_app.py` — positive control (local-only)

Both expose `GET /__attestra_mock__` with `mode` and `local_only`. See `docs/ELITE_VAPT_GAP_ANALYSIS.md`.

```bash
pytest tests/automated_vapt/test_e2_mock_apps.py -q
```
