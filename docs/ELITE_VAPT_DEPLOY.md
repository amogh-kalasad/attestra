# Elite automated security testing — developer notes

## Feature flag

```bash
ATTESTRA_AUTOMATED_VAPT_ENABLED=1
```

Off by default. API: `/api/automated-vapt/...`. Engagement UI card appears when enabled.

## Migration

```bash
alembic upgrade head   # includes 0034_automated_test_executions
```

## Local mocks

```bash
pytest tests/automated_vapt/ -q
python scripts/elite_e15_demo.py
```

Secure and vulnerable FastAPI mocks live under `tests/automated_vapt/fixtures/`. Prefer `http://localhost:...` asset URLs (`127.0.0.1` is SSRF-blocked).

## Credits

When `SUBSCRIPTION_SERVICE=ON`, queueing an Elite execution consumes **one** organization test-run credit (idempotent per execution id). Screenshots and HTTP captures inside that run do not consume extra credits.

## Implemented catalogue handlers

| ID | Handler |
| --- | --- |
| SCOPE_SMOKE | Scope + authorization gate |
| T01 | HTTPX capture |
| T02 | Browser screenshot (Playwright or injected capture_fn) |
| T03–T07 | Authn/authz/BOLA/tenant/disclosure modules |
| T08–T18 | Covered by validation/evidence/import/integration tests; some remain DEFERRED in live orchestrator until wired |

Gap matrix: `docs/ELITE_VAPT_GAP_ANALYSIS.md`.
