# AASI Phase 9 completion report

Branch: `attestra-asi-bundle`. Date: 2026-11-23.

## Summary

Phase 9 documents Docker / deployment practices for AASI without enabling new required
Compose services. The main app image remains scanner-free; AI tools stay digest-pinned
isolated containers; `ATTESTRA_AASI` defaults off. Operators get a validate-env stub and
commented optional pull notes only.

## Deliverables

| Item | Path | Notes |
|---|---|---|
| Deployment guide | `docs/ai_security/AASI_DOCKER_DEPLOYMENT.md` | App image practices, isolation, digest pins (Garak/Promptfoo/SafeLabs/PyRIT reserved), no-privileged, resource limits, health/validate commands, rollback |
| This completion note | `docs/ai_security/AASI_PHASE9_COMPLETION.md` | Status snapshot |
| Env validate stub | `scripts/aasi/validate_aasi_env.py` | Checks `ATTESTRA_AASI` + AI image digests; never prints secret values |
| Optional Compose notes | `compose.yaml` (commented block only) | `aasi-scanner-pull` example — **disabled** / commented; default `up` unchanged |
| Digest stubs | `docker/scanner-digests.env` | Commented GARAK/PROMPTFOO/SAFELABS/PYRIT stubs |

## Non-goals (intentional)

- No new required Compose services or worker `depends_on` changes
- No real registry digests committed (placeholders remain until `docker inspect`)
- No `.env.example` rewrite beyond what Phase 8 already landed
- No commit / push in this pass

## Verification

- Default stack still: `mongo`, `mongo-init`, `api`, `scanner-pull` (web), `worker`, `worker-2`
- `python scripts/aasi/validate_aasi_env.py` reports AASI off and placeholder AI images without leaking secrets
- Health via existing `GET /api/health` and `GET /api/aasi/status` (examples in deploy guide)
- `lat check` after lat.md Phase 9 section update

## Limits

- AI image digests are still placeholders; adapters refuse them at runtime
- Compose resource limits are documented as optional; Helm values already encode production-shaped limits
- Promptfoo registry host (`ghcr.io` vs `docker.io`) must be reconciled when pinning

## Next

Phase 10 — dependency management (`pyproject.toml` / `requirements.txt` alignment), or
operator pin of real AI digests when a lab target is ready.
