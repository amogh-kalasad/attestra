# AASI deployment runbook (Phase 13)

Operator steps to enable Attestra Agentic Security Intelligence on an **already running** Attestra stack. Branch reference: `attestra-asi-bundle`. Full Docker background: [`AASI_DOCKER_DEPLOYMENT.md`](AASI_DOCKER_DEPLOYMENT.md).

**This runbook does not perform a deploy.** No production or staging deployment was executed when this document was written. Prefer staging first. Keep `ATTESTRA_AASI=off` until digests and RoE are ready.

---

## 0. Prerequisites

- Attestra API + worker + Mongo (replica set) healthy: `GET /api/health`.
- Migrations applied (includes `0005_aasi_collections`, `0006_aasi_graph`).
- Signed authorization / scope for any `ai_app` targets (same gates as other assets).
- AI narrative / provider secrets only if you will run recommend-only roles (`ATTESTRA_AI_NARRATIVES` and provider keys — see `docs/AI_NARRATIVES.md`). AASI reuses that stack; do not invent a separate AASI provider env.
- Shannon AGPL code **must not** be vendored into the image or tree.

---

## 1. Pin AI scanner digests (required before adapter runs)

Placeholders and `REPLACE_AFTER_INSPECT` are **refused** at runtime.
Full recipes: [`../../docker/aasi/README.md`](../../docker/aasi/README.md).

```bash
# Promptfoo (public)
docker pull ghcr.io/promptfoo/promptfoo:<tag>
docker image inspect --format '{{index .RepoDigests 0}}' ghcr.io/promptfoo/promptfoo:<tag>

# Garak / SafeLabs / PyRIT — build from Attestra Dockerfiles (upstream pip packages)
docker build -f docker/aasi/Dockerfile.garak -t attestra/garak:local docker/aasi
docker build -f docker/aasi/Dockerfile.safelabs -t attestra/safelabs:local docker/aasi
docker build -f docker/aasi/Dockerfile.pyrit -t attestra/pyrit-worker:local docker/aasi
docker image inspect --format '{{index .RepoDigests 0}}' attestra/garak:local
```

Set in the **deployment** environment (Compose `.env`, Helm secrets, or Vault) — do not commit production secrets:

| Variable | Tool | Source |
|---|---|---|
| `ATTESTRA_IMAGE_GARAK` | Garak | Built `attestra/garak` (or NGC eval-factory if entrypoint aligned) |
| `ATTESTRA_IMAGE_PROMPTFOO` | Promptfoo | `ghcr.io/promptfoo/promptfoo` |
| `ATTESTRA_IMAGE_SAFELABS` | safelabs-eval | Built `attestra/safelabs` |
| `ATTESTRA_IMAGE_PYRIT` | PyRIT worker | Built `attestra/pyrit-worker` |

Optional local pull helper (Compose): uncomment `aasi-scanner-pull` in `compose.yaml` only after real digests exist. Default `scanner-pull` remains web tools only.

---

## 2. Validate env (no secret echo)

From repo root (or image with the script):

```bash
python scripts/aasi/validate_aasi_env.py
python scripts/aasi/validate_aasi_env.py --env-file /path/to/deploy.env
# Before enabling adapters in staging:
python scripts/aasi/validate_aasi_env.py --require-ai-images
```

Expect: readable `ATTESTRA_AASI` flag; each AI image `ok` when `--require-ai-images` is used. Script never prints secret values.

---

## 3. Staging enablement sequence

1. Deploy or restart API/workers with **`ATTESTRA_AASI=off`** and real digests loaded.
2. Confirm `GET /api/aasi/status` → `{ "enabled": false }` (or equivalent) and mutate routes 404.
3. Confirm web scanners still work; AI adapters not required yet.
4. Set budget/approval knobs (defaults are safe):

   | Variable | Suggested staging start |
   |---|---|
   | `ATTESTRA_AASI_REQUIRE_APPROVAL` | `on` |
   | `ATTESTRA_AASI_MAX_ITERATIONS` | `8` (or lower) |
   | `ATTESTRA_AASI_MAX_TASKS` | `32` |
   | `ATTESTRA_AASI_MAX_MODEL_CALLS` | `40` |
   | `ATTESTRA_AASI_MAX_TOKENS` | `50000` |
   | `ATTESTRA_AASI_MAX_WALL_CLOCK_S` | `1800` |
   | `ATTESTRA_AASI_RETRY_LIMIT` | `2` |

5. Enable narratives only if the tenant is allowed (`ATTESTRA_AI_NARRATIVES`, honour tenant off-list).
6. Set **`ATTESTRA_AASI=on`**, restart API (and workers if they read the flag at process start).
7. Smoke: `GET /api/aasi/status` → enabled true; start a recommend-only run on a lab engagement; **approve** intrusive recommendations manually before planner execution.
8. For scanner e2e: dispatch registered `garak` / `promptfoo` / `safelabs` / `pyrit` against an **authorized** AI lab URL only; import results via existing importers if using offline exports.

---

## 4. Production promotion (after staging sign-off)

Only after staging e2e, digest verification, and security/ops review:

1. Copy proven digest pins into production secret store.
2. Keep AASI **off** on first production rollout of the binary if AI scanning is not contracted.
3. Enable per change window with approval still `on`.
4. Monitor audit events for AASI approve/cancel; watch worker failures for placeholder/digest errors.
5. Do **not** bake Garak/Promptfoo/SafeLabs/PyRIT into the main app image.

Helm: use existing scanner Job patterns (`deploy/README.md`); no privileged scanners; NetworkPolicy egress to pinned target `/32` where applicable.

---

## 5. Health checks

| Check | Command / endpoint |
|---|---|
| App | `GET /api/health` |
| AASI flag | `GET /api/aasi/status` |
| Env digests | `python scripts/aasi/validate_aasi_env.py [--require-ai-images]` |
| Migrations | Existing Mongo migration runner includes `0005` / `0006` |

---

## 6. If something fails

Use [`AASI_ROLLBACK_RUNBOOK.md`](AASI_ROLLBACK_RUNBOOK.md): set `ATTESTRA_AASI=off`, unset or revert bad image pins, restart. Core VAPT path does not require AASI.
