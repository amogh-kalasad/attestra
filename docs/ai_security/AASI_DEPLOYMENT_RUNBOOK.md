# AASI deployment runbook (V5.1 shared env)

Operator steps to enable Attestra Agentic Security Intelligence on an **already running** Attestra stack. Branch reference: `attestra-asi-bundle`. V5.1 tracker: [`AASI_V51_STATUS.md`](AASI_V51_STATUS.md). Directive: [`AASI_CLI_PROMPT_5.1.md`](AASI_CLI_PROMPT_5.1.md).

**V5.1 supersedes** V4 “pin AI scanner digests” enablement. Garak, Promptfoo, SafeLabs, and PyRIT execute **natively** under `ATTESTRA_SHARED_ENV_ROOT`. Do **not** claim or require production AI image digests.

**This runbook does not perform a deploy.** Prefer staging first. Keep `ATTESTRA_AASI=off` until the shared environment is healthy and RoE is ready. Docker-free AI scanner work may still be **IN PROGRESS** — see the status tracker.

---

## 0. Prerequisites

- Attestra API + worker + Mongo (replica set) healthy: `GET /api/health`.
- Migrations applied (includes `0005_aasi_collections`, `0006_aasi_graph`).
- Signed authorization / scope for any `ai_app` targets (same gates as other assets).
- AI narrative / provider secrets only if you will run recommend-only roles (`ATTESTRA_AI_NARRATIVES` and provider keys — see `docs/AI_NARRATIVES.md`). AASI reuses that stack; do not invent a separate AASI provider env.
- Shannon AGPL code **must not** be vendored into the image or tree.
- Python and Node versions compatible with Attestra + pinned AI scanner releases (see shared-env install report).

---

## 1. Install the shared environment (required before native AI scanner runs)

Set a single managed root (example):

```bash
export ATTESTRA_SHARED_ENV_ROOT=/opt/attestra/runtime
# Also set in deployment .env / secrets — see .env.example
```

Expected layout under that root (one Python venv only; Node/npm for Promptfoo):

```text
$ATTESTRA_SHARED_ENV_ROOT/
  venv/                 # Attestra + Garak + SafeLabs + PyRIT
  tools/node/           # Node runtime (not a second Python venv)
  npm/                  # npm prefix; promptfoo CLI here
  manifests/
  logs/  cache/  tmp/
```

### Install / verify steps

From repo root (V5.1 shared-env installer on this branch):

```bash
# Provisions ATTESTRA_SHARED_ENV_ROOT (default <repo>/.attestra-runtime):
# one venv/ + tools/node + npm (Promptfoo). Never docker-pulls AI images; never a second venv.
python scripts/aasi/install_shared_env.py
# Promptfoo-only wrapper (same npm prefix under the shared root):
python scripts/aasi/install_promptfoo_npm.py
# Flag / env helper (does not print secrets); not an AI-digest gate under V5.1:
python scripts/aasi/validate_aasi_env.py
```

The installer must (summary):

1. Validate OS / Python / Node compatibility.
2. Create **exactly one** Python venv under `$ATTESTRA_SHARED_ENV_ROOT/venv`.
3. Install Attestra deps, then Garak, SafeLabs, and PyRIT into that **same** venv.
4. Install Node under `tools/node/` and Promptfoo under the shared `npm/` prefix (not pip).
5. Write manifests; run `pip check` and npm integrity checks; verify scanner executables.
6. Produce an installation report (no customer scans during install).

**Prohibited:** per-scanner venvs; system-Python fallback for scanners; Docker pulls/execution for the four AI tools; installing packages during normal scan jobs.

Overall Docker-free AI scanner track remains **IN PROGRESS** until native adapters + lab e2e are proven — see [`AASI_V51_STATUS.md`](AASI_V51_STATUS.md).

Leave AI image vars unset:

```env
# Deprecated under V5.1 — do not pin for AI execution
# ATTESTRA_IMAGE_GARAK=
# ATTESTRA_IMAGE_PROMPTFOO=
# ATTESTRA_IMAGE_SAFELABS=
# ATTESTRA_IMAGE_PYRIT=
```

Web scanner digests (ZAP, Nuclei, …) remain separate and unchanged.

---

## 2. Validate env (no secret echo)

From repo root (or image with the script):

```bash
python scripts/aasi/validate_aasi_env.py
python scripts/aasi/validate_aasi_env.py --env-file /path/to/deploy.env
# After install_shared_env.py — confirm shared root health via attestra.scanner_runtime
# (or follow docs/ai_security/AASI_V51_INSTALL.md when present)
```

Expect: readable `ATTESTRA_AASI` flag; `ATTESTRA_SHARED_ENV_ROOT` set when enabling native scanners (empty may default to `<repo>/.attestra-runtime`). Script must never print secret values. Do **not** use `--require-ai-images` as a V5.1 readiness gate — AI digests are obsolete for execution.

---

## 3. Staging enablement sequence

1. Deploy or restart API/workers with **`ATTESTRA_AASI=off`** and shared env installed/verified.
2. Confirm `GET /api/aasi/status` → `{ "enabled": false }` (or equivalent) and mutate routes 404.
3. Confirm web scanners still work; native AI adapters not required yet.
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
8. For scanner e2e: dispatch registered `garak` / `promptfoo` / `safelabs` / `pyrit` against an **authorized** AI lab URL only, using the shared-env interpreters/CLIs; or import offline exports via existing importers.

---

## 4. Production promotion (after staging sign-off)

Only after staging e2e, shared-env verification, and security/ops review:

1. Promote the **same** shared-env manifests/versions proven in staging (controlled upgrade workflow — not ad-hoc pip during jobs).
2. Keep AASI **off** on first production rollout of the binary if AI scanning is not contracted.
3. Enable per change window with approval still `on`.
4. Monitor audit events for AASI approve/cancel; watch worker failures for missing shared-env / unavailable scanner status.
5. Do **not** bake Garak/Promptfoo/SafeLabs/PyRIT into a “AI Docker digest” story — V5.1 is native shared env. Do not claim production AI digests.

Helm / host: keep non-AI scanner Job patterns (`deploy/README.md`); no privileged scanners; NetworkPolicy / host egress to pinned target `/32` where applicable. Shared venv does **not** replace network isolation.

---

## 5. Health checks

| Check | Command / endpoint |
|---|---|
| App | `GET /api/health` |
| AASI flag | `GET /api/aasi/status` |
| Shared env | `python scripts/aasi/install_shared_env.py` (install/report); runtime health via `attestra.scanner_runtime` |
| Env flag helper | `python scripts/aasi/validate_aasi_env.py` |
| Migrations | Existing Mongo migration runner includes `0005` / `0006` |

---

## 6. If something fails

Use [`AASI_ROLLBACK_RUNBOOK.md`](AASI_ROLLBACK_RUNBOOK.md): set `ATTESTRA_AASI=off`, stop native AI scanner jobs, restore last known-good shared-env manifest via the upgrade/backup scripts when available, restart. Core VAPT path does not require AASI. Do not “fix” AI scanners by re-enabling obsolete Docker digest pins unless an explicit temporary exception is documented and approved.
