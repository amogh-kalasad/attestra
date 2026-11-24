# AASI worker images — **superseded by V5.1 native policy**

Short policy note for AI-security scanners used by Attestra Agentic Security Intelligence.

**V5.1 supersedes** the V4 isolated Docker worker-image model for Garak, Promptfoo, SafeLabs, and PyRIT. Master tracker: [`AASI_V51_STATUS.md`](./AASI_V51_STATUS.md). Directive: [`AASI_CLI_PROMPT_5.1.md`](./AASI_CLI_PROMPT_5.1.md). Deployment: [`AASI_DEPLOYMENT_RUNBOOK.md`](./AASI_DEPLOYMENT_RUNBOOK.md). Historical Dockerfiles: [`../../docker/aasi/README.md`](../../docker/aasi/README.md) (**deprecated for AI execution**). Licence decisions: [`AASI_LICENSE_REVIEW.md`](./AASI_LICENSE_REVIEW.md). Adoption matrix: [`REPOSITORY_ADOPTION_MATRIX.md`](./REPOSITORY_ADOPTION_MATRIX.md).

## V5.1 native / shared-env policy (authoritative)

1. Garak, SafeLabs Eval, and PyRIT run as **native** processes from **one** shared Python virtual environment under `ATTESTRA_SHARED_ENV_ROOT` (same venv as Attestra Python deps).
2. Promptfoo runs via a **Node.js** runtime and npm prefix under the **same** shared environment root (not pip; not a separate Promptfoo-only venv; not a Docker image).
3. **No** per-scanner virtual environments. **No** AI scanner Docker image pulls or Docker execution for these four tools.
4. `ATTESTRA_IMAGE_GARAK` / `PROMPTFOO` / `SAFELABS` / `PYRIT` are **deprecated / unused** for AI execution. Do **not** claim production AI digests.
5. Core Attestra still must not treat Shannon AGPL code as reusable. Promptfoo workers keep remote generation, telemetry, sharing, and update checks disabled.
6. Host-level process, filesystem, and network controls remain required — a shared venv is not isolation.
7. Web/non-AI scanners (ZAP, Nuclei, testssl, naabu, …) **continue** to use digest-pinned images; this supersession is AI-scanner-scoped only.

## What “reference those repos and implement here” means

| Layer | Where it lives |
|---|---|
| Architecture / CLI / schema reference | External GitHub projects (Garak, Promptfoo, safelabs-eval, PyRIT, …) |
| Importers, adapters, AASI orchestration | **This Attestra repo** (`attestra/importers`, `attestra/runner/scanners`, `attestra/aasi`) |
| Tool runtimes (V5.1) | **`ATTESTRA_SHARED_ENV_ROOT`** — one Python `venv/` + `tools/node/` + `npm/` |
| Tool runtimes (V4, superseded) | Isolated images under `docker/aasi/` or GHCR/NGC — **not** used for AI execution under V5.1 |
| Shannon | **No code reuse** (AGPL) |

## Historical V4 image table (obsolete for execution)

| Env var | V4 approach | V5.1 |
|---|---|---|
| `ATTESTRA_IMAGE_PROMPTFOO` | Pull GHCR, pin digest | **Unused** — npm under shared root |
| `ATTESTRA_IMAGE_GARAK` | Build `Dockerfile.garak` | **Unused** — pip into shared venv |
| `ATTESTRA_IMAGE_SAFELABS` | Build `Dockerfile.safelabs` | **Unused** — pip into shared venv |
| `ATTESTRA_IMAGE_PYRIT` | Build `Dockerfile.pyrit` | **Unused** — pip into shared venv |

Old stub Hub names were documentation placeholders, not public images. V5.1 does not replace them with production digests.
