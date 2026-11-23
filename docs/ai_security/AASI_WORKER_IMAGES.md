# AASI worker images — dependency policy

Short policy note for AI-security scanner / worker containers used by Attestra Agentic Security Intelligence. Build instructions: [`../../docker/aasi/README.md`](../../docker/aasi/README.md). Full inventory: [`AASI_DEPENDENCY_AND_LICENSE_INVENTORY.md`](./AASI_DEPENDENCY_AND_LICENSE_INVENTORY.md). Licence decisions: [`AASI_LICENSE_REVIEW.md`](./AASI_LICENSE_REVIEW.md). Adoption matrix: [`REPOSITORY_ADOPTION_MATRIX.md`](./REPOSITORY_ADOPTION_MATRIX.md).

## What “reference those repos and implement here” means

| Layer | Where it lives |
|---|---|
| Architecture / CLI / schema reference | External GitHub projects (Garak, Promptfoo, safelabs-eval, PyRIT, …) |
| Importers, adapters, AASI orchestration | **This Attestra repo** (`attestra/importers`, `attestra/runner/scanners`, `attestra/aasi`) |
| Tool runtimes | **Isolated images** under `docker/aasi/` or official GHCR/NGC — never core `pyproject.toml` |
| Shannon | **No code reuse** (AGPL) |

## Isolated worker dependency policy

1. Garak, Promptfoo, SafeLabs Eval, and PyRIT run only inside digest-pinned container images referenced by `ATTESTRA_IMAGE_*`.
2. Core Attestra must **not** install those frameworks as API dependencies. Importers parse exports; adapters invoke Docker.
3. Placeholder / `REPLACE_AFTER_INSPECT` digests are refused at runtime.
4. Promptfoo workers must keep remote generation, telemetry, sharing, and update checks disabled.
5. Do not bake AGPL-prohibited code (e.g. Shannon) into Attestra-shipped worker images.

## Image reality (why Hub pulls failed)

| Env var | Correct approach |
|---|---|
| `ATTESTRA_IMAGE_PROMPTFOO` | Pull `ghcr.io/promptfoo/promptfoo`, pin digest |
| `ATTESTRA_IMAGE_GARAK` | Build `docker/aasi/Dockerfile.garak` → `attestra/garak` (preferred for adapter). Optional NGC `nvcr.io/nvidia/eval-factory/garak` |
| `ATTESTRA_IMAGE_SAFELABS` | Build `docker/aasi/Dockerfile.safelabs` from `pip install safelabs-eval` |
| `ATTESTRA_IMAGE_PYRIT` | Build `docker/aasi/Dockerfile.pyrit` (PyRIT + `attestra_pyrit_worker`) |

Old stub names (`docker.io/nvidia/garak`, `docker.io/agentsafelabs/safelabs-eval`, unpublished `docker.io/attestra/pyrit-worker`) are documentation placeholders, not public Hub images.
