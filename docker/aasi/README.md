# AASI scanner worker images

Attestra **does not vendor** Garak / Promptfoo / SafeLabs / PyRIT into the core
Python app. The V4.0 prompt’s “take code reference and implement here” means:

1. **Reference** those GitHub projects for CLI/schema/architecture.
2. **Implement here** Attestra importers, adapters, and AASI orchestration.
3. **Run the tools** in isolated, digest-pinned containers (or import offline results).

Shannon (AGPL) remains **no code reuse**.

## What to pull vs what to build

| Tool | Source of truth | Image strategy |
|---|---|---|
| **Promptfoo** | [promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) | Public: `ghcr.io/promptfoo/promptfoo:<tag>` — pin digest after `docker inspect` |
| **Garak** | [NVIDIA/garak](https://github.com/NVIDIA/garak) | Prefer build from `Dockerfile.garak` (`python -m garak`, matches adapter). Optional NGC: `nvcr.io/nvidia/eval-factory/garak` (login, large; entrypoint may differ) |
| **SafeLabs** | [AgentSafeLabs/safelabs-eval](https://github.com/AgentSafeLabs/safelabs-eval) (`pip install safelabs-eval`) | **Build** `Dockerfile.safelabs` — no public Docker Hub image |
| **PyRIT** | [microsoft/PyRIT](https://github.com/microsoft/PyRIT) | **Build** `Dockerfile.pyrit` with Attestra thin worker module — no published `attestra/pyrit-worker` |

Stub names like `docker.io/nvidia/garak` or `docker.io/agentsafelabs/safelabs-eval` were **placeholders** and will fail Hub pulls. That is expected until you set real `ATTESTRA_IMAGE_*` pins.

## Build (local registry / lab)

From repo root:

```bash
# Garak (pip-based; matches GarakAdapter docker_entrypoint=python -m garak)
docker build -f docker/aasi/Dockerfile.garak -t attestra/garak:local docker/aasi
docker image inspect --format '{{index .RepoDigests 0}}' attestra/garak:local

# SafeLabs (pip safelabs-eval → CLI `safelabs`)
docker build -f docker/aasi/Dockerfile.safelabs -t attestra/safelabs:local docker/aasi
docker image inspect --format '{{index .RepoDigests 0}}' attestra/safelabs:local

# PyRIT worker (pyrit + attestra_pyrit_worker)
docker build -f docker/aasi/Dockerfile.pyrit -t attestra/pyrit-worker:local docker/aasi
docker image inspect --format '{{index .RepoDigests 0}}' attestra/pyrit-worker:local

# Promptfoo — prefer official GHCR, then pin
docker pull ghcr.io/promptfoo/promptfoo:latest
docker image inspect --format '{{index .RepoDigests 0}}' ghcr.io/promptfoo/promptfoo:latest
```

Tag/push to **your** registry if needed, then set in deployment `.env`:

```env
ATTESTRA_IMAGE_GARAK=attestra/garak@sha256:...
ATTESTRA_IMAGE_PROMPTFOO=ghcr.io/promptfoo/promptfoo@sha256:...
ATTESTRA_IMAGE_SAFELABS=attestra/safelabs@sha256:...
ATTESTRA_IMAGE_PYRIT=attestra/pyrit-worker@sha256:...
```

Validate:

```bash
python scripts/aasi/validate_aasi_env.py --require-ai-images
```

## Adapter contracts

| Adapter | Env | Expected container command shape |
|---|---|---|
| Garak | `ATTESTRA_IMAGE_GARAK` | `python -m garak …` (entrypoint overridden to `python`) |
| Promptfoo | `ATTESTRA_IMAGE_PROMPTFOO` | `promptfoo eval …` + disable-remote/telemetry env |
| SafeLabs | `ATTESTRA_IMAGE_SAFELABS` | `safelabs run --target … --output json` |
| PyRIT | `ATTESTRA_IMAGE_PYRIT` | `python -m attestra_pyrit_worker run --config … --output … --scenario …` |

Offline imports still work without images via `attestra.importers.{garak,promptfoo,safelabs,pyrit}`.
