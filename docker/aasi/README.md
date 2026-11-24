# AASI scanner worker images — **DEPRECATED for AI execution (V5.1)**

**Status:** Deprecated as the **runtime path** for Garak, Promptfoo, SafeLabs, and PyRIT.

AASI CLI Prompt **5.1** supersedes the V4 Docker AI image / digest-pin approach. AI scanners run **natively** under one shared environment root (`ATTESTRA_SHARED_ENV_ROOT`: single Python venv + Node/npm for Promptfoo). See:

- [`docs/ai_security/AASI_V51_STATUS.md`](../../docs/ai_security/AASI_V51_STATUS.md)
- [`docs/ai_security/AASI_DEPLOYMENT_RUNBOOK.md`](../../docs/ai_security/AASI_DEPLOYMENT_RUNBOOK.md)
- [`docs/ai_security/AASI_CLI_PROMPT_5.1.md`](../../docs/ai_security/AASI_CLI_PROMPT_5.1.md)

Do **not** pull or pin `ATTESTRA_IMAGE_GARAK` / `PROMPTFOO` / `SAFELABS` / `PYRIT` for production AI scanning. Do **not** claim production AI digests.

This directory (Dockerfiles, `pyrit_worker/`) remains as a **historical packaging reference** only. Offline importers in `attestra.importers.*` still apply. Shannon (AGPL) remains **no code reuse**.

Web/non-AI scanners continue to use digest-pinned images elsewhere (`docker/scanner-digests.env`, ZAP/Nuclei/…).

---

## Historical V4 notes (not the V5.1 execution path)

Attestra **does not vendor** Garak / Promptfoo / SafeLabs / PyRIT into the core app tree as Docker-baked runtime for V5.1. Under V4, “take code reference and implement here” meant:

1. **Reference** those GitHub projects for CLI/schema/architecture.
2. **Implement here** Attestra importers, adapters, and AASI orchestration.
3. **Run the tools** in isolated, digest-pinned containers (superseded) **or** import offline results.

### What V4 pulled vs built (obsolete for execution)

| Tool | Source of truth | V4 image strategy (superseded) |
|---|---|---|
| **Promptfoo** | [promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) | GHCR digest pin — unused under V5.1 |
| **Garak** | [NVIDIA/garak](https://github.com/NVIDIA/garak) | `Dockerfile.garak` — unused under V5.1 |
| **SafeLabs** | [AgentSafeLabs/safelabs-eval](https://github.com/AgentSafeLabs/safelabs-eval) | `Dockerfile.safelabs` — unused under V5.1 |
| **PyRIT** | [microsoft/PyRIT](https://github.com/microsoft/PyRIT) | `Dockerfile.pyrit` + thin worker — unused under V5.1 |

Stub Hub names like `docker.io/nvidia/garak` were placeholders and fail Hub pulls — expected; V5.1 does not fix that with digests.

### V5.1 install pointer

```bash
# Set shared root (example; empty may default to <repo>/.attestra-runtime)
export ATTESTRA_SHARED_ENV_ROOT=/opt/attestra/runtime

python scripts/aasi/install_shared_env.py
# See docs/ai_security/AASI_DEPLOYMENT_RUNBOOK.md
```

Offline imports still work without Docker or shared-env scanners via `attestra.importers.{garak,promptfoo,safelabs,pyrit}`.
