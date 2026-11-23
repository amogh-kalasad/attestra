# AASI worker images — dependency policy

Short policy note for AI-security scanner / worker containers used by Attestra Agentic Security Intelligence. Full inventory: [`AASI_DEPENDENCY_AND_LICENSE_INVENTORY.md`](./AASI_DEPENDENCY_AND_LICENSE_INVENTORY.md). Licence decisions: [`AASI_LICENSE_REVIEW.md`](./AASI_LICENSE_REVIEW.md).

## Isolated worker dependency policy

1. **Garak, Promptfoo, SafeLabs Eval, and PyRIT run only inside digest-pinned container images** referenced by `ATTESTRA_IMAGE_*` / `AdapterMeta.image_ref_env`. Their runtimes and transitive dependencies stay in those images.
2. **Core Attestra** (`pyproject.toml` / API & durable worker venv) must **not** install those frameworks. Importers parse exported reports; adapters invoke `docker_run_argv` (or equivalent process boundary).
3. Placeholder digests are refused at runtime until replaced with inspected pins (`docker/scanner-digests.env` comments for Garak / Promptfoo / SafeLabs; PyRIT worker later).
4. Promptfoo workers must keep remote generation, telemetry, sharing, and update checks disabled; that is operational lockdown, not a substitute for egress policy.
5. Do not bake AGPL-prohibited code (e.g. Shannon) into Attestra-shipped worker images.
