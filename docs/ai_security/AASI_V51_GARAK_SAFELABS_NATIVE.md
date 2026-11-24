# AASI V5.1 — Garak and SafeLabs native-only adapters

Design note for converting `garak` and `safelabs` scanner adapters from digest-pinned Docker to the Attestra shared scanner Python environment.

## Goal

Run Garak and SafeLabs against authorized `ai_app` targets via a native shared venv only. Docker is not a fallback path for these two tools.

## Contract changes (both adapters)

| Field | V5.1 value |
|---|---|
| `image_key` | `""` |
| `allows_docker` | `False` |
| `uses_docker()` | always `False` |
| `meta.image_ref_env` | `""` |
| `docker_args` | `NotImplementedError` (native-only) |
| `docker_entrypoint` | removed / unused |
| Execution | `base._scan` native path (`build_argv` → `run_process`) |
| Timeouts | unchanged (`ATTESTRA_SCANNER_TIMEOUT_<TOOL>` / `default_timeout_s`) |
| Importers | unchanged (`import_tool` still `garak` / `safelabs`) |

## Shared env resolution

Each adapter defines a local `_shared_python()` helper that prefers `attestra.scanner_runtime.resolve_shared_env().python` when that package is importable, then falls back to:

1. `ATTESTRA_SHARED_ENV_ROOT` (layout `venv/Scripts|bin/python`)
2. `.attestra-runtime` as a directory root or a one-line path file (cwd / repo root)
3. `config.shared_env_root()`

Availability prefers `scanner_runtime.check_python_package` (`garak`, `safelabs-eval`), then `shutil.which` / `python -m` import probes.

`unavailable_reason()` tells operators to run `python scripts/aasi/install_shared_env.py`. It never mentions Docker or `ATTESTRA_IMAGE_*`.

## Garak (`attestra/runner/scanners/garak.py`)

- Launcher: shared `python -m garak` (fallback: `garak` on PATH / `sys.executable -m garak`).
- Still requires `PinnedTarget`; optional `scope` / `endpoint_url`.
- Writes `garak-generator.json` + `garak-run.yaml` under the host out dir (absolute `report_dir`).
- Fixed flags: `--target_type rest -G … --config … --generations 1`.
- `resolve_output` still maps `{prefix}.report.jsonl`.

### OpenAI / Anthropic / LiteLLM policy

Shared venv prefers **openai 3.x** for PyRIT, so Garak is installed with `pip install --no-deps` (see [`AASI_V51_DEPENDENCIES.md`](./AASI_V51_DEPENDENCIES.md)).

- Attestra always probes the authorized `ai_app` via **REST** (`RestGenerator`).
- Garak's native **OpenAI** generator is **unsupported** in this shared env.
- **Anthropic** and **LiteLLM** packages are installed for Garak generators that need them.

## SafeLabs (`attestra/runner/scanners/safelabs.py`)

- Launcher: shared-env `safelabs` console script (venv `Scripts`), else `python -m safelabs`, else PATH / sys.executable.
- Still requires `PinnedTarget`; profiles `baseline` → `ASI01`, `full`/`active` → `all`.
- Fixed argv: `run --target <url> --category <…> --output json`.
- `report_on_stdout = True` so base scan persists JSON into the host out dir.

## Tests

- `tests/runner/test_garak_adapter.py` — meta (`allows_docker is False`, empty `image_key`), mocked `build_argv` / `available`, shared-env unavailable reason, authorize reject, no Docker.
- `tests/runner/test_safelabs_adapter.py` — same native contract; `docker_args` raises; health without shared env.

## Related

- Base `allows_docker` / shared-env unavailable path: `docs/ai_security/AASI_V51_NO_DOCKER.md`
- Installer: `scripts/aasi/install_shared_env.py`
- Runtime package: `attestra/scanner_runtime/`
