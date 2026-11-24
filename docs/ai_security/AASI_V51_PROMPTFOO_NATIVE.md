# AASI V5.1 — Promptfoo native Node (shared env)

Promptfoo runs as a **native Node** process from the shared environment root. Docker / `ATTESTRA_IMAGE_PROMPTFOO` are not used. Branch: `attestra-asi-bundle`. Directive: [`AASI_CLI_PROMPT_5.1.md`](AASI_CLI_PROMPT_5.1.md). Status: [`AASI_V51_STATUS.md`](AASI_V51_STATUS.md).

## Contract

| Field | Value |
| --- | --- |
| `name` / `import_tool` | `promptfoo` |
| `image_key` | `""` (no image) |
| `allows_docker` | `False` |
| `out_name` | `promptfoo-results.json` |
| `AdapterMeta.asset_kinds` | `("ai_app",)` |
| `safety_tier` | `T2` |
| `network_egress` | `target` |
| `licence` | `MIT` |
| `image_ref_env` | `""` |
| `output_schema` | `promptfoo-results-json` |

## Shared-env resolution

`ATTESTRA_SHARED_ENV_ROOT` (empty → `.attestra-runtime` under CWD via `config.shared_env_root()`).

Expected layout (see Prompt 5.1 §4):

```text
$ATTESTRA_SHARED_ENV_ROOT/
├── tools/node/bin/node          # managed Node runtime
└── npm/                         # npm prefix for Promptfoo
    ├── bin/promptfoo            # preferred CLI (non-wrapper)
    ├── node_modules/.bin/promptfoo
    └── node_modules/promptfoo/dist/src/entrypoint.js
```

`available()` / `resolve_promptfoo_argv_prefix()` only succeed when Promptfoo exists **under that npm prefix**. There is **no** system-PATH / global Promptfoo fallback.

`build_argv` returns a fixed list (`shell=False`):

1. `[promptfoo_cli, "eval", "-c", <config>, "-o", <out>]` when `npm/bin` or `npm/node_modules/.bin` has a non-wrapper CLI, or
2. `[node, promptfoo_entry, "eval", "-c", <config>, "-o", <out>]` using shared `tools/node` + package `entrypoint.js`.

Windows `.cmd` / `.bat` / `.ps1` wrappers are skipped so argv never requires a shell.

## Privacy lockdown

Still required (process env + config `env:` block):

```text
PROMPTFOO_DISABLE_REMOTE_GENERATION=true
PROMPTFOO_DISABLE_TELEMETRY=1
PROMPTFOO_DISABLE_SHARING=1
PROMPTFOO_DISABLE_UPDATE=1
```

`privacy_env()` exposes those pairs. `_scan` merges them into the subprocess environment without relying on Docker `-e`.

## Run shape

1. Write `promptfooconfig.yaml` into the scan `out_dir` (same minimal POST-to-authorized-URL shape as Phase 2).
2. Invoke shared Promptfoo with fixed `eval -c … -o …` argv.
3. Optional `judge=` remains tenant-approved / local only (e.g. `ollama:chat:llama3.2`).
4. `unavailable_reason()` points at the shared npm prefix and states Docker is not used — never suggests Docker Desktop or `ATTESTRA_IMAGE_PROMPTFOO`.

## Tests

`tests/runner/test_promptfoo_adapter.py` — meta/contract, shared-env CLI and node+entry argv, privacy env, no PATH fallback, no Docker.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/runner/test_promptfoo_adapter.py -q --tb=short
```

## Importer

Unchanged: `attestra/importers/promptfoo.py` (`tool="promptfoo"`). See `AASI_PHASE1_PROMPTFOO_IMPORTER.md`.
