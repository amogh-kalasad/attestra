# AASI Phase 2 — Promptfoo scanner adapter

Short note for `attestra/runner/scanners/promptfoo.py` on branch `attestra-asi-bundle`. Parent wiring of `registry.py` / `sdk.DEFAULT_META` / `docker/scanner-digests.env` is out of scope for this slice.

## Contract

| Field | Value |
| --- | --- |
| `name` / `import_tool` / `image_key` | `promptfoo` |
| `out_name` | `promptfoo-results.json` |
| `AdapterMeta.asset_kinds` | `("ai_app",)` |
| `safety_tier` | `T2` |
| `network_egress` | `target` |
| `licence` | `MIT` |
| `image_ref_env` | `ATTESTRA_IMAGE_PROMPTFOO` |
| `output_schema` | `promptfoo-results-json` |

Digest-pinned image required via `base.require_digest_image` (floating tags raise). Placeholder comment for the env var already exists in `docker/scanner-digests.env` for parent INT to fill after image inspect.

## Run shape

1. Write a minimal `promptfooconfig.yaml` into the scan `out_dir` that POSTs to the authorized host-header URL (`scheme://host[:port]/path`).
2. Docker: `promptfoo eval -c /out/promptfooconfig.yaml -o /out/promptfoo-results.json` with entrypoint `promptfoo`.
3. Host name pinned with `--add-host host:ip` (same pattern as ZAP/Nuclei/testssl) so DNS inside the container cannot leave the gate’s resolved IP.
4. Local PATH fallback uses the same config + `promptfoo eval -c … -o …` (Docker is the supported product path).

## Remote / cloud lockdown

`build_docker_argv` passes these as `docker run -e` via `extra_flags` (base `docker_run_argv` has no first-class env arg):

```text
PROMPTFOO_DISABLE_REMOTE_GENERATION=true
PROMPTFOO_DISABLE_TELEMETRY=1
PROMPTFOO_DISABLE_SHARING=1
PROMPTFOO_DISABLE_UPDATE=1
```

The same keys are mirrored under the config’s `env:` block. Disabling remote generation is **not** a network firewall; Attestra still relies on digest pin + target-only egress documentation + the `--add-host` pin. Promptfoo Cloud / login paths stay out of scope for the worker.

## Judge policy

Baseline asserts are deterministic (`javascript` not-empty). Optional `judge=` on argv builders sets `defaultTest.options.provider` to a **tenant-approved or local** provider id (for example `ollama:chat:llama3.2`). Do not enable Promptfoo remote generation or a cloud grader by default.

## Egress

`network_egress="target"`: the container may talk to the authorized AI app URL only (plus whatever the host Docker network allows — product policy still gates off-scope URLs before queue). Third-party judge egress requires a later tenant flag path (blueprint §8); this adapter does not open it.

## Tests

`tests/runner/test_promptfoo_adapter.py` — meta/contract, env disables in docker argv, import_tool/image_key, digest rejection, config write, no image pull.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/runner/test_promptfoo_adapter.py -q --tb=short
```

## Importer

Failed assertions in `promptfoo-results.json` are parsed by `attestra/importers/promptfoo.py` (`tool="promptfoo"`). See `docs/ai_security/AASI_PHASE1_PROMPTFOO_IMPORTER.md`.
