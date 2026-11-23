# AASI Phase 2 — Garak scanner adapter

Design note for `attestra/runner/scanners/garak.py`. Registry / `DEFAULT_META` / digest env wiring is owned by the parent integrator.

## Role

Runs NVIDIA Garak as a digest-pinned container (`ATTESTRA_IMAGE_GARAK`) against an authorized `ai_app` URL. Offline report parsing remains in `attestra/importers/garak.py` (Phase 1).

## Contract

| Field | Value |
|---|---|
| `name` / `import_tool` / `image_key` | `garak` |
| `out_name` | `garak-report.jsonl` |
| Capabilities | `ai_llm_probe` |
| Asset kinds | `ai_app` |
| Safety tier | `T2` |
| Egress | `target` |
| Licence | Apache-2.0 |
| Image env | `ATTESTRA_IMAGE_GARAK` |
| Output schema | `garak-jsonl` |
| Timeout | 3600s (override via `ATTESTRA_SCANNER_TIMEOUT_GARAK`) |

`available()` is true only when a local `garak` CLI is on `PATH`. Docker remains the primary execution path via `uses_docker()` when the digest-pinned image is configured.

## CLI approach

1. Require a `PinnedTarget` (gate pins DNS for URL assets).
2. When `scope` is provided, call `authorize_target` on the RestGenerator URI before writing configs.
3. Write fixed files into the report directory (mounted at `/out` in Docker):
   - `garak-generator.json` — `rest.RestGenerator` with `uri` = authorized target URL (OpenAI-style chat JSON body, JSONPath response field).
   - `garak-run.yaml` — `reporting.report_dir` = `/out` (or host out dir locally), `report_prefix` = `garak-report`, `run.generations` = 1.
4. Fixed argv (never `shell=True`, never agent-supplied commands):
   - Docker: `--entrypoint python` + `-m garak --target_type rest -G /out/garak-generator.json --config /out/garak-run.yaml --generations 1`
   - Local: `garak` with the same flags and host paths.
5. Garak names the JSONL `{prefix}.report.jsonl` → `garak-report.report.jsonl`. `resolve_output` maps that file for import.
6. Cancellation / timeout use the base `_scan` / `run_process` path. Missing or unreadable reports set `ScannerResult.error` (never treated as a pass).

## Optional opts

- `endpoint_url` — full RestGenerator URI when the LLM path is not the pin root (`/`).
- `scope` — `AuthorizedScope`; off-scope URLs raise `AuthorizationError`.

## Tests

`tests/runner/test_garak_adapter.py` — meta contract, argv/`/out` paths, no shell metacharacters, `unavailable_reason` mentions `ATTESTRA_IMAGE_GARAK`, off-scope authorize reject. No live Docker required.

## Out of scope (parent)

- `registry.py` registration
- `sdk.DEFAULT_META["garak"]`
- `docker/scanner-digests.env` / `config.SCANNER_IMAGES["garak"]`
- Gate `TOOL_ASSET_KINDS` entry for `ai_app`
