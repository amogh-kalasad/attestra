# AASI Phase 5 — PyRIT isolated multi-turn worker

Design note for `attestra/runner/scanners/pyrit.py` on branch `attestra-asi-bundle`. The Phase 1 importer (`attestra/importers/pyrit.py`) already parses attack-result exports; this slice adds the digest-pinned container adapter that produces them.

## Contract

| Field | Value |
| --- | --- |
| `name` / `import_tool` / `image_key` | `pyrit` |
| `out_name` | `pyrit-results.json` |
| `AdapterMeta.asset_kinds` | `("ai_app",)` |
| `safety_tier` | `T2` |
| `network_egress` | `target` |
| `licence` | `MIT` |
| `image_ref_env` | `ATTESTRA_IMAGE_PYRIT` |
| `output_schema` | `pyrit-json` |
| Timeout | 3600s (override via `ATTESTRA_SCANNER_TIMEOUT_PYRIT`) |

Digest-pinned image required via `base.require_digest_image` (floating tags raise). Placeholder comment lives in `docker/scanner-digests.env`; `config._PLACEHOLDER_IMAGES["pyrit"]` holds an all-zero digest refused at runtime until replaced after `docker inspect`.

## Why isolated

PyRIT carries a large optional dependency tree (Azure SDKs, transformers, etc.). Attestra **never** `import pyrit` in the core app. The worker runs only inside `ATTESTRA_IMAGE_PYRIT`. Unrestricted PyRIT CLIs / tools are **not** exposed to the AASI agent — only allowlisted scenarios via `profile` / `opts["scenario"]`.

## Allowlisted scenarios

Fixed argv only (map → `--scenario <id>`). No agent-supplied `command` / `argv` / `shell` / `extra_args`.

| Id | Notes |
| --- | --- |
| `crescendo` | Multi-turn escalation (default for `baseline` / `full` / `active`) |
| `pair` | PAIR multi-turn |
| `tree_of_attacks` | Tree-of-attacks / TAP (`toa` / `tap` aliases) |
| `red_teaming` | Red-teaming attack (`red_team` / `redteam` aliases) |
| `many_shot` | Many-shot jailbreak (`many_shot_jailbreak` alias) |

## Run shape

1. Require a `PinnedTarget` (gate pins DNS for URL assets).
2. Write `pyrit-run.json` into the scan `out_dir` with:
   - authorized host-header URL (`scheme://host[:port]/path`) and `prompt_target: http_target`
   - selected scenario
   - judge / adversarial egress policy
   - `output.include_transcripts` / `include_usage` so the worker embeds conversation turns and cost fields
3. Docker: `--entrypoint python` + `-m attestra_pyrit_worker run --config /out/pyrit-run.json --output /out/pyrit-results.json --scenario <id>`.
4. Host name pinned with `--add-host host:ip` (same pattern as Promptfoo / ZAP).
5. Cancellation / timeout use the base `_scan` / `run_process` path (named container stop on cancel).

Local PATH fallback uses the same worker module and host paths (Docker is the supported product path).

## Third-party judge / adversarial egress

**Default: disabled** (local/none). `build_docker_argv` passes:

```text
PYRIT_DISABLE_EXTERNAL_JUDGE=1
PYRIT_DISABLE_ADVERSARIAL_EGRESS=1
```

and the run config sets `judge.mode=none`, `adversarial_model.egress=disabled`.

Opt-in only when `opts["tenant_authorize_external_judge"] is True` (strict identity check). Then disable env flags are omitted and optional `judge` / `adversarial_model` provider ids may be written into the config. Meta stays `network_egress="target"`; product policy still gates off-scope URLs before queue.

## Transcript evidence and usage

Worker report JSON (importer-compatible) should include:

- Top-level `attack_results[]` with conversation / scenario ids, outcomes, scores (Phase 1 importer).
- Per-result `transcript` (or `conversation`) turn lists for evidence citation.
- Top-level `usage` / cost fields when available (`tokens_in`, `tokens_out`, `cost_usd`, …).

`PyRITAdapter.scan` copies usage/cost into `ScannerResult.extra` after a successful base scan so planners and AASI budgets can record actual spend without re-parsing the file.

## Image contract

The digest-pinned image must provide `python -m attestra_pyrit_worker` that:

1. Reads `/out/pyrit-run.json`.
2. Talks only to the configured HTTP target (plus authorized external judge when flagged).
3. Writes `/out/pyrit-results.json` in the Phase 1 importer shape, including transcripts and usage when known.

Building/publishing that image is out of scope for this adapter slice (placeholder digest until inspect).

## Tests

`tests/runner/test_pyrit_adapter.py` — meta/contract, scenario allowlist, external-judge lockdown, digest pin, config write, usage attach, registry line. No image pull.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/runner/test_pyrit_adapter.py -q --tb=short
```

## Importer

Successful attack results in `pyrit-results.json` are parsed by `attestra/importers/pyrit.py` (`tool="pyrit"`). See `docs/ai_security/AASI_PHASE1_SAFELABS_PYRIT_IMPORTERS.md`.
