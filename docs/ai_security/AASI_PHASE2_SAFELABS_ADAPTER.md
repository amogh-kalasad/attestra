# AASI Phase 2 — SafeLabs scanner adapter

Digest-pinned `ScannerAdapter` for [AgentSafeLabs/safelabs-eval](https://github.com/AgentSafeLabs/safelabs-eval) (Apache-2.0). Phase 1 already ships the offline importer; this slice adds container execution only.

**Owned files (this slice):**

- `attestra/runner/scanners/safelabs.py`
- `tests/runner/test_safelabs_adapter.py`
- `docs/ai_security/AASI_PHASE2_SAFELABS_ADAPTER.md`

Registry / SDK / digests wiring is owned by the parent integration step — this adapter is **not** registered here.

## Adapter contract

| Field | Value |
| --- | --- |
| Class | `SafeLabsAdapter` |
| `name` / `import_tool` / `image_key` | `safelabs` |
| `out_name` | `safelabs-report.json` |
| `AdapterMeta.asset_kinds` | `("ai_app",)` |
| `safety_tier` | `T2` (active adversarial prompts against the authorized target) |
| `network_egress` | `target` |
| `licence` | `Apache-2.0` |
| `image_ref_env` | `ATTESTRA_IMAGE_SAFELABS` |
| `output_schema` | `safelabs-json` |

## Execution model

- **Isolation:** intended runtime is a digest-pinned Python image with the safelabs-eval core only (pydantic / httpx / click — no LangChain/CrewAI extras, no host `pip install` into Attestra).
- **Entrypoint:** `docker_entrypoint = "safelabs"`; `docker_args` → `run --target <url> --category <…> --output json`.
- **Report path:** CLI JSON goes to stdout (`--output json`). With `report_on_stdout = True`, base `ScannerAdapter.scan` writes stdout to the host `out_dir` bind-mounted at `CONTAINER_OUT` (`/out/safelabs-report.json`). Evidence is the raw report path + sha256 via the normal `ScannerResult` / durable-job path.
- **DNS pin:** requires `PinnedTarget` so Docker `--add-host` pins the agent hostname to the authorized IP. Optional `endpoint_path` (default `/`) and `category` opts.
- **Profiles:** `baseline` → `ASI01`; `full` / `active` → `all` (300 prompts).

## Uncertainty / validation

SafeLabs detectors are pattern heuristics. **This adapter does not upgrade findings.** Import stays with `attestra.importers.safelabs.parse`, which records `validation=potential` on `confidence` and never emits confirmed status. `uncertain` / `pass` / missing / error rows remain non-findings at import time.

## Tests

`tests/runner/test_safelabs_adapter.py` — contract, meta, argv/docker_args, fixture validate_report, health without a real image. No Docker pull required.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/runner/test_safelabs_adapter.py -q --tb=short
```

## Out of scope

- Adding `safelabs` to `registry.py` / `SCANNER_IMAGES` real digests / UI picker (parent).
- Optional LLM judges or framework-specific agent adapters.
- Treating SafeLabs ASI01–ASI10 labels as official OWASP Agentic Top 10 2026 IDs.
