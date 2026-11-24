# AASI V5.1 — PyRIT genuine native framework execution

Design note for converting PyRIT from the deprecated Docker HTTP-marker worker to **genuine native** execution on branch `attestra-asi-bundle`.

## What changed

| Before (Phase 5 docker worker) | After (V5.1 native) |
| --- | --- |
| `image_key="pyrit"`, `ATTESTRA_IMAGE_PYRIT` digest pin | `image_key=""`, **`allows_docker=False`** — no image env |
| `python -m attestra_pyrit_worker` inside container | `python -m attestra.aasi.pyrit_native` in the **shared venv** |
| Thin HTTP probes + success-marker heuristics | Imports the real **`pyrit`** package; records `pyrit.__version__` |
| Claim risk: worker looked like PyRIT but was not | Explicit `scenario_engine: "pyrit-backed"`; docs forbid claiming the old worker as genuine PyRIT |

**Do not** claim the old `docker/aasi/pyrit_worker` HTTP-marker probes are genuine PyRIT. That folder remains only as a deprecated reference; the adapter path no longer invokes it.

## Contract

| Field | Value |
| --- | --- |
| `name` / `import_tool` | `pyrit` |
| `image_key` | `""` (empty) |
| `allows_docker` | `False` |
| `out_name` | `pyrit-results.json` |
| `AdapterMeta.asset_kinds` | `("ai_app",)` |
| `safety_tier` | `T2` |
| `network_egress` | `target` |
| `licence` | `MIT` |
| `image_ref_env` | `""` (no `ATTESTRA_IMAGE_PYRIT`) |
| `output_schema` | `pyrit-json` |
| Timeout | 3600s (`ATTESTRA_SCANNER_TIMEOUT_PYRIT`) |
| Availability | `import pyrit` succeeds in the shared interpreter |

If PyRIT is not installed: `available()` is `False` and `unavailable_reason()` / native runner emit the install message (`pip install 'pyrit>=0.9.0'`).

## Allowlisted scenarios

Fixed argv only (`--scenario <id>`). No agent-supplied `command` / `argv` / `shell` / `extra_args`.

| Id | Preferred PyRIT class (documented export) | Conservative path when adversarial egress is off |
| --- | --- | --- |
| `crescendo` | `CrescendoAttack` | `PromptSendingAttack` + `HTTPTarget` |
| `pair` | `PAIRAttack` | same |
| `tree_of_attacks` | `TreeOfAttacksWithPruningAttack` (`TAPAttack` alias) | same |
| `red_teaming` | `RedTeamingAttack` | same |
| `many_shot` | `ManyShotJailbreakAttack` | that class when constructable, else `PromptSendingAttack` |

Full multi-turn orchestrators require an adversarial chat model. Third-party judge / adversarial egress stays **off** unless `tenant_authorize_external_judge=True`. Without that flag the runner still uses real PyRIT APIs (`HTTPTarget`, `PromptSendingAttack` / `ManyShotJailbreakAttack`) and labels results `scenario_engine: "pyrit-backed"`.

## PyRIT APIs used

Inspected against [microsoft/PyRIT](https://github.com/microsoft/PyRIT) main / docs:

- `pyrit.__version__`
- `pyrit.setup.initialize_pyrit_async` + `IN_MEMORY` (best-effort)
- `pyrit.prompt_target.HTTPTarget` with Burp-style raw request and `{PROMPT}`
- `pyrit.prompt_target.get_http_target_json_response_callback_function` (`choices[0].message.content`)
- `pyrit.executor.attack.PromptSendingAttack`
- `pyrit.executor.attack.ManyShotJailbreakAttack` (when available)
- Preferred class names recorded in report metadata: `CrescendoAttack`, `PAIRAttack`, `TreeOfAttacksWithPruningAttack`, `RedTeamingAttack`, `ManyShotJailbreakAttack`

## Run shape

1. Require a `PinnedTarget`.
2. Write `pyrit-run.json` (authorized URL, scenario, judge / adversarial policy, transcripts+usage flags).
3. Subprocess: `sys.executable -m attestra.aasi.pyrit_native run --config <host path> --output <host path> --scenario <id>` (never `shell=True`).
4. Native module imports `pyrit`, builds `HTTPTarget`, executes the conservative (or many-shot) attack path, writes `pyrit-results.json` for `attestra.importers.pyrit`.
5. Adapter copies usage / `pyrit_version` into `ScannerResult.extra`.

## Deprecated Docker worker

`docker/aasi/pyrit_worker/` and `Dockerfile.pyrit` are **deprecated** for the adapter path. Leave the tree in place for historical builds; do not wire `ATTESTRA_IMAGE_PYRIT` for V5.1 scans. Offline importer fixtures continue to work unchanged.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest tests/runner/test_pyrit_adapter.py tests/aasi/test_pyrit_native.py -q --tb=short
```

Coverage: mock pyrit missing/present, `allows_docker=False`, scenario allowlist rejection, native argv module, judge lockdown config, usage attach.
