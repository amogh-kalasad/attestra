# AASI Phase 1 — Promptfoo importer

Short note for `attestra/importers/promptfoo.py` on branch `attestra-asi-bundle`.

## Input

`promptfoo eval -o results.json` or `promptfoo redteam run -o results.json` (schema v2/v3).

Typical export wrapper:

| Field | Role |
| --- | --- |
| `evalId` | Eval run id |
| `results.version` | `2` or `3` |
| `results.timestamp` | ISO run time |
| `results.results[]` | Per-cell `EvaluateResult` rows |
| `results.prompts` / `results.stats` | Prompt metrics and aggregate counts |
| `config` | Suite config (providers/targets, redteam plugins/strategies) |
| `metadata.promptfooVersion` | Tool version stamped onto findings |

Per-row fields used for findings:

| Field | Role |
| --- | --- |
| `success` | `false` → candidate finding; `true` → no finding |
| `failureReason` | `1` ASSERT kept; `2` ERROR skipped (not a vuln) |
| `gradingResult.pass` / `reason` / `componentResults` | Assertion outcome text |
| `metadata.pluginId` / `testCase.metadata.pluginId` | Plugin id → `rule_id` |
| `metadata.strategyId` / grading metadata | Strategy id → `variant` + `original_id` |
| `metadata.severity` / `harmCategory` / `goal` | Severity, title, description |
| `provider.id` / `label` | Target → `location` |
| `testIdx` / `id` | Test-case reference → `param` / `evidence_refs` |
| `response.output` | Truncated into description (evidence later) |

Bare `EvaluateSummary` (`{ version, results: [...] }`) is also accepted.

## Behaviour

- Failed red-team / security assertions → `NormalizedFinding(tool="promptfoo")`.
- Passed tests → no finding (coverage accounting is later).
- Malformed / unsupported structures → `ValueError`.
- CWE left `None` unless the source supplies a real CWE field (no invented mapping).
- Not registered in `importers.PARSERS` in this slice (call `promptfoo.parse` directly); registry wiring is a later exclusive change.

## Fixtures / tests

- `tests/fixtures/ai/promptfoo/results_failed.json` — failed assertions (+ one ERROR row skipped)
- `tests/fixtures/ai/promptfoo/results_passed.json` — all pass → `[]`
- `tests/fixtures/ai/promptfoo/results_malformed.json` — `ValueError`
- `tests/test_importer_promptfoo.py`

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_importer_promptfoo.py -q --tb=short
```
