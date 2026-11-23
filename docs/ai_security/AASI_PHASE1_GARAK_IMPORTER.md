# AASI Phase 1 — Garak importer

Short design note for `attestra/importers/garak.py`. Parent wiring of `PARSERS` is out of scope for this slice.

## Input

Native Garak JSONL (report or hitlog), or a JSON array of the same records.

| `entry_type` / shape | Role |
|---|---|
| `init` | `garak_version` → `tool_version` |
| `start_run setup` | target type/name → `location` |
| `attempt` (`status == 2`) | Per-detector scores in `detector_results` |
| `eval` / `probe_summary` / `digest` | Recognized; **no** findings |
| hitlog row (`probe`/`detector`/`score`, no `entry_type`) | One finding when `score >= 0.5` |

## Hit rule

Aligns with Garak `ThresholdEvaluator` (default threshold **0.5**): a detector hit is any score `>= 0.5`. Only qualifying hits become `NormalizedFinding` rows. Probe execution alone and eval fail counts alone do **not**.

## Finding shape

- `tool="garak"`
- `rule_id="{probe}:{detector}"`
- `original_id` from attempt UUID (+ detector / seq / idx)
- `severity`: `high` if score `>= 0.85`, else `medium`
- `cwe=None` (never invented)
- `confidence` = score string; `evidence_refs` carry attempt id, score, truncated prompt/output

## Malformed input

Empty → `[]`. Invalid JSON/JSONL or non-object `detector_results` → `ValueError`.

## Fixtures

`tests/fixtures/ai/garak/` — `hits.report.jsonl`, `no_hit.report.jsonl`, `malformed.report.jsonl`, `hitlog.jsonl`.
