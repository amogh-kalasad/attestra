# AASI Phase 1 — SafeLabs + PyRIT importers

Phase 1 offline parsers for SafeLabs `safelabs-eval` and Microsoft PyRIT structured exports. Worker/adapter execution is out of scope here (SafeLabs adapter ≈ Phase 2; PyRIT worker = Phase 5).

## Shared rules

- Output shape: [`NormalizedFinding`](../../attestra/importers/base.py) (`tool` = `safelabs` or `pyrit`).
- Malformed input → `ValueError`.
- Empty / all-negative exports → `[]` (no false findings).
- Only **positive detections** become findings.
- `NormalizedFinding` has **no validation-status field**. Persist-time validation must remain **`potential`**. Heuristic uncertainty / score strings go on `confidence`.

These parsers are not registered in `PARSERS` by this change; call `attestra.importers.safelabs.parse` / `attestra.importers.pyrit.parse` directly until the registry is wired by the owning Phase 1 bundle work.

---

## SafeLabs (`attestra/importers/safelabs.py`)

### Source shape

Matches `safelabs-eval` CLI `--output json` and `EvalResult` dumps (researched against AgentSafeLabs/safelabs-eval ≥ 0.12):

```json
{
  "version": "0.12.0",
  "target": "http://localhost:8000/chat",
  "results": [
    {
      "id": "ASI01-001",
      "category": "ASI01",
      "severity": "critical",
      "verdict": "vulnerable",
      "confidence": 0.7,
      "reasoning": "...",
      "indicators": ["..."],
      "echoed_indicators": [],
      "eval_type": "prompt_injection",
      "remediation_hint": "..."
    }
  ]
}
```

Also accepts `{ "records": [ { "prompt_id", "scoring_result": { ... } } ] }` and JSONL of record objects.

### Positive detections

| Verdict | Finding? |
| --- | --- |
| `vulnerable` | yes |
| `fail` | yes |
| `uncertain` | **no** (ambiguous; not a positive detection) |
| `pass` | no |
| `missing_infrastructure` / error-only rows | no |

### Preserved fields

| Source | NormalizedFinding |
| --- | --- |
| `id` / `prompt_id` | `rule_id`, `original_id` |
| `eval_type` / detector | `param` |
| `indicators` | `evidence_refs` + description |
| heuristic `confidence` + verdict | `confidence` string (`heuristic_detector; evidence_score=…; uncertainty=pattern_based; validation=potential`) |
| `version` / `safelabs_version` | `tool_version` |
| taxonomy | titles/descriptions say **SafeLabs ASI-source** (OWASP-inspired). **Not** labelled as official OWASP Agentic Top 10 2026 |

### Validation honesty

SafeLabs detectors are pattern-based heuristics. The importer **never** labels results as confirmed. Downstream import/persist must keep validation at **`potential`**.

### Fixtures / tests

- `tests/fixtures/ai/safelabs/report.json`
- `tests/fixtures/ai/safelabs/eval_records.json`
- `tests/test_importer_safelabs.py`

---

## PyRIT (`attestra/importers/pyrit.py`)

### Contract (fixture-driven)

Attestra accepts a structured attack-result export (not a live PyRIT import). Typical shape:

```json
{
  "tool": "pyrit",
  "tool_version": "1.2.1",
  "target": "https://llm.example.com/v1/chat",
  "attack_results": [
    {
      "attack_result_id": "...",
      "conversation_id": "...",
      "scenario_id": "...",
      "objective": "...",
      "attack_type": "CrescendoAttack",
      "outcome": "success",
      "success": true,
      "score": {
        "value": true,
        "score_type": "true_false",
        "category": ["jailbreak"],
        "rationale": "...",
        "scorer": "SelfAskTrueFalseScorer"
      }
    }
  ]
}
```

Also accepts `results` / `records` / `attacks` wrappers, a bare list, JSONL, or a single object.

Fields align with PyRIT `AttackResult` / score concepts (`conversation_id`, `outcome` ∈ `success|failure|error|undetermined`, score value/type).

### Positive detections

A row becomes a finding when **any** of:

- `outcome` ∈ success aliases (`success`, `succeeded`, …)
- `success: true`
- true/false score value is true
- float score ≥ explicit `success_threshold` when provided

`failure` / `error` / `undetermined` / `success: false` → **no finding**.

### Preserved fields

Conversation ID, scenario ID, score value, outcome/success flags, attack type, tool version, and scorer rationale are copied into description / `evidence_refs` / `confidence`.

### Fixtures / tests

- `tests/fixtures/ai/pyrit/attack_results.json`
- `tests/fixtures/ai/pyrit/attack_results.jsonl`
- `tests/test_importer_pyrit.py`

---

## Out of scope

- Registering `safelabs` / `pyrit` in `importers/__init__.py` `PARSERS` (owned elsewhere).
- Digest-pinned scanner adapters / PyRIT container worker.
- Mapping into `ai_taxonomy.yaml` / compliance packs.
- Raising validation above `potential` from these importers.
