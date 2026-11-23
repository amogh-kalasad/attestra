# AASI Phase 1 — AI taxonomy mapping

Status: **Implemented data + docs** (taxonomy YAML and ISO pack tool refs). Importers and `ai_llm` / `ai_agent` test types may land in parallel Phase 1 work; this file describes the mapping artefact only.

Canonical machine-readable map: [`attestra/compliance/data/ai_taxonomy.yaml`](../../attestra/compliance/data/ai_taxonomy.yaml).

## Purpose

Give Attestra a single, honest matrix from AI red-team tool outputs (Garak probes, Promptfoo plugins, SafeLabs tests, PyRIT scenarios) to:

1. **OWASP Top 10 for LLM Applications 2025** (`LLM01`–`LLM10`) — matches [`owasp.yaml`](../../attestra/compliance/data/owasp.yaml) `llm_top10_2025` and the ISO pack `llm_top10` block.
2. **OWASP Top 10 for Agentic Applications (2026 edition)** (`ASI01`–`ASI10`) — published 2025-12-09 by the OWASP GenAI Security Project Agentic Security Initiative.
3. **CWE** — only IDs already listed under `packs/iso_42001_2023.yaml` → `llm_top10` (no invented CWEs).
4. **ISO/IEC 42001:2023** Annex A controls already wired in that pack.

## Sources (versioned)

| Source | Edition / date | Notes |
| --- | --- | --- |
| OWASP LLM Top 10 | **2025** | Primary for `ai_llm`. Attestra packs stay on 2025 even though a 2026 LLM Top 10 also exists. |
| OWASP Agentic Top 10 | **2026** (published 2025-12-09) | Primary for `ai_agent`. Official names: Agent Goal Hijack … Rogue Agents. |
| ISO/IEC 42001 | **2023** pack in-repo | CWE + control links are Attestra engineering judgement (pack header says neither ISO nor OWASP publishes an official map). |
| Independent coverage matrix | Snapshot 2026-08-03 | Used as a cross-check for which tools ship dedicated tests; not product truth. |

## Tool mapping summary

Counts below are **families** in `ai_taxonomy.yaml` (probe/plugin/scenario/test entries), not every upstream sub-probe.

| Tool | Families mapped | Primary use | Honesty |
| --- | --- | --- | --- |
| **garak** | 15 probe families + 2 explicit gaps | Breadth LLM probes | Internal `owasp:llmNN` tags are **2023** numbering — map by behaviour to 2025. No dedicated LLM04 / LLM08. |
| **promptfoo** | 26 plugin/preset entries | OWASP-preset red team | Official docs map plugins to LLM01–LLM10. LLM03/04/10 often **partial**. |
| **safelabs** | 10 ASI tests | Agent eval | SafeLabs ASI01–ASI10 ≠ official OWASP Agentic ASI01–ASI10. Crosswalk `confidence: low` / `status: unverified`. Cap findings ≤ `potential`. |
| **pyrit** | 8 scenarios/datasets + 6 gaps | Multi-turn jailbreaks | Strong on LLM01; most other LLM categories **not_covered** as shipped turnkey tests. |

### LLM Top 10 coverage (honest)

| ID | Name | Testable tools | Status in taxonomy |
| --- | --- | --- | --- |
| LLM01 | Prompt Injection | garak, promptfoo, pyrit | testable |
| LLM02 | Sensitive Information Disclosure | garak, promptfoo | testable (PyRIT partial) |
| LLM03 | Supply Chain | garak, promptfoo | **partial** (hallucination / ModelAudit proxies) |
| LLM04 | Data and Model Poisoning | promptfoo | **partial** (behavioural proxy only) |
| LLM05 | Improper Output Handling | garak, promptfoo | testable |
| LLM06 | Excessive Agency | promptfoo, garak | **partial** (PyRIT not covered) |
| LLM07 | System Prompt Leakage | garak, promptfoo | testable |
| LLM08 | Vector and Embedding Weaknesses | promptfoo | testable (garak/PyRIT gap) |
| LLM09 | Misinformation | garak, promptfoo | testable (no pack CWE) |
| LLM10 | Unbounded Consumption | garak, promptfoo | **partial** |

Unsupported categories are labelled `not_covered` / `partial` / `unverified` — never treated as covered.

### Agentic Top 10 coverage (honest)

Most Agentic entries are **partial** or **not_covered** in Phase 1. ASI06 (Memory & Context Poisoning) and ASI10 (Rogue Agents) have **no** mapped tool coverage. SafeLabs results must be remapped through `tools.safelabs.tests` before any official ASI ID is asserted.

## ISO 42001 pack extension

[`iso_42001_2023.yaml`](../../attestra/compliance/data/packs/iso_42001_2023.yaml) gains:

- Per-`llm_top10` entry: optional `assessment_tools` listing garak / promptfoo / safelabs / pyrit evidence sources (only where a real test exists).
- Top-level `assessment_tools` / `ai_tools` section describing how those tools feed A.6.2.4-style verification evidence.

A clean scan still **never** marks a 42001 control `met` by itself (existing pack roll-up rules).

## Categories → Attestra test types

| Test type | Primary taxonomy | Tools |
| --- | --- | --- |
| `ai_llm` | OWASP LLM Top 10 2025 | garak, promptfoo, pyrit |
| `ai_agent` | OWASP Agentic Top 10 2026 | safelabs, promptfoo, garak, pyrit |

(`ASSET_KINDS` / `TEST_TYPES` registration is out of scope for this taxonomy-only change set.)

## What this Phase 1 artefact does **not** do

- Does not invent CWE numbers.
- Does not equate SafeLabs ASI IDs with official OWASP Agentic ASI IDs.
- Does not claim ISO or Agentic coverage without a mapped test.
- Does not edit importers or `models.py` (owned elsewhere).

## Validation

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_ai_taxonomy.py -q --tb=short
```

The test loads the YAML and asserts required top-level keys, source entries, tool blocks, and category keys.
)
