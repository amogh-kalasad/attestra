# AASI Phase 1 — AI asset kinds and test types

Status: **Implemented** (catalogue only). Importers, adapters, and UI wiring are later phases.

## What changed

`attestra/models.py` now authorizes AI targets the same way as web/API/host assets:

| Key | Catalogue | Meaning |
| --- | --- | --- |
| `ai_app` | `ASSET_KINDS` | AI application / LLM endpoint |
| `ai_llm` | `TEST_TYPES` | LLM vulnerability assessment — OWASP LLM Top 10 (2025); imports `garak`, `promptfoo`, `pyrit` |
| `ai_agent` | `TEST_TYPES` | Agentic AI security assessment — OWASP Agentic Applications; imports `safelabs`, `promptfoo`, `garak` |

`DEFAULT_TESTS["ai_app"]` is `["ai_llm", "ai_agent"]` (VA-oriented; no `manual_pt`).

`DISPLAY_LABELS` includes `ai_app`, `ai_llm`, and `ai_agent` (existing compliance `ai_*` labels unchanged).

`VA_TEST_TYPES` derives from `TEST_TYPES` minus `PT_TEST_TYPES`, so `ai_llm` / `ai_agent` are allowed on VA (and VA+PT) engagements and are **not** in the PT-only set.

## Authorization

This phase only extends catalogues. Scans and imports still require a signed authorization that covers the asset and test types — nothing is bypassed.

## Tests

`tests/test_aasi_asset_types.py` asserts kind/type presence, defaults, VA inclusion, and PT exclusion.

## Out of scope here

- Garak / Promptfoo / SafeLabs / PyRIT importers and runner adapters
- UI form options (API catalog already exposes `ASSET_KINDS` / `TEST_TYPES` dynamically)
- Compliance taxonomy YAML and report sections
