# AASI Phase 1 completion report

Branch: `attestra-asi-bundle`. Date: 2026-11-23.

## Summary

Phase 1 makes Attestra able to authorize AI assets and ingest AI-security tool results offline. Scanner execution adapters are Phase 2.

## Components implemented

- Asset kind `ai_app` and test types `ai_llm`, `ai_agent` in `attestra/models.py`
- Importers: `garak`, `promptfoo`, `safelabs`, `pyrit` registered in `PARSERS`
- `attestra/compliance/data/ai_taxonomy.yaml` plus ISO 42001 `assessment_tools` evidence-source annotations
- Baseline fix: `test_unsupported_tool_raises` uses an unregistered tool name

## Files added

- `attestra/importers/garak.py`, `promptfoo.py`, `safelabs.py`, `pyrit.py`
- `attestra/compliance/data/ai_taxonomy.yaml`
- `tests/test_aasi_asset_types.py`, `test_importer_garak.py`, `test_importer_promptfoo.py`, `test_importer_safelabs.py`, `test_importer_pyrit.py`, `test_ai_taxonomy.py`
- `tests/fixtures/ai/{garak,promptfoo,safelabs,pyrit}/`
- `docs/ai_security/AASI_PHASE1_*.md`, `lat.md/aasi.md`

## Files modified

- `attestra/models.py`, `attestra/importers/__init__.py`
- `attestra/compliance/data/packs/iso_42001_2023.yaml`
- `tests/test_importers.py` (unsupported-tool case)
- `lat.md/import-pipeline.md`, `aasi.md`, `compliance.md`, `tests.md`, `findings.md`, `lat.md`

## Tests

`41 passed` for Phase 1 suite including registry wiring and the fixed unsupported-tool test.

## Lat

`lat check` — all checks passed.

## Next phase

Phase 2 — digest-pinned Garak / Promptfoo / SafeLabs scanner adapters via existing SDK + coverage/run_validity extensions.
