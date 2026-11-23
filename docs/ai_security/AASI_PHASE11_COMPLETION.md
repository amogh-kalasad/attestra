# AASI Phase 11 completion report

Branch: `attestra-asi-bundle`. Date: 2026-11-23.

## Summary

Documentation pass for Attestra Agentic Security Intelligence. Status text matches the tree after inspection: Phases 0–1 and 3 complete; Phases 2 / 4–7 / 9 / 12 **partially implemented**; Phase 8 env templates and Phase 10 dependency docs complete; Phase 13 not started. **AI image digests are not production-pinned.**

## Docs updated

| File | Change |
|---|---|
| [`README.md`](../../README.md) | New **Attestra Agentic Security Intelligence (AASI)** section: enablement, asset kinds, importers, adapters (incl. PyRIT worker), API, honesty on digests |
| [`SETUP_GUIDE.md`](../../SETUP_GUIDE.md) | Short AASI subsection (flag off by default; optional AI image env vars) |
| [`docs/IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md) | Pointer bullet to the AASI status track |
| [`docs/ROADMAP.md`](../ROADMAP.md) | AASI note (parallel track on `attestra-asi-bundle`) |
| [`AASI_IMPLEMENTATION_STATUS.md`](AASI_IMPLEMENTATION_STATUS.md) | Phase table refreshed from tree inspection |
| This file | Phase 11 completion record |

## Verified claims (do not overstate)

- **Enabled only when** `ATTESTRA_AASI` is on (`off` default); listed in `.env.example`.
- Asset kind `ai_app`; test types `ai_llm`, `ai_agent`.
- Importers: `garak`, `promptfoo`, `safelabs`, `pyrit`.
- Adapters registered: `garak`, `promptfoo`, `safelabs`, `pyrit` (digests placeholders).
- Recommend-only `/api/aasi` mounted; agents do not invoke scanners.
- Phase 4 helpers (`evidence_gate`, `task_tree`, `prioritize`), Phase 6 graph store, and Phase 7 `aasi_sections` report builders exist; remediation PRs do not.

## Out of scope for Phase 11

No application code or digest pins were changed in this phase. No commit/push. `lat.md` was not edited (exclusive file set for this task).
