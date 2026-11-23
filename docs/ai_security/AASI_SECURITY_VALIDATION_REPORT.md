# AASI security validation report (Phase 12)

Branch: `attestra-asi-bundle`. Date: 2026-11-23.

Offline validation of AASI trust boundaries. Each row maps a Phase 12 scenario to the primary module under test and the result from `tests/aasi/test_aasi_security.py`.

## Method

- Unit / integration-style tests with fakes and monkeypatches
- No live network exploitation, no real Docker pulls, no live LLM provider calls
- Assertions target existing gates (orchestrator, evidence_gate, budget, importers, adapters, routes, QA)

## Scenario matrix

| # | Scenario | Primary modules | Result |
|---|---|---|---|
| 1 | Prompt injection in scanner output | `importers/promptfoo.py`, `aasi/context.py` | PASS |
| 2 | Prompt injection in retrieved documents | `aasi/context.py` | PASS |
| 3 | Unauthorized AI asset rejected | `aasi/orchestrator.py` | PASS |
| 4 | Cross-tenant evidence citation rejected | `aasi/evidence_gate.py` | PASS |
| 5 | Unregistered test ID rejected | `aasi/orchestrator.py` | PASS |
| 6 | Scope escalation blocked | `aasi/orchestrator.py` | PASS |
| 7 | Arbitrary command request rejected | `runner/scanners/pyrit.py`, `runner/scanners/garak.py` | PASS |
| 8 | Secret leakage prevented in provider prompts | `aasi/provider.py`, `ai_narratives.py` | PASS |
| 9 | Unbounded agent loop stopped by budget | `aasi/orchestrator.py` (`SimpleBudget`), `aasi/budget.py` | PASS |
| 10 | Excessive model calls stopped by budget | `aasi/orchestrator.py`, `aasi/budget.py` | PASS |
| 11 | Approval bypass ineffective | `aasi/orchestrator.py` | PASS |
| 12 | Forged evidence ID rejected | `aasi/evidence_gate.py`, `aasi/orchestrator.py` | PASS |
| 13 | Malformed tool output rejected by importers | `importers/{garak,promptfoo,safelabs,pyrit}.py` | PASS |
| 14 | Duplicate run idempotency | `aasi/store.py` | PASS |
| 15 | AI-disabled regression | `aasi/routes.py`, `aasi/orchestrator.py` | PASS |
| 16 | Failed scanner output not treated as passed | `automated_vapt/core/run_validity.py` | PASS |
| 17 | Report claims without evidence fail QA | `reports/aasi_sections.py` (`aasi_qa_issues`) | PASS |
| 18 | Unpinned scanner image rejection | `config.py` (`require_image_digest` / `image_is_placeholder`), adapters | PASS |

## Counts

| Suite | Passed | Failed | Notes |
|---|---:|---:|---|
| `tests/aasi/test_aasi_security.py` | 18 | 0 | Phase 12 security file |
| Scenario coverage | 18 / 18 | — | All listed scenarios exercised |

## Residual risk / honesty

- Placeholder AI image digests remain refused at runtime until operators pin real digests.
- These tests do not prove resistance to every prompt-injection variant against a live model; they prove Attestra **redacts and gates** untrusted content before persistence / planner hand-off.
- Cross-tenant and forged-evidence checks rely on injectable lookup / fake Mongo; production Mongo indexes and RBAC remain required operational controls.
