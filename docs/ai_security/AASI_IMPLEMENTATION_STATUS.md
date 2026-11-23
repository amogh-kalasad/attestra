# AASI implementation status

Phase tracker for Attestra Agentic Security Intelligence (AASI) on branch `attestra-asi-bundle`.
Companion docs: [`AASI_BASELINE_AUDIT.md`](AASI_BASELINE_AUDIT.md), [`AASI_REPOSITORY_FINDINGS.md`](AASI_REPOSITORY_FINDINGS.md), [`REPOSITORY_ADOPTION_MATRIX.md`](REPOSITORY_ADOPTION_MATRIX.md), [`AASI_LICENSE_REVIEW.md`](AASI_LICENSE_REVIEW.md), [`AASI_IMPLEMENTATION_BLUEPRINT.md`](AASI_IMPLEMENTATION_BLUEPRINT.md), [`AASI_PHASE11_COMPLETION.md`](AASI_PHASE11_COMPLETION.md), [`AASI_PHASE13_COMPLETION.md`](AASI_PHASE13_COMPLETION.md), [`AASI_FINAL_IMPLEMENTATION_REPORT.md`](AASI_FINAL_IMPLEMENTATION_REPORT.md), [`AASI_PRODUCTION_READINESS_REPORT.md`](AASI_PRODUCTION_READINESS_REPORT.md).

Verified against the working tree on **2026-11-23** (code + docs). **AI scanner digests remain placeholders** (`REPLACE_AFTER_INSPECT` / all-zero defaults) and are refused at runtime until operators pin real digests.

## Classification (Phase 13)

| Field | Value |
|---|---|
| **Classification** | **READY FOR STAGING** |
| Alternate framing | READY FOR PRODUCTION REVIEW |
| **Not** | PRODUCTION READY |
| Production deploy verified? | **No** |

---

## Master feature matrix

Legend: **Production configured** = real digests/secrets/flags set in a deployed staging or production environment (not merely templates in git).

| Feature | Planned | Implemented | Tested | Production configured |
|---|---|---|---|---|
| Phase 0 baseline / licence / Shannon AGPL ban | Yes | Yes | Docs review | N/A (policy) |
| Asset kind `ai_app` + tests `ai_llm` / `ai_agent` | Yes | Yes | Unit (`test_aasi_asset_types`) | No (needs ops engagement config) |
| AI taxonomy + ISO 42001 pack data | Yes | Yes | Unit (`test_ai_taxonomy`) | No |
| Importer: Garak | Yes | Yes | Unit | No |
| Importer: Promptfoo | Yes | Yes | Unit | No |
| Importer: SafeLabs | Yes | Yes | Unit | No |
| Importer: PyRIT | Yes | Yes | Unit | No |
| Adapter: Garak (digest-gated container) | Yes | Yes | Unit (adapter) | **No** — digest placeholder |
| Adapter: Promptfoo | Yes | Yes | Unit | **No** — digest placeholder |
| Adapter: SafeLabs | Yes | Yes | Unit | **No** — digest placeholder |
| Adapter: PyRIT | Yes | Yes | Unit | **No** — digest placeholder |
| Coverage origin `aasi` + AI-tool → NOT_TESTED | Yes | Yes | Unit | No |
| AASI contracts / budget / roles | Yes | Yes | Unit (`tests/aasi/`) | No |
| Orchestrator recommend-only | Yes | Yes | Unit | No |
| `/api/aasi` routes (flag-gated) | Yes | Yes | Unit | No |
| Mongo `aasi_runs` / `aasi_decisions` (`0005`) | Yes | Yes | Unit / migration test | No |
| Evidence gate / task tree / prioritize | Yes | Yes | Unit | No |
| Attack-path graph (`0006`) | Yes | Yes | Unit | No |
| GitHub draft remediation PR proposals | Yes | Yes | Unit (`test_github_pr`) | No |
| Report sections (`aasi_sections`) | Yes | Yes | Unit (`test_aasi_reporting`) | No |
| Env templates (`.env.example`, `.env.production.example`) | Yes | Yes | Manual/docs | Templates only |
| `validate_aasi_env.py` | Yes | Yes | Script runnable | N/A |
| Docker / Compose optional AI pull docs | Yes | Yes (commented) | Docs | **No** |
| Live vulnerable AI lab e2e | Yes (Phase 12+) | **No** (this session) | **No** | **No** |
| Real AI image digests pinned in repo/ops | Yes | **No** | **No** | **No** |
| Shannon code reuse | No (prohibited) | Prohibited | Licence docs | Must stay No |

---

## Phase 0 — Baseline and prerequisites

| Track / item | Status | Notes |
|---|---|---|
| Track A — Git / `*.bak_*` hygiene | **Complete** | `*.bak_*` in `.gitignore` |
| Track B — Source architecture snapshot | **Complete** | Mongo migrations include `0005_aasi_collections`, `0006_aasi_graph` |
| Track B — Repository findings inventory | **Complete** | Path existence table + gaps documented |
| Track C — Python environment | **Complete** | `.venv` usable; `import attestra` OK; floors may lag pyproject |
| Track C — Lat validation | **Complete** (baseline) | Phase 13 updates `lat.md/aasi.md` |
| Track C — Docker deployment | **Complete** | Compose + web digests; AI digests still placeholders |
| Track C — License policy | **Complete** | Shannon AGPL prohibited; scanners isolated containers |
| External repo adoption matrix | **Complete** | `REPOSITORY_ADOPTION_MATRIX.md` |
| Licence review | **Complete** | `AASI_LICENSE_REVIEW.md` |

**Phase 0 status: COMPLETE.**

## Phase table (verified)

| Phase | Status | What exists in tree |
|---|---|---|
| Phase 0 — Baseline | **Complete** | Hygiene, audits, licence review |
| Phase 1 — AI targets + importers + taxonomy | **Complete** | `ai_app` / `ai_llm` / `ai_agent`; importers `garak`, `promptfoo`, `safelabs`, `pyrit`; `ai_taxonomy.yaml` |
| Phase 2 — AI tool adapters | **Partially implemented** | Adapters `garak`, `promptfoo`, `safelabs`, `pyrit` registered; coverage `origin=aasi`; AI-tool outcomes → `NOT_TESTED`. Digests **not** production-pinned |
| Phase 3 — AASI core (recommend-only) | **Complete** | `attestra/aasi/` contracts, budget, provider/context, roles, orchestrator, store, `/api/aasi` (default off) |
| Phase 4 — Evidence intelligence | **Partially implemented** | `evidence_gate.py`, `task_tree.py`, `prioritize.py` in package; not a full evidence-review product surface |
| Phase 5 — PyRIT worker | **Partially implemented** | `PyRITAdapter` registered; scenario allowlist; external judge off by default. Image digest still placeholder |
| Phase 6 — Attack-path + remediation PRs | **Partially implemented** | Mongo graph helpers (`graph.py`, migration `0006_aasi_graph`); draft GitHub PR client `attestra/integrations/github_pr.py` |
| Phase 7 — Reporting and compliance | **Complete (report sections)** | `aasi_sections.py` + render/templates hook; executive/technical/traceability/coverage; `aasi_qa_issues`; four docs. Hashing/signing/four-eyes unchanged |
| Phase 8 — Production config / env | **Complete** (templates) | `.env.example` AASI/AI blocks; `.env.production.example`; inventory + draft docs. Digests still `REPLACE_AFTER_INSPECT`; PyRIT stub missing from env examples |
| Phase 9 — Docker production | **Partially implemented** | Docs `AASI_DOCKER_DEPLOYMENT.md`, `scripts/aasi/validate_aasi_env.py`, commented Compose/digest notes. **No real AI digests committed** |
| Phase 10 — Dependency management | **Complete** (docs) | `AASI_DEPENDENCY_AND_LICENSE_INVENTORY.md`, `AASI_WORKER_IMAGES.md` — AI tools stay out of core `pyproject` |
| Phase 11 — README / install docs | **Complete** | Root README AASI section; SETUP_GUIDE subsection; status pointers |
| Phase 12 — Full testing / security | **Partially implemented** | `tests/aasi/test_aasi_security.py` (18 offline security/regression scenarios); Phases 1–7 unit paths; **no** full live-AI e2e claimed |
| Phase 13 — Production readiness | **Complete** (docs) | Final + readiness reports, deploy/rollback runbooks, matrix, changelog, lat pointer — **READY FOR STAGING** |

## Enablement (implemented)

| Knob | Default | Role |
|---|---|---|
| `ATTESTRA_AASI` | `off` | Master flag → `config.AASI_ENABLED` / `attestra.aasi.enabled()` |
| `ATTESTRA_AASI_MAX_*` / `RETRY_LIMIT` | bounded | Orchestrator budget ceilings |
| `ATTESTRA_AASI_REQUIRE_APPROVAL` | `on` | Human approval before intrusive recommendations |
| `ATTESTRA_AI_NARRATIVES` / tenant off-list | off / honour | Provider also gated by narratives stack |
| `ATTESTRA_IMAGE_GARAK` / `PROMPTFOO` / `SAFELABS` / `PYRIT` | placeholders | Required for adapter runs; placeholders refused |

## Blockers / honesty notes

- **Do not claim production AI scanner digests are pinned.**
- Shannon AGPL-3.0: hard no-reuse.
- No CLI `aasi` subcommand; HTTP API under `/api/aasi` (status always answers; mutate routes 404 when disabled).
- No staging/production deploy verified in the Phase 13 documentation session.
- Core venv may lag `pyproject.toml` floors — refresh with `pip install -e ".[dev]"` before relying on declared minimums.
- Runbooks: [`AASI_DEPLOYMENT_RUNBOOK.md`](AASI_DEPLOYMENT_RUNBOOK.md), [`AASI_ROLLBACK_RUNBOOK.md`](AASI_ROLLBACK_RUNBOOK.md).
