# AASI final implementation report (Phase 13)

Branch: `attestra-asi-bundle`. Inspected: **2026-11-23**. Companion: [`AASI_IMPLEMENTATION_STATUS.md`](AASI_IMPLEMENTATION_STATUS.md), [`AASI_PRODUCTION_READINESS_REPORT.md`](AASI_PRODUCTION_READINESS_REPORT.md), [`AASI_PHASE13_COMPLETION.md`](AASI_PHASE13_COMPLETION.md).

**Classification: READY FOR STAGING** — not production-ready. AI scanner digests remain placeholders; no staging or production deploy was verified in this session. This report documents what exists in the tree; it does **not** claim a production deployment occurred.

---

## 1. What AASI is

Attestra Agentic Security Intelligence (AASI) adds AI/LLM target catalogues, offline importers, digest-gated scanner adapters, a recommend-only agentic loop under `/api/aasi`, attack-path graph helpers, draft GitHub remediation PR proposals, and report sections — all behind `ATTESTRA_AASI=off` by default.

---

## 2. Implemented surface (tree-verified)

### Package and API

| Area | Path / symbol | Notes |
|---|---|---|
| Core package | `attestra/aasi/` | `contracts`, `budget`, `provider`, `context`, `roles`, `orchestrator`, `store`, `evidence_gate`, `task_tree`, `prioritize`, `graph`, `routes` |
| Feature flag | `attestra/config.py` → `AASI_ENABLED` | From `ATTESTRA_AASI` (default off) |
| HTTP API | `attestra/aasi/routes.py` mounted in `attestra/api.py` | `GET /api/aasi/status` always; mutate routes 404 when disabled |
| Mongo migrations | `0005_aasi_collections`, `0006_aasi_graph` | Runs / decisions; graph nodes / edges |

### Catalogues and import

| Area | Evidence |
|---|---|
| Asset / tests | `ai_app` asset kind; `ai_llm`, `ai_agent` test types in `attestra/models.py` |
| Taxonomy | `attestra/compliance/data/ai_taxonomy.yaml`; ISO 42001 pack present |
| Importers | `garak`, `promptfoo`, `safelabs`, `pyrit` under `attestra/importers/` and `PARSERS` |

### Scanner adapters (isolated containers)

| Adapter | Module | Registry | Image env | Digest in repo |
|---|---|---|---|---|
| Garak | `attestra/runner/scanners/garak.py` | yes | `ATTESTRA_IMAGE_GARAK` | placeholder |
| Promptfoo | `attestra/runner/scanners/promptfoo.py` | yes | `ATTESTRA_IMAGE_PROMPTFOO` | placeholder |
| SafeLabs | `attestra/runner/scanners/safelabs.py` | yes | `ATTESTRA_IMAGE_SAFELABS` | placeholder |
| PyRIT | `attestra/runner/scanners/pyrit.py` | yes | `ATTESTRA_IMAGE_PYRIT` | placeholder |

Placeholders live in `config._PLACEHOLDER_IMAGES` and commented stubs in `docker/scanner-digests.env`. Runtime refuses them via `image_is_placeholder`.

### Phase 4–7 product pieces

| Piece | Status in tree |
|---|---|
| Evidence gate / task tree / prioritize | Implemented in package; unit-tested |
| Attack-path graph store | `attestra/aasi/graph.py` + migration `0006` |
| GitHub draft PR proposals | `attestra/integrations/github_pr.py` + `tests/integrations/test_github_pr.py` |
| Report sections | `attestra/reports/aasi_sections.py` hooked from `render.py` / templates |

### Env, Docker, validation

| Item | Path |
|---|---|
| Dev env template | `.env.example` (AASI block; GARAK/PROMPTFOO/SAFELABS commented — **PyRIT line absent** from example) |
| Prod env template | `.env.production.example` (AASI off; same three image stubs) |
| Digest comments | `docker/scanner-digests.env` (all four AI images commented placeholders) |
| Compose | Default `scanner-pull` = web tools only; optional `aasi-scanner-pull` **commented** |
| Validate script | `scripts/aasi/validate_aasi_env.py` |
| Deploy guide | `docs/ai_security/AASI_DOCKER_DEPLOYMENT.md` |

### Tests (unit / offline)

Present under `tests/aasi/`, `tests/runner/test_*_{garak,promptfoo,safelabs,pyrit}_adapter.py`, `tests/test_importer_*`, `tests/test_aasi_*`, `tests/test_ai_taxonomy.py`, `tests/integrations/test_github_pr.py`, `tests/automated_vapt/test_aasi_coverage_origin.py`. **No full end-to-end run against a live vulnerable AI lab was executed or claimed in this session.**

---

## 3. Phase roll-up

| Phase | Outcome |
|---|---|
| 0 Baseline / licence | Complete — Shannon AGPL prohibited (documented) |
| 1 Assets / importers / taxonomy | Complete |
| 2 Adapters + coverage honesty | Implemented; digests not production-pinned |
| 3 Recommend-only core + API + store | Complete |
| 4 Evidence intelligence | Helpers implemented |
| 5 PyRIT worker adapter | Registered; digest placeholder |
| 6 Graph + draft GitHub PRs | Implemented in tree |
| 7 Reporting sections | Complete (hashing/four-eyes unchanged) |
| 8 Env templates | Complete (templates; digests placeholders) |
| 9 Docker docs / validate | Docs + stub; no real AI digests committed |
| 10 Dependency / licence inventory | Docs; AI tools kept out of core `pyproject` |
| 11 README / SETUP pointers | Complete |
| 12 Testing depth | Unit coverage; no live-AI e2e claimed |
| 13 Production-readiness docs | **This pass** — documentation only |

---

## 4. Explicit non-claims

- Production (or staging) **was not deployed** as part of Phase 13.
- Real AI scanner image digests are **not** pinned or verified in-repo.
- Core `.venv` package versions may still sit **below** `pyproject.toml` floors (documented in Phase 10 inventory).
- Shannon (AGPL-3.0) remains **no code reuse**.

---

## 5. Pointers

| Doc | Role |
|---|---|
| [`AASI_PRODUCTION_READINESS_REPORT.md`](AASI_PRODUCTION_READINESS_REPORT.md) | Gate checklist + classification |
| [`AASI_DEPLOYMENT_RUNBOOK.md`](AASI_DEPLOYMENT_RUNBOOK.md) | Operator enablement steps |
| [`AASI_ROLLBACK_RUNBOOK.md`](AASI_ROLLBACK_RUNBOOK.md) | Disable / revert steps |
| [`AASI_IMPLEMENTATION_STATUS.md`](AASI_IMPLEMENTATION_STATUS.md) | Master feature matrix |
| [`lat.md/aasi.md`](../../lat.md/aasi.md) | Knowledge-graph snapshot |
