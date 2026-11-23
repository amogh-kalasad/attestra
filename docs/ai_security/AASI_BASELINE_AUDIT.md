# AASI baseline audit

Phase 0 baseline for Attestra Agentic Security Intelligence (AASI).
Track B records how existing modules fit together; track C records Python env, Lat, Docker, licences, and a pytest sample.
Verified against source on branch `attestra-asi-bundle` (no product code changed). Companion inventory: [`AASI_REPOSITORY_FINDINGS.md`](AASI_REPOSITORY_FINDINGS.md). Status table: [`AASI_IMPLEMENTATION_STATUS.md`](AASI_IMPLEMENTATION_STATUS.md).

## Source architecture snapshot

Attestra is already a full authorization → plan → execute/import → validate → comply → report pipeline. AASI must plug into these seams; it must not introduce a second persistence layer, planner, validation enum, or scanner SDK.

### Persistence (Mongo active; SQLAlchemy schema only)

- **Active store:** MongoDB. [`attestra/db.py`](../../attestra/db.py) `session()` yields `MongoSession`; `_engine` is unused for writes. Declarative `Base` in the same module is the schema that MongoSession maps.
- **Collections:** [`persistence/mongo/collections.py`](../../attestra/persistence/mongo/collections.py) names domain collections 1:1 with legacy tables (`findings`, `evidence`, `jobs`, `automated_test_executions`, `audit_events`, …) plus upgrade INT (`api_inventories`, `discovery_candidates`, `asset_snapshots`, `asset_change_events`).
- **Migrations:** In-code list in [`migrations/__init__.py`](../../attestra/persistence/mongo/migrations/__init__.py): `0001_mongo_baseline` … `0004_upgrade_int_indexes`. **Next free ID: `0005`.** Applied by `apply_pending()` into `_schema_migrations`.
- **Tenant isolation:** [`tenant.py`](../../attestra/persistence/mongo/tenant.py) `effective_scope` / `SYSTEM_SCOPE` / `TenantAccessDenied`; every AASI read/write must go through this.

### Authorization and execution gates

- **Runner scope:** [`runner/authorization.py`](../../attestra/runner/authorization.py) builds `AuthorizedScope` from the engagement, then `authorize_target` / `validate_url_target` / `validate_resolved_ips` / `assert_safe_cli_arg` at execution time.
- **Automated VAPT guard:** [`authorization_guard.py`](../../attestra/automated_vapt/core/authorization_guard.py) `assert_engagement_ready_for_case` / `load_asset` re-check halt, status, auth expiry, environment, window, ownership.
- **Intrusive policy:** [`intrusive_policy.py`](../../attestra/automated_vapt/core/intrusive_policy.py) fail-closed for `SSRF`, `UPLOAD`, `XSSSTORE`, `T22`; production environments never allowed.
- **Run validity:** [`run_validity.py`](../../attestra/automated_vapt/core/run_validity.py) folds response classifications into run states (`VALID`, `AUTH_EXPIRED`, `CHALLENGE_DETECTED`, `RATE_LIMITED`, …). Empty or blocked AI-tool output should map here as not tested, never as passed.

### Planning and catalogue

- **Catalogue:** [`test_registry.py`](../../attestra/automated_vapt/core/test_registry.py) registers Elite cases (T01–T22 plus named probes). Agents may only recommend IDs that exist here or as registered adapter capabilities.
- **Planner:** [`planner.py`](../../attestra/automated_vapt/core/planner.py) `PlanFacts` → `plan_cases()` → `PlannedCase` actions `run` | `skip` | `defer`, with session/secondary/intrusive and rate-profile rules. Remains the only execution planner.
- **Coverage:** [`coverage/ledger.py`](../../attestra/automated_vapt/coverage/ledger.py) stores per-case ledger rows on the execution; extend categories rather than building a second ledger.

### Scanners and importers

- **SDK:** [`sdk.py`](../../attestra/runner/scanners/sdk.py) `AdapterMeta` (capabilities, `asset_kinds`, safety tier T0–T3, `network_egress`, `ResourceProfile`, licence, `image_ref_env`, output schema). [`base.py`](../../attestra/runner/scanners/base.py) `ScannerAdapter` + `ScannerResult` (`raw_sha256`) + `run_process` (no shell).
- **Registry (14):** `trivy`, `semgrep`, `nuclei`, `zap`, `prowler`, `kube_bench`, `testssl`, `gitleaks`, `checkov`, `naabu`, `webcheck`, `subfinder`, `dnsx`, `httpx_probe`.
- **Importers:** [`importers/base.py`](../../attestra/importers/base.py) `NormalizedFinding`; [`importers/__init__.py`](../../attestra/importers/__init__.py) `PARSERS` for zap/nuclei/trivy/sarif/cyclonedx/dependency_track/prowler/kube_bench/testssl/gitleaks/checkov/naabu/webcheck/observatory/ssllabs/burp/nessus plus discovery stubs. AI tools get importers first, then container adapters.
- **Jobs:** [`jobs/durable.py`](../../attestra/jobs/durable.py) Mongo durable queue (enqueue, claim, cancel) driving adapters for scan runs.

### Findings, proof, audit, AI, compliance, reports

- **Validation classes:** [`finding_validation/statuses.py`](../../attestra/finding_validation/statuses.py) — `unvalidated`, `confirmed`, `needs_manual_validation`, `potential`, `false_positive`, `informational`, `not_reproducible`, `accepted_risk`. Do not add a new enum; AI imports should enter as `potential` / `needs_manual_validation`.
- **Asset / test types:** [`models.py`](../../attestra/models.py) `ASSET_KINDS` = web_app, api, host, repo, image, cloud_account, mobile_app; `TEST_TYPES` = web_dast, api_dast, manual_pt, tls, network_va, sca_container, sast, iac_cloud, mobile. **No AI asset kind or AI test type yet** (Phase 1 gap).
- **Proof:** [`proof/`](../../attestra/proof/) capture, pair, redact, replay, screenshots, store — raw evidence before verdicts.
- **Audit:** [`audit.py`](../../attestra/audit.py) hash-chained `record` / `verify` (Mongo-backed).
- **AI narratives (existing, not AASI):** [`ai_narratives.py`](../../attestra/ai_narratives.py) `Provider` protocol (`complete`), Ollama / OpenAI-compatible providers, off by default via `ATTESTRA_AI_NARRATIVES`, per-tenant kill via `ATTESTRA_AI_TENANTS_OFF`, `redact` / `finding_metadata`. DraftStore is disk JSON (not tenant-Mongo) — AASI memory must not copy that pattern.
- **Compliance:** [`compliance/`](../../attestra/compliance/) packs include `iso_42001_2023.yaml` and LLM Top-10 grouping in `owasp.py`; **no code path produces LLM findings today**.
- **Reports:** [`reports/render.py`](../../attestra/reports/render.py) renders technical/executive/compliance views then freezes by hash/signature.
- **Tests:** [`tests/`](../../tests/) holds the regression surface (~186 `test_*.py`); AASI tests belong here with `lat.md` specs.

### AASI extension rule (from this baseline)

Recommend-only agents → human/policy approval → `planner.plan_cases` / durable jobs → registered `ScannerAdapter` (digest-pinned container) → importer → existing validation classes → coverage ledger → audit + reports. New Mongo collections (e.g. `aasi_runs`, `aasi_decisions`) append via migration **`0005`+**; never a second planner, SDK, or validation enum.

## Git and backup files

Branch `attestra-asi-bundle` is the AASI V4.0 working branch. At Phase 0 start HEAD was `9bae08a` and the tree was clean against origin. The repository contains **413** historical `*.bak_*` editor backups (mostly under `attestra/`); **409** have a live twin. None were deleted. `.gitignore` now includes `*.bak_*` in addition to the existing `*.bak` rule. Full inventory: [`AASI_REPOSITORY_FINDINGS.md`](AASI_REPOSITORY_FINDINGS.md)#Git-baseline-and-bak-inventory.

## Python environment

Package metadata, local venv, and how `requirements.txt` relates to `pyproject.toml`.

| Item | Value |
|---|---|
| Package name | `attestra` (`pyproject.toml` `[project].name`) |
| Version | `1.0.0` |
| Requires Python | `>=3.11` (`tool.ruff.target-version` = `py311`; Dockerfile uses `python:3.12-slim`) |
| Local interpreter | `E:\GitHub\attestra\.venv\Scripts\python.exe` → **CPython 3.12.10** |
| `import attestra` | **OK** (`attestra\__init__.py`) |
| Entry point | `attestra = attestra.cli:main` |
| Dev extra | `[project.optional-dependencies].dev` = `pytest`, `httpx`, `httpx2`, `ruff` (also duplicated into core `dependencies`) |
| Other extras | `oidc`, `docs`, `s3`, `screenshots`, `temporal`, `observability` |

`requirements.txt` is kept in sync with `[project].dependencies` plus common `[dev]` tools; comments say prefer `pip install -e ".[dev]"` for development. Optional extras (`authlib`, `boto3`, `temporalio`, `weasyprint`, `docxtpl`, OpenTelemetry, playwright) are commented there.

Key packages observed in `.venv` (metadata versions): `fastapi 0.143.2`, `uvicorn 0.54.0`, `SQLAlchemy 2.1.4`, `pydantic 2.14.1`, `pymongo 4.19.0`, `pytest 9.1.1`, `httpx 0.28.1`, `cryptography 50.0.2`, `Jinja2 3.1.6`, `PyYAML 6.0.3`, `xhtml2pdf 0.2.27`, `Pillow 13.0.0`, `ruff 0.17.1`, `openpyxl 3.1.5`, `python-docx 1.2.0`. **Not installed** in this venv: `authlib`, `boto3`, `temporalio`, `weasyprint`, `docxtpl`. Note: several installed floors sit **below** current `pyproject.toml` minimums (e.g. SQLAlchemy `2.1.4` vs `>=2.1.8`, pydantic `2.14.1` vs `>=2.14.3`, pytest `9.1.1` vs `>=9.2.0`, xhtml2pdf `0.2.27` vs `>=0.2.28`) — refresh with `pip install -e ".[dev]"` before relying on the floors for AASI work.

## Lat validation

`lat` CLI is available. Semantic `lat search` works (API key configured). `lat locate` resolves Architecture, Local Docker Compose, Licence policy, Runner plane.

| Check | Result |
|---|---|
| `lat check` (after fixing unsupported wiki path links under Local Docker Compose) | **Pass** (warning only: "No init version recorded — run lat init") |
| Prior failures (recorded) | Eight broken `[[compose.yaml]]` / `[[Dockerfile]]` / `docker/scripts/*.sh` / `docker/scanner-digests.env` wiki links — current lat treats those extensions as non-resolvable file targets; converted to backtick paths. One leading-paragraph length overshoot (262 > 250) shortened. |
| Blueprint claim | Blueprint §2 said lat was not installed — **obsolete**; lat is installed and checkable on this machine. |

No AASI product behaviour was added to `lat.md/` (docs-only Phase 0). Local Docker Compose prose remains the implemented Compose snapshot.

## Docker deployment

Local stack and deploy artefacts; **no AI scanner images** yet.

### Compose services (`compose.yaml`)

| Service | Role |
|---|---|
| `mongo` | `mongo:7`, replica set `rs0`, published `127.0.0.1:27017` only |
| `mongo-init` | Oneshot `rs.initiate` via `docker/mongo-init/init-replica-set.js` |
| `api` | Build `Dockerfile`; `attestra init && attestra serve` on `127.0.0.1:8000` |
| `scanner-pull` | Oneshot digest validation + `docker pull` for ZAP / Nuclei / testssl / Naabu |
| `worker`, `worker-2` | `attestra worker`; Docker socket mount (dev DooD); waits for API + `scanner-pull` |

### Images and digests

- App image: multi-stage `Dockerfile` (`python:3.12-slim`), wheels the package, installs Docker **CLI only** for worker DooD; scanners are **not** baked in.
- Pinned web scanners in `docker/scanner-digests.env` (also compose defaults): `ATTESTRA_IMAGE_ZAP`, `ATTESTRA_IMAGE_NUCLEI`, `ATTESTRA_IMAGE_TESTSSL`, `ATTESTRA_IMAGE_NAABU`.
- `.env.example` documents additional pins (placeholders): Trivy, Semgrep, Gitleaks, Checkov, Subfinder, Dnsx, Httpx.
- **No** `ATTESTRA_IMAGE_GARAK` / Promptfoo / PyRIT / SafeLabs vars or compose services.

### Deploy /

Helm chart under `deploy/helm/attestra/` (api, worker, scanner-job, network policies, secrets, PVC); raw `deploy/k8s/` manifests; Keycloak realm example; loadtest; observability (Prometheus/Grafana/Promtail). Operator notes: `docs/DOCKER_DEPLOYMENT_GUIDE.md`, `deploy/README.md`.

## License policy

External tools stay out-of-process; copyleft services stay optional and off by default.

- [`docs/LICENSES.md`](../LICENSES.md) (reviewed 2026-10-14): table for ZAP, Nuclei, Trivy, Semgrep CE, Prowler, kube-bench, testssl.sh (GPL-2.0 process-only), Gitleaks, Checkov, naabu, OpenVAS/Greenbone (AGPL HTTP-only), MobSF (GPL HTTP-only). **Nmap / NPSL not used.**
- Rules: never import/vendor/copy GPL/AGPL/NPSL into Attestra images; copyleft network services off by default; every new tool needs a table row before merge.
- Runtime SBOM policy: [`attestra/supply_chain/license_policy.py`](../../attestra/supply_chain/license_policy.py) — opt-in via `ATTESTRA_LICENSE_POLICY`; default denies AGPL/SSPL/…, reviews GPL/LGPL/MPL/…, allows MIT/Apache/BSD/….
- AASI implication: Garak / Promptfoo / PyRIT / SafeLabs must run as digest-pinned containers with `AdapterMeta.licence` set; Shannon remains no-reuse per blueprint; do not pull copyleft AI runtimes into the core image.

## Architecture discrepancies

Claims that disagree with the runner / SDK (record only; product docs not rewritten in this track).

| Claim | Reality |
|---|---|
| [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) §Key design decisions: "**Import, don't execute.** Attestra never runs testing tools… keeps scanner licenses (AGPL, GPL, NPSL) out of the product." | Runner executes **14** adapters via `run_process` / `docker_run_argv` ([`base.py`](../../attestra/runner/scanners/base.py), [`sdk.py`](../../attestra/runner/scanners/sdk.py), [`registry.py`](../../attestra/runner/scanners/registry.py)). testssl is GPL-2.0 process/container; OpenVAS/MobSF remain HTTP-only off-by-default. |
| Same doc v0.1 table: "Orchestrator and runners — Not in scope for v0.1" | Scoped runner plane, durable jobs, Compose workers, and automated VAPT orchestrator exist. |
| Same doc data row: "SQLite or PostgreSQL" | Runtime persistence is **MongoDB only** (SQLAlchemy `Base` is schema for MongoSession). |
| [`lat.md/architecture.md`](../../lat.md/architecture.md) opening: "It does **not** execute scanners…" | Contradicts the same file's Runner plane / Local Docker Compose sections and the code. |

Reconciliation of `docs/ARCHITECTURE.md` / lat opening prose is still an open Phase 0 doc task (note only here).

## AI-related environment variables

`.env.example` has **no** `ATTESTRA_AI*` entries. Documented elsewhere:

| Variable | Default / notes | Source |
|---|---|---|
| `ATTESTRA_AI_NARRATIVES` | `off` | `docs/AI_NARRATIVES.md`, `ai_narratives.py` |
| `ATTESTRA_AI_PROVIDER` | `ollama` (or `openai`) | same |
| `ATTESTRA_AI_BASE_URL` | Ollama `http://localhost:11434` or OpenAI-compatible base | same |
| `ATTESTRA_AI_MODEL` | `llama3.1` | same |
| `ATTESTRA_AI_API_KEY` | fallback if secret `ai_api_key` unset | same |
| `ATTESTRA_AI_TENANTS_OFF` | comma-separated tenant ids | same |
| `ATTESTRA_AASI` | proposed `off` (not implemented) | blueprint §8 |
| `ATTESTRA_LICENSE_POLICY` | empty / opt-in SBOM policy | `.env.example` |

## Baseline tests

Full suite not executed end-to-end (too long for this track). Sample recorded honestly.

| Step | Command | Result |
|---|---|---|
| Collect-only | `.\.venv\Scripts\python.exe -m pytest tests/ -q --collect-only` | **1836 tests collected** in ~31s (1 `PytestCollectionWarning` for `TestContext`) |
| Targeted importers | `pytest tests/test_importers.py tests/test_phase7_importers.py -q --tb=no` | **1 failed, 33 passed, 1 skipped** in ~5s |
| Failure (not converted to pass) | `tests/test_importers.py::test_unsupported_tool_raises` | Expected `ValueError` matching `Unsupported format`; got `invalid XML: not well-formed (invalid token): line 1, column 0` |

Full regression remains deferred; treat the importer failure as a known baseline defect until fixed in a later track.
