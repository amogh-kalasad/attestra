# AASI (Attestra Agentic Security Intelligence)

AI/LLM security for Attestra: catalogues, adapters, recommend-only AASI core, reporting, V5.1 native shared-env scanners, env/deploy docs, Phase 12 tests, and Phase 13 readiness (READY FOR STAGING, not production-ready).

## Phase 1 asset types

AI targets use the same authorization catalogues as other assets; nothing bypasses signed RoE checks.

[[attestra/models.py#ASSET_KINDS]] includes `ai_app` ("AI application / LLM endpoint"). [[attestra/models.py#TEST_TYPES]] adds `ai_llm` (OWASP LLM Top 10 (2025); imports garak, promptfoo, pyrit) and `ai_agent` (OWASP Agentic Applications; imports safelabs, promptfoo, garak). [[attestra/models.py#DEFAULT_TESTS]] for `ai_app` is `["ai_llm", "ai_agent"]`. [[attestra/models.py#DISPLAY_LABELS]] covers those three keys; existing compliance `ai_*` labels stay. Because [[attestra/models.py#VA_TEST_TYPES]] is `TEST_TYPES` minus [[attestra/models.py#PT_TEST_TYPES]], VA and VA+PT allow the AI tests while PT engagements do not. Phase note: `docs/ai_security/AASI_PHASE1_ASSET_TYPES.md`.

## Phase 1 AI-security importers

Offline parsers for Garak, Promptfoo, safelabs-eval, and PyRIT exports, registered in [[attestra/importers/__init__.py#PARSERS]].

[[attestra/importers/garak.py#parse]] emits findings only for detector hits. [[attestra/importers/promptfoo.py#parse]] emits findings only for failed security assertions. [[attestra/importers/safelabs.py#parse]] imports only `vulnerable`/`fail` heuristic hits as `tool="safelabs"`, labels taxonomy as SafeLabs ASI-source, and records uncertainty on `confidence` (`validation=potential`). [[attestra/importers/pyrit.py#parse]] imports successful attack results only (`tool="pyrit"`), preserving conversation/scenario ids and scores; empty or failed exports yield no findings. See [[import-pipeline#Garak importer]], [[import-pipeline#Promptfoo importer]], [[import-pipeline#SafeLabs importer]], [[import-pipeline#PyRIT importer]].

## Phase 2 SafeLabs adapter

Native shared-env [[attestra/runner/scanners/safelabs.py#SafeLabsAdapter]] runs safelabs-eval against a DNS-pinned `ai_app` URL (AASI V5.1; no Docker).

[[attestra/runner/scanners/safelabs.py#SafeLabsAdapter]] sets `name`/`import_tool` to `safelabs`, `image_key=""`, `allows_docker=False`, `out_name` to `safelabs-report.json`, and `AdapterMeta` with `asset_kinds=("ai_app",)`, `safety_tier="T2"`, `network_egress="target"`, `licence="Apache-2.0"`, empty `image_ref_env`, `output_schema="safelabs-json"`. `build_argv` launches shared `python -m safelabs` (or venv `safelabs` script) with `run … --output json`; with `report_on_stdout`, base scan persists JSON under the host out dir. The adapter never upgrades heuristic hits — import stays at potential via [[attestra/importers/safelabs.py#parse]]. Notes: `docs/ai_security/AASI_V51_GARAK_SAFELABS_NATIVE.md`, `docs/ai_security/AASI_PHASE2_SAFELABS_ADAPTER.md`.

## Phase 2 coverage and AI-tool validity

Ledger provenance and AI-tool failure honesty for AI coverage rows; scanner adapters are separate Phase 2 work.

[[attestra/automated_vapt/coverage/ledger.py#CoverageLedgerEntry]] adds ``origin`` (``catalogue`` \| ``aasi``) via [[attestra/automated_vapt/coverage/ledger.py#normalize_origin]]. Categories ``ai_llm`` / ``ai_agent`` are recognized by [[attestra/automated_vapt/coverage/ledger.py#is_ai_coverage_category]]. [[attestra/automated_vapt/coverage/ledger.py#merge_ledger]] dedupes on surface × risk (endpoint + category + asset + origin). [[attestra/automated_vapt/core/run_validity.py#ai_tool_outcome_to_status]] maps empty / refused / rate-limited / failed AI-tool outcomes to ``NOT_TESTED`` (never passed); ledger maps that to ``SKIPPED``. Doc: `docs/ai_security/AASI_PHASE2_COVERAGE.md`. Tests: [[tests#AASI Phase 2 coverage origin]].

## Phase 2 Garak adapter

Native shared-env Garak REST probes via [[attestra/runner/scanners/garak.py#GarakAdapter]] against authorized `ai_app` URLs (AASI V5.1; no Docker).

[[attestra/runner/scanners/garak.py#GarakAdapter]] declares `image_key=""`, `allows_docker=False`, and `meta` (`ai_llm_probe`, `ai_app`, T2, `network_egress="target"`, Apache-2.0, empty `image_ref_env`, `garak-jsonl`). Launcher is shared `python -m garak` via `_shared_python()` / `scanner_runtime`. Fixed argv writes RestGenerator + run configs under the host out dir, never `shell=True`. Scope uses `authorize_target` when provided. Empty/failed reports set `ScannerResult.error`. Shared-env openai policy: REST only; OpenAI generator unsupported; Anthropic/LiteLLM packages present ([[aasi#V5.1 openai shared-env policy]]). Design notes: `docs/ai_security/AASI_V51_GARAK_SAFELABS_NATIVE.md`, `docs/ai_security/AASI_PHASE2_GARAK_ADAPTER.md`.

## Phase 2 Promptfoo adapter

Native shared-env Promptfoo (`allows_docker=False`) that runs `promptfoo eval` against an authorized `ai_app` URL with remote/cloud features off.

[[attestra/runner/scanners/promptfoo.py#PromptfooAdapter]] sets `name`/`import_tool` to `promptfoo`, empty `image_key`, `allows_docker=False`, `out_name` to `promptfoo-results.json`, and [[attestra/runner/scanners/sdk.py#AdapterMeta]] with `asset_kinds=("ai_app",)`, `safety_tier="T2"`, `network_egress="target"`, `licence="MIT"`, empty `image_ref_env`, `output_schema="promptfoo-results-json"`. [[attestra/runner/scanners/promptfoo.py#resolve_promptfoo_argv_prefix]] / [[attestra/runner/scanners/promptfoo.py#PromptfooAdapter#build_argv]] run from `ATTESTRA_SHARED_ENV_ROOT` (npm + Node under that root), write a minimal `promptfooconfig.yaml`, apply [[attestra/runner/scanners/promptfoo.py#privacy_env]], and never use Docker. Judges stay local or tenant-approved. Note: `docs/ai_security/AASI_V51_PROMPTFOO_NATIVE.md`, `docs/ai_security/AASI_V51_NO_DOCKER.md`. Tests: [[tests#AASI Phase 2 Promptfoo adapter]].

## Phase 3 provider and context

Thin narratives-provider wrapper and bounded trust-labelled context for recommend-only runs.

[[attestra/aasi/provider.py#build_provider]] reuses [[attestra/ai_narratives.py#provider_from_env]] / [[attestra/ai_narratives.py#get_provider]] and raises [[attestra/aasi/provider.py#AasiProviderDisabled]] when `ATTESTRA_AASI`, `ATTESTRA_AI_NARRATIVES`, or `ATTESTRA_AI_TENANTS_OFF` blocks AI (no network). [[attestra/aasi/provider.py#AasiProvider#complete_json]] redacts outbound prompts, retries with [[attestra/config.py#AASI_RETRY_LIMIT]], and validates required JSON keys. [[attestra/aasi/context.py#build_context_packet]] builds a serializable [[attestra/aasi/context.py#ContextPacket]] (ai_app preferred, redacted finding refs, coverage gaps, observation ids, registry + AI adapter test ids) and never includes evidence bodies, credentials, or source code. Note: `docs/ai_security/AASI_PHASE3_PROVIDER_CONTEXT.md`. Tests: [[tests#AASI Phase 3 provider]], [[tests#AASI Phase 3 context]].

## Phase 3 contracts and budget

Typed recommend-only decision contracts and hard run ceilings used by roles and the orchestrator.

[[attestra/aasi/contracts.py#Hypothesis]], [[attestra/aasi/contracts.py#TestRecommendation]], and [[attestra/aasi/contracts.py#Conclusion]] are frozen dataclasses with `validate` / `from_mapping`. Intrusive status is computed only via [[attestra/aasi/contracts.py#compute_intrusive]] from [[attestra/automated_vapt/core/intrusive_policy.py#INTRUSIVE_TEST_IDS]] — never from model output. Claiming conclusions require citations; [[attestra/aasi/contracts.py#Conclusion#validate_against_known]] rejects unknown evidence IDs. [[attestra/aasi/budget.py#Budget]] enforces [[attestra/config.py#AASI_MAX_ITERATIONS]] and sibling `AASI_MAX_*` via `check` / `consume` / `remaining`, raising [[attestra/aasi/budget.py#BudgetExceeded]]. Note: `docs/ai_security/AASI_PHASE3_CONTRACTS.md`.

## Phase 3 roles

Five logical roles on one runtime (not five agent processes); recommend-only typed outputs.

[[attestra/aasi/roles.py#run_strategist]], [[attestra/aasi/roles.py#run_hypothesis]], [[attestra/aasi/roles.py#run_ai_security]], [[attestra/aasi/roles.py#run_evidence_reviewer]], and [[attestra/aasi/roles.py#run_quality_reviewer]] take a ContextPacket-like dict plus optional prior outputs. When a provider with `complete_json` is injected it is used; with `provider=None`, deterministic stubs keep tests offline (empty hypotheses without observations; catalogue-gap AI recommendations). Role DTOs keep Phase-3 prompt field names (`test_id` / `cites`); shared [[attestra/aasi/contracts.py]] shapes may differ until parent unification. Note: `docs/ai_security/AASI_PHASE3_ORCHESTRATOR.md`. Tests: [[tests#AASI Phase 3 roles]].

## Phase 3 orchestrator

Bounded recommend-only loop: context → roles → validate → approval → planner payloads (no scanners).

[[attestra/aasi/orchestrator.py#AasiOrchestrator]] builds context via an injectable hook, runs [[attestra/aasi/roles.py#ROLE_SEQUENCE]] under budget and cancel Event checks, and validates recommendations against [[attestra/aasi/orchestrator.py#registered_test_ids]] (test_registry ∪ garak/promptfoo/safelabs/pyrit). Unauthorized assets and scope-escalation fields are rejected; AI adapters / intrusive IDs stay pending until [[attestra/aasi/orchestrator.py#AasiOrchestrator#approve]] (model approval claims ignored). [[attestra/aasi/orchestrator.py#AasiOrchestrator#planner_payloads]] returns Attestra-planner inputs only. Decisions persist via an injectable store (`MemoryStore` in tests). When [[attestra/aasi/__init__.py#enabled]] is false, `run` returns `DISABLED` or raises [[attestra/aasi/orchestrator.py#AasiDisabledError]]. Note: `docs/ai_security/AASI_PHASE3_ORCHESTRATOR.md`. Tests: [[tests#AASI Phase 3 orchestrator]].

## Phase 3 FastAPI routes

Recommend-only HTTP API under `/api/aasi`. Parent mounts [[attestra/aasi/routes.py#api_router]]; this package does not edit `attestra/api.py`.

[[attestra/aasi/routes.py#api_router]] exposes `GET /status`, start/get run, list decisions, human recommendation approve, and cancel. When [[attestra/aasi/__init__.py#enabled]] is false, status returns `{enabled: false}` and other routes return 404 (discovery/AI-narratives norm). Mutate requires `engagement.write` (tester/lead/admin); `engagement.read` may GET. Approve and cancel call `audit.record`. Note: `docs/ai_security/AASI_PHASE3_ROUTES.md`. Tests: [[tests#AASI Phase 3 routes]].

## Phase 3 Mongo persistence

Tenant-scoped Mongo store for AASI runs and append-only decisions (`aasi_runs` / `aasi_decisions`).

[[attestra/aasi/store.py#AasiStore]] creates runs unique per `(tenant_id, idempotency_key)` (returns existing on conflict), appends decisions without updating prior rows, and always filters `get_run` / `list_decisions` by `tenant_id`. Documents carry `schema_version`, optional `audit_hash` (canonical JSON SHA-256), and soft `retain_until`. [[attestra/aasi/store.py#sanitize_payload]] strips CoT-like keys so only structured summaries are stored. Migration `0005_aasi_collections` owns indexes. Doc: `docs/ai_security/AASI_PHASE3_STORE.md`. Tests: [[tests#AASI Phase 3 store]].

## Phase 4 evidence intelligence

Evidence-ID gate for conclusions, run-state task tree helpers, and recommendation ranking for planner handoff.

[[attestra/aasi/evidence_gate.py#assert_citations_valid]] rejects citations that are missing, cross-tenant/engagement, inaccessible, deleted, or expired via an injectable `lookup_fn` (raises [[attestra/aasi/evidence_gate.py#EvidenceGateError]] with `reason`). [[attestra/aasi/orchestrator.py#AasiOrchestrator#persist_conclusion]] applies the gate before recording a conclusion decision. [[attestra/aasi/task_tree.py]] attaches parent/child tasks (`dependencies`, `result_refs`, `retry_count`, completion summary propagation) to `run["tasks"]` — not a separate agent graph. [[attestra/aasi/prioritize.py#prioritize_recommendations]] ranks candidates (coverage gap > confirmed finding adjacency > default); the planner still orders execution. Evidence/quality reviewers note unknown or citation-less claims. Doc: `docs/ai_security/AASI_PHASE4_EVIDENCE.md`. Tests: [[tests#AASI Phase 4 evidence gate]], [[tests#AASI Phase 4 task tree]], [[tests#AASI Phase 4 prioritize]].

## AASI worker image recipes

V4 Docker AI image recipes are **deprecated for execution** under V5.1; see [[aasi#V5.1 native scanners]].

`docker/aasi/` still holds historical Dockerfiles for Garak, SafeLabs, and PyRIT plus a thin `attestra_pyrit_worker`. They are not the V5.1 runtime path. Policy: `docs/ai_security/AASI_WORKER_IMAGES.md`; deprecation notice: `docker/aasi/README.md`.

## Phase 5 PyRIT adapter

Native shared-env PyRIT runner for authorized `ai_app` URLs (AASI V5.1); Docker worker path is deprecated.

[[attestra/runner/scanners/pyrit.py#PyRITAdapter]] sets `name`/`import_tool` to `pyrit`, `image_key=""`, `allows_docker=False`, `out_name` to `pyrit-results.json`, and [[attestra/runner/scanners/sdk.py#AdapterMeta]] with `asset_kinds=("ai_app",)`, `safety_tier="T2"`, `network_egress="target"`, `licence="MIT"`, empty `image_ref_env`, `output_schema="pyrit-json"`. Execution is `python -m attestra.aasi.pyrit_native` via [[attestra/aasi/pyrit_native.py#run_scenario]] (real `pyrit` import, `HTTPTarget`, `PromptSendingAttack` / `ManyShotJailbreakAttack`). Allowlisted scenarios only; unrestricted command opts rejected. Third-party judge egress off unless `tenant_authorize_external_judge=True`. Doc: `docs/ai_security/AASI_V51_PYRIT_NATIVE.md`. Tests: [[tests#AASI Phase 5 PyRIT adapter]].

## Phase 6 attack-path graph

Mongo-native attack-path nodes/edges with provenance labels; risk is never raised from inferred edge count alone.

[[attestra/aasi/graph.py#AasiGraphStore]] upserts nodes and inserts edges on `aasi_graph_nodes` / `aasi_graph_edges` (migration `0006_aasi_graph`). [[attestra/aasi/graph.py#PROVENANCE_LABELS]] are `observed` | `inferred` | `demonstrated`. Every edge stores `evidence_citations`, `source`, and timestamps; [[attestra/aasi/graph.py#AasiGraphStore#add_edge]] requires `proof_refs` for `demonstrated`. [[attestra/aasi/graph.py#aggregate_path_risk]] / [[attestra/aasi/graph.py#risk_delta_for_edge]] exclude inferred edges from `risk_delta`. Doc: `docs/ai_security/AASI_PHASE6_GRAPH_REMEDIATION.md`. Tests: [[tests#AASI Phase 6 attack-path graph]].

## Phase 6 GitHub remediation PR proposals

Draft-only remediation pull-request proposals, separate from Issues; customer approval and retest_passed closure.

[[attestra/integrations/github_pr.py#GitHubPRProposalClient]] proposes local drafts linked to a finding, requires [[attestra/integrations/github_pr.py#GitHubPRProposalClient#approve]], then opens GitHub PRs only with `draft: true` via [[attestra/integrations/github_pr.py#GitHubPRProposalClient#create_draft_pr]]. No push/merge APIs. Tenant `authorizer` gates use; audit history is appended on each transition. [[attestra/integrations/github_pr.py#GitHubPRProposalClient#close_on_retest_passed]] accepts only `finding_status="retest_passed"`. Issues remain in [[attestra/integrations/github.py#GitHubIssuesClient]]. Doc: `docs/ai_security/AASI_PHASE6_GRAPH_REMEDIATION.md`. Tests: [[tests#AASI Phase 6 GitHub PR proposals]].

## Phase 7 reporting sections

AI-security executive / technical / traceability / coverage payloads inside the existing report renderer; hashing and four-eyes unchanged.

[[attestra/reports/aasi_sections.py#aasi_report_context]] builds `aasi` context dicts; [[attestra/reports/render.py#_aasi_report_context]] injects them when AASI is on and runs exist, else [[attestra/reports/aasi_sections.py#empty_aasi_payload]]. [[attestra/reports/aasi_sections.py#build_coverage_matrix]] uses [[attestra/reports/aasi_sections.py#COVERAGE_STATUSES]] only and never encodes silence as pass. [[attestra/reports/aasi_sections.py#aasi_qa_issues]] flags invalid evidence refs, unreproduced confirmed, and cross-tenant rows without bypassing sign-off. Spec/docs under `docs/ai_security/AASI_REPORTING_*.md` and `AASI_COMPLIANCE_COVERAGE.md`. See [[reports#AASI reporting sections (Phase 7)]]. Tests: [[tests#AASI Phase 7 reporting]].

## Phase 8 environment templates

Operator env templates for AASI/AI narratives with safe off-by-default values; V5.1 adds shared-env root and deprecates AI image pins.

`.env.example` documents `ATTESTRA_AI_*` narratives vars, [[attestra/config.py#AASI_ENABLED]] / `ATTESTRA_AASI_*` budgets with `ATTESTRA_AASI_REQUIRE_APPROVAL=on`, `ATTESTRA_SHARED_ENV_ROOT`, and deprecated commented `ATTESTRA_IMAGE_GARAK` / `PROMPTFOO` / `SAFELABS` / `PYRIT` (unused for AI execution under V5.1). `.env.production.example` mirrors production-safe defaults (`APP_ENV=production`, bypasses false, AASI/AI off, secret placeholders only). Inventory: `docs/ai_security/AASI_ENV_INVENTORY.md`. Draft defaults: `docs/ai_security/AASI_PHASE8_ENV_DRAFT.md`. Completion: `docs/ai_security/AASI_PHASE8_COMPLETION.md`.

## Phase 9 Docker and deployment

Docs and safe Compose extensions for the Attestra app stack; V5.1 moves AI scanner enablement to shared-env install, not digest pins.

`docs/ai_security/AASI_DOCKER_DEPLOYMENT.md` records app-image practices. V5.1 operator path is `docs/ai_security/AASI_DEPLOYMENT_RUNBOOK.md` (install shared env under `ATTESTRA_SHARED_ENV_ROOT`). `scripts/aasi/validate_aasi_env.py` checks [[attestra/config.py#AASI_ENABLED]] without printing secrets; AI `--require-ai-images` is not a V5.1 readiness gate. Root `compose.yaml` keeps default `scanner-pull` for **web** tools only. Completion note: `docs/ai_security/AASI_PHASE9_COMPLETION.md` (V4 era); tracker: `docs/ai_security/AASI_V51_STATUS.md`.

## Phase 12 security and regression tests

Offline suite covering AASI trust boundaries (prompt-injection redaction, scope/evidence gates, budgets, approval bypass, importers, digests, AI-off routes).

[[tests/aasi/test_aasi_security.py]] exercises eighteen scenarios against existing modules (orchestrator, evidence_gate, context/provider redaction, PyRIT/Garak adapters, importers, store idempotency, routes, `ai_tool_outcome_to_status`, `aasi_qa_issues`, `require_image_digest`). Docs: `docs/ai_security/AASI_PHASE12_COMPLETION.md`, `docs/ai_security/AASI_SECURITY_VALIDATION_REPORT.md`, `docs/ai_security/AASI_TEST_RESULTS.md`. Spec: [[tests#AASI Phase 12 security]].

## Phase 13 production readiness

Documentation-only readiness pack: final implementation report, production-readiness gates, deploy/rollback runbooks, and master feature matrix; no production deploy claimed.

Classification is **READY FOR STAGING** (also READY FOR PRODUCTION REVIEW) — **not** PRODUCTION READY — for recommend-only AASI core from the Phase 13 session. V5.1 native AI scanners are a separate **IN PROGRESS** track and must not claim production AI digests. Operator docs: `docs/ai_security/AASI_FINAL_IMPLEMENTATION_REPORT.md`, `docs/ai_security/AASI_PRODUCTION_READINESS_REPORT.md`, `docs/ai_security/AASI_DEPLOYMENT_RUNBOOK.md`, `docs/ai_security/AASI_ROLLBACK_RUNBOOK.md`, `docs/ai_security/AASI_PHASE13_COMPLETION.md`, `docs/ai_security/AASI_V51_STATUS.md`. Status matrix: `docs/ai_security/AASI_IMPLEMENTATION_STATUS.md`. Honest gaps include unfinished native shared-env install/adapters, possible core `.venv` lag vs `pyproject.toml`, and Shannon AGPL-3.0 no-reuse.

## V5.1 native scanners

V5.1 runs Garak, Promptfoo, SafeLabs, and PyRIT natively under one `ATTESTRA_SHARED_ENV_ROOT`; Docker AI digests are superseded and must not be claimed as production pins.

Prompt 5.1 requires exactly one shared Python venv (Attestra + Garak + SafeLabs + PyRIT) and Node/npm under the same root for Promptfoo — no per-scanner venvs, no AI Docker pulls/execution. Track status is **IN PROGRESS** (`docs/ai_security/AASI_V51_STATUS.md`, `docs/ai_security/AASI_IMPLEMENTATION_STATUS.md`). Env templates document `ATTESTRA_SHARED_ENV_ROOT` and deprecate `ATTESTRA_IMAGE_GARAK` / `PROMPTFOO` / `SAFELABS` / `PYRIT` for AI execution. Operator install/verify steps: `docs/ai_security/AASI_DEPLOYMENT_RUNBOOK.md`. Policy supersession: `docs/ai_security/AASI_WORKER_IMAGES.md`. `docker/aasi/` is deprecated for AI execution. Web scanner digests remain unchanged. Directive archive: `docs/ai_security/AASI_CLI_PROMPT_5.1.md`.

## V5.1 native-only AI scanners (no Docker)

AI adapters opt out of Docker via `allows_docker=False`; shared env installs replace container images for Garak/Promptfoo/SafeLabs/PyRIT.

[[attestra/runner/scanners/base.py#ScannerAdapter]] adds `allows_docker` (default true). [[attestra/runner/scanners/base.py#ScannerAdapter#uses_docker]] returns false when that flag is false, even with a digest-pinned image and Docker present. [[attestra/runner/scanners/base.py#ScannerAdapter#unavailable_reason]] then points at [[attestra/config.py#SHARED_ENV_ROOT]] / [[attestra/config.py#shared_env_root]] (`ATTESTRA_SHARED_ENV_ROOT`, empty → `.attestra-runtime`) and never suggests Docker. Placeholder `garak`/`promptfoo`/`safelabs`/`pyrit` keys in `_PLACEHOLDER_IMAGES` may remain but are unused by AI adapters at runtime. Non-AI scanners keep Docker images. Doc: `docs/ai_security/AASI_V51_NO_DOCKER.md`. Tests: [[tests#AASI V5.1 no Docker for AI adapters]].

## V5.1 shared scanner runtime

One shared install root for native AI scanners: a single Python venv plus Node/npm for Promptfoo under `ATTESTRA_SHARED_ENV_ROOT`.

[[attestra/scanner_runtime/environment.py#resolve_shared_env]] / [[attestra/scanner_runtime/environment.py#SharedEnvironment]] resolve the root (default `<repo>/.attestra-runtime`) and layout (`venv`, `tools/node`, `npm`, `manifests`, `logs`, `cache`, `tmp`). [[attestra/scanner_runtime/environment.py#require_python]], [[attestra/scanner_runtime/environment.py#require_promptfoo]], and [[attestra/scanner_runtime/environment.py#shared_python]] expose Windows-aware binaries; [[attestra/scanner_runtime/environment.py#reject_extra_venvs]] forbids per-scanner venvs. [[attestra/scanner_runtime/versions.py#SUPPORTED]] pins garak `0.17.1`, safelabs-eval `0.12.0`, pyrit `1.2.1`, promptfoo `~0.118.x`, node `20.x`. [[attestra/scanner_runtime/dependency_check.py#check_python_package]] queries shared-venv `importlib.metadata`; [[attestra/scanner_runtime/health.py#health_report]] covers all four scanners with `docker: false`. [[attestra/scanner_runtime/process.py#run_with_shared_env]] wraps [[attestra/runner/scanners/base.py#run_process]] with sanitized PATH. [[attestra/scanner_runtime/manifest.py#write_manifest]] / [[attestra/scanner_runtime/manifest.py#read_manifest]] store JSON under `manifests/`. Optional `pyproject.toml` extra `ai-scanners` lists SafeLabs, PyRIT, `openai>=3,<4`, anthropic, and litellm (Garak is staged by the installer with `--no-deps`); `requirements.txt` mirrors those as comments (Promptfoo is npm-only via `runtime/npm/package.json` pin `promptfoo@0.118.17`). [[scripts/aasi/install_shared_env.py]] provisions the root and installs into the single `venv/` (never docker-pulls / never a second venv); [[scripts/aasi/install_promptfoo_npm.py]] is the Promptfoo-only wrapper. Docs: `docs/ai_security/AASI_V51_SHARED_ENV.md`, `docs/ai_security/AASI_V51_DEPENDENCIES.md`, `docs/ai_security/AASI_V51_INSTALL.md`. Complements [[aasi#V5.1 native-only AI scanners (no Docker)]] and [[aasi#V5.1 openai shared-env policy]].

## V5.1 openai shared-env policy

Single shared venv prefers openai 3.x for PyRIT; Garak installs with `--no-deps` and runs REST/Anthropic/LiteLLM only.

Upstream `garak==0.17.1` wants `openai>=2,<3` while `pyrit==1.2.1` wants `openai>=3,<4`. [[scripts/aasi/install_shared_env.py#pip_install_ai_scanners]] stages core + joint pins (SafeLabs, PyRIT, openai 3.x, anthropic, litellm), then `garak==0.17.1 --no-deps`, then Garak METADATA deps via [[scripts/aasi/install_shared_env.py#filter_garak_requirements]] (openai and extras dropped), re-pins openai 3.x, and verifies imports. A `pip check` line that only complains about garak↔openai is an accepted WARN. [[attestra/runner/scanners/garak.py#GarakAdapter]] keeps `--target_type rest`; Garak's native OpenAI generator is unsupported in this env. No second venv. Docs: `docs/ai_security/AASI_V51_DEPENDENCIES.md`. Tests: [[tests#AASI V5.1 openai shared-env policy]].

## V5.1 native target-bound egress

Helpers that re-check the DNS-pinned target and strip host secrets from scanner subprocess env for native shared-venv runs.

[[attestra/scanner_runtime/egress.py#assert_target_egress_allowed]] refuses a missing pin and revalidates `pinned.ip` via [[attestra/runner/authorization.py#validate_resolved_ips]] (metadata/CGNAT stay blocked). [[attestra/scanner_runtime/egress.py#scanner_process_env]] keeps PATH/system essentials, drops AWS/Mongo/`ATTESTRA_SESSION*` secrets, and sets `ATTESTRA_SCANNER_JOB=1`. Shared venv is not isolation; `HTTP_PROXY` alone is insufficient — fail closed without a valid pin. Doc: `docs/ai_security/AASI_V51_NATIVE_EGRESS.md`. Tests: [[tests#AASI V5.1 native egress]]. Lab note: when asset notes include `allow_private`, [[attestra/runner/authorization.py#validate_resolved_ips]] may allow loopback so the mock LLM on `127.0.0.1` can be scanned.

## V5.1 live Anthive + mock LLM E2E

Lab verification that shared-env openai policy and native AI adapters run, plus webcheck against the Anthive marketing site.

`https://www.anthive.tech/` is treated as `web_app` (HTML marketing); AI scanners target [[scripts/aasi/mock_llm_target.py]] (`ai_app` + `allow_private`). Live eng `#1`: SafeLabs `#10` and PyRIT `#12` `done` against the mock; webcheck `#13` `done` with 10 imported anthive findings; Garak `#11` REST RestGenerator completed (exit 0, digest) but Attestra marked `failed` on strict JSONL import ([[attestra/importers/garak.py#_parse_records]]); Promptfoo skipped (`--skip-node`); ZAP not run (Docker daemon down). Results doc: `docs/ai_security/AASI_V51_E2E_ANTHIVE_VERIFICATION.md`. Tracker: `docs/ai_security/AASI_V51_STATUS.md`. Policy: [[aasi#V5.1 openai shared-env policy]].
