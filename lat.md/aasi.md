# AASI (Attestra Agentic Security Intelligence)

AI/LLM security for Attestra: catalogues, adapters, recommend-only AASI core, reporting, env/deploy docs, Phase 12 security tests, and Phase 13 readiness (READY FOR STAGING, not production-ready).

## Phase 1 asset types

AI targets use the same authorization catalogues as other assets; nothing bypasses signed RoE checks.

[[attestra/models.py#ASSET_KINDS]] includes `ai_app` ("AI application / LLM endpoint"). [[attestra/models.py#TEST_TYPES]] adds `ai_llm` (OWASP LLM Top 10 (2025); imports garak, promptfoo, pyrit) and `ai_agent` (OWASP Agentic Applications; imports safelabs, promptfoo, garak). [[attestra/models.py#DEFAULT_TESTS]] for `ai_app` is `["ai_llm", "ai_agent"]`. [[attestra/models.py#DISPLAY_LABELS]] covers those three keys; existing compliance `ai_*` labels stay. Because [[attestra/models.py#VA_TEST_TYPES]] is `TEST_TYPES` minus [[attestra/models.py#PT_TEST_TYPES]], VA and VA+PT allow the AI tests while PT engagements do not. Phase note: `docs/ai_security/AASI_PHASE1_ASSET_TYPES.md`.

## Phase 1 AI-security importers

Offline parsers for Garak, Promptfoo, safelabs-eval, and PyRIT exports, registered in [[attestra/importers/__init__.py#PARSERS]].

[[attestra/importers/garak.py#parse]] emits findings only for detector hits. [[attestra/importers/promptfoo.py#parse]] emits findings only for failed security assertions. [[attestra/importers/safelabs.py#parse]] imports only `vulnerable`/`fail` heuristic hits as `tool="safelabs"`, labels taxonomy as SafeLabs ASI-source, and records uncertainty on `confidence` (`validation=potential`). [[attestra/importers/pyrit.py#parse]] imports successful attack results only (`tool="pyrit"`), preserving conversation/scenario ids and scores; empty or failed exports yield no findings. See [[import-pipeline#Garak importer]], [[import-pipeline#Promptfoo importer]], [[import-pipeline#SafeLabs importer]], [[import-pipeline#PyRIT importer]].

## Phase 2 SafeLabs adapter

Digest-pinned [[attestra/runner/scanners/safelabs.py#SafeLabsAdapter]] runs safelabs-eval against a DNS-pinned `ai_app` URL inside an isolated Python container.

[[attestra/runner/scanners/safelabs.py#SafeLabsAdapter]] sets `name`/`import_tool`/`image_key` to `safelabs`, `out_name` to `safelabs-report.json`, and `AdapterMeta` with `asset_kinds=("ai_app",)`, `safety_tier="T2"`, `network_egress="target"`, `licence="Apache-2.0"`, `image_ref_env="ATTESTRA_IMAGE_SAFELABS"`, `output_schema="safelabs-json"`. `docker_args` invoke `safelabs run … --output json`; with `report_on_stdout`, base scan persists JSON under [[attestra/runner/scanners/base.py#CONTAINER_OUT]]. The adapter never upgrades heuristic hits — import stays at potential via [[attestra/importers/safelabs.py#parse]]. Registry/digest wiring is parent-owned. Note: `docs/ai_security/AASI_PHASE2_SAFELABS_ADAPTER.md`.

## Phase 2 coverage and AI-tool validity

Ledger provenance and AI-tool failure honesty for AI coverage rows; scanner adapters are separate Phase 2 work.

[[attestra/automated_vapt/coverage/ledger.py#CoverageLedgerEntry]] adds ``origin`` (``catalogue`` \| ``aasi``) via [[attestra/automated_vapt/coverage/ledger.py#normalize_origin]]. Categories ``ai_llm`` / ``ai_agent`` are recognized by [[attestra/automated_vapt/coverage/ledger.py#is_ai_coverage_category]]. [[attestra/automated_vapt/coverage/ledger.py#merge_ledger]] dedupes on surface × risk (endpoint + category + asset + origin). [[attestra/automated_vapt/core/run_validity.py#ai_tool_outcome_to_status]] maps empty / refused / rate-limited / failed AI-tool outcomes to ``NOT_TESTED`` (never passed); ledger maps that to ``SKIPPED``. Doc: `docs/ai_security/AASI_PHASE2_COVERAGE.md`. Tests: [[tests#AASI Phase 2 coverage origin]].

## Phase 2 Garak adapter

Digest-pinned Garak REST probes via [[attestra/runner/scanners/garak.py#GarakAdapter]] against authorized `ai_app` URLs.

[[attestra/runner/scanners/garak.py#GarakAdapter]] declares `meta` (`ai_llm_probe`, `ai_app`, T2, `network_egress="target"`, Apache-2.0, `ATTESTRA_IMAGE_GARAK`, `garak-jsonl`). Docker is primary (`python -m garak`); local CLI is optional via `available()`. Fixed argv writes RestGenerator + run configs under `/out`, never `shell=True`. Scope uses `authorize_target` when provided. Empty/failed reports set `ScannerResult.error`. Design note: `docs/ai_security/AASI_PHASE2_GARAK_ADAPTER.md`. Registry and digest wiring are parent-owned.

## Phase 2 Promptfoo adapter

Digest-pinned Node container that runs `promptfoo eval` against an authorized `ai_app` URL with remote/cloud features off.

[[attestra/runner/scanners/promptfoo.py#PromptfooAdapter]] sets `name`/`import_tool`/`image_key` to `promptfoo`, `out_name` to `promptfoo-results.json`, and [[attestra/runner/scanners/sdk.py#AdapterMeta]] with `asset_kinds=("ai_app",)`, `safety_tier="T2"`, `network_egress="target"`, `licence="MIT"`, `image_ref_env="ATTESTRA_IMAGE_PROMPTFOO"`, `output_schema="promptfoo-results-json"`. [[attestra/runner/scanners/promptfoo.py#PromptfooAdapter#build_docker_argv]] writes a minimal `promptfooconfig.yaml`, pins the host via `--add-host`, and passes `PROMPTFOO_DISABLE_REMOTE_GENERATION` / `TELEMETRY` / `SHARING` / `UPDATE` as `docker run -e` through `extra_flags`. Judges stay local or tenant-approved; registry/digest wiring is parent INT. Note: `docs/ai_security/AASI_PHASE2_PROMPTFOO_ADAPTER.md`. Tests: [[tests#AASI Phase 2 Promptfoo adapter]].

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

Buildable isolated images for AI scanners; core Attestra stays free of those deps.

`docker/aasi/` holds Dockerfiles for Garak, SafeLabs, and PyRIT plus a thin `attestra_pyrit_worker`. Promptfoo uses official GHCR. Upstream GitHub projects are referenced; Attestra implements adapters/importers here. See `docs/ai_security/AASI_WORKER_IMAGES.md` and `docker/aasi/README.md`.

## Phase 5 PyRIT adapter

Digest-pinned multi-turn PyRIT worker for authorized `ai_app` URLs; never imports PyRIT into the core app.

[[attestra/runner/scanners/pyrit.py#PyRITAdapter]] sets `name`/`import_tool`/`image_key` to `pyrit`, `out_name` to `pyrit-results.json`, and [[attestra/runner/scanners/sdk.py#AdapterMeta]] with `asset_kinds=("ai_app",)`, `safety_tier="T2"`, `network_egress="target"`, `licence="MIT"`, `image_ref_env="ATTESTRA_IMAGE_PYRIT"`, `output_schema="pyrit-json"`. Allowlisted scenarios (`crescendo`, `pair`, `tree_of_attacks`, `red_teaming`, `many_shot`) map to fixed argv; unrestricted command opts are rejected. Third-party judge/adversarial egress stays off unless `tenant_authorize_external_judge=True`. Run config requests transcripts; [[attestra/runner/scanners/pyrit.py#PyRITAdapter#scan]] copies usage/cost into `ScannerResult.extra`. Registry line in [[attestra/runner/scanners/registry.py]]. Note: `docs/ai_security/AASI_PHASE5_PYRIT.md`. Tests: [[tests#AASI Phase 5 PyRIT adapter]].

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

Operator env templates for AASI/AI narratives with safe off-by-default values; digests stay placeholders until Phase 9.

`.env.example` documents `ATTESTRA_AI_*` narratives vars, [[attestra/config.py#AASI_ENABLED]] / `ATTESTRA_AASI_*` budgets with `ATTESTRA_AASI_REQUIRE_APPROVAL=on`, and commented `ATTESTRA_IMAGE_GARAK` / `PROMPTFOO` / `SAFELABS` pins (`REPLACE_AFTER_INSPECT`). `.env.production.example` mirrors production-safe defaults (`APP_ENV=production`, bypasses false, AASI/AI off, secret placeholders only). Inventory: `docs/ai_security/AASI_ENV_INVENTORY.md`. Draft defaults: `docs/ai_security/AASI_PHASE8_ENV_DRAFT.md`. Completion: `docs/ai_security/AASI_PHASE8_COMPLETION.md`.

## Phase 9 Docker and deployment

Docs and safe Compose extensions for AASI production Docker without enabling new required services.

`docs/ai_security/AASI_DOCKER_DEPLOYMENT.md` records app-image practices (scanners not baked in), AI scanner isolation, digest pins for Garak/Promptfoo/SafeLabs/PyRIT, no-privileged/`no-new-privileges`, Helm resource limits, validate/health commands, and rollback. `scripts/aasi/validate_aasi_env.py` checks [[attestra/config.py#AASI_ENABLED]] and AI image digest shape without printing secrets. Root `compose.yaml` keeps default `scanner-pull` for web tools only; an optional `aasi-scanner-pull` block stays fully commented. Completion: `docs/ai_security/AASI_PHASE9_COMPLETION.md`.

## Phase 12 security and regression tests

Offline suite covering AASI trust boundaries (prompt-injection redaction, scope/evidence gates, budgets, approval bypass, importers, digests, AI-off routes).

[[tests/aasi/test_aasi_security.py]] exercises eighteen scenarios against existing modules (orchestrator, evidence_gate, context/provider redaction, PyRIT/Garak adapters, importers, store idempotency, routes, `ai_tool_outcome_to_status`, `aasi_qa_issues`, `require_image_digest`). Docs: `docs/ai_security/AASI_PHASE12_COMPLETION.md`, `docs/ai_security/AASI_SECURITY_VALIDATION_REPORT.md`, `docs/ai_security/AASI_TEST_RESULTS.md`. Spec: [[tests#AASI Phase 12 security]].

## Phase 13 production readiness

Documentation-only readiness pack: final implementation report, production-readiness gates, deploy/rollback runbooks, and master feature matrix; no production deploy claimed.

Classification is **READY FOR STAGING** (also READY FOR PRODUCTION REVIEW) — **not** PRODUCTION READY — because AI scanner digests remain placeholders, no staging deploy was verified in the Phase 13 session, and no live vulnerable-AI lab e2e was run then. Operator docs: `docs/ai_security/AASI_FINAL_IMPLEMENTATION_REPORT.md`, `docs/ai_security/AASI_PRODUCTION_READINESS_REPORT.md`, `docs/ai_security/AASI_DEPLOYMENT_RUNBOOK.md`, `docs/ai_security/AASI_ROLLBACK_RUNBOOK.md`, `docs/ai_security/AASI_PHASE13_COMPLETION.md`. Status matrix: `docs/ai_security/AASI_IMPLEMENTATION_STATUS.md`. Honest gaps include placeholder digests, possible core `.venv` lag vs `pyproject.toml`, and Shannon AGPL-3.0 no-reuse.
