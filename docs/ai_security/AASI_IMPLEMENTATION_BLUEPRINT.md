# Attestra Agentic Security Intelligence (AASI) — Implementation Blueprint

Status: **Proposal, approved for Phase 0 only.** No production code has been changed.
Verified against: the `attestra-code/` working tree and ten upstream GitHub repositories, inspected on 2026-11-23 (commit SHAs in §4).
Supersedes: the GPT "Master Engineering Directive" (v1), the "MASTER CLI AGENT INSTRUCTION v3.0" and the "Final repository adoption decisions" table. Where this document disagrees with them, the reason is given and backed by a source reference.

Precedence when implementing: **actual source code > `AGENTS.md` > this document > GPT directives.** Record any discrepancy you find instead of silently working around it.

This file lives in `docs/` on purpose. Per `AGENTS.md`, `lat.md/` describes only implemented behaviour. Each phase below must add its implemented parts to `lat.md/` and pass `lat check`.

---

## 1. Decision summary

1. **Attestra stays the system of record.** It owns authorization, scope, test planning, scanner execution, findings, evidence, validation, compliance and reports. AASI adds reasoning, never a second copy of any of these.
2. **Agents recommend; Attestra decides and executes.** An agent can only output registered test IDs. The existing planner decides run, skip or defer. The existing orchestrator and runner execute. Importers normalize the results, and the existing validation classes classify them. A human confirms.
3. **Build AI-security testing before the agent core** (this reverses GPT's order). Garak and Promptfoo importers fill a gap customers can see today, carry low risk, and give the agent core a real catalogue of AI tests to recommend from. Building the agent first would give it nothing new to choose.
4. **No external agent runtime gets execution rights.** Strix, PentAGI, AutoPentest AI, RedAmon and Shannon are used as design references. Their runtimes give the LLM shell, filesystem or MCP access (verified in §4), which breaks Attestra's registered-tools-only rule.
5. **AI frameworks run as digest-pinned containers through the existing adapter SDK,** not as dependencies of the core app. This keeps PyRIT's 56 dependencies, Garak's `torch` and Promptfoo's Node 22 runtime out of the Attestra Python environment.

### Final adoption decisions (changes from GPT's table are marked)

| Repository | GPT decision | **Final decision** | How it enters Attestra |
|---|---|---|---|
| Garak | Adopt | **Adopt, first** | Importer, then runner adapter (container) |
| Promptfoo | Adopt | **Adopt, first** | Importer, then runner adapter (container, remote generation off) |
| SafeLabs Eval | Adopt selectively | **Adopt selectively** | Importer and adapter. Results never above `potential` |
| PyRIT | Adopt | **Adopt later, isolated worker** ▲ | Container worker for multi-turn attacks, plus an importer |
| Strix | Primary orchestration | **Primary *design reference*, no runtime** ▲ | Three patterns re-implemented natively (§4.1) |
| AutoPentest AI | Design reference | Design reference | Task tree, endpoint priority, tool-output verification. WAF evasion excluded |
| PentAGI | Design reference | Design reference (**EULA restrictions**) ▲ | Ideas only |
| RedAmon | Selective reference | Selective reference | Graph schema ideas implemented on MongoDB. Bundled-tool licences rule out reuse |
| AgentEval | Design reference | Design reference | Tool-call assertions written as pytest |
| Shannon | No code reuse | **No code reuse (denied by Attestra licence policy)** | The "no exploit, no report" rule, expressed with existing validation classes |

---

## 2. Verified Attestra baseline — integration points

Every row has been checked in the source. Use these as the only extension points.

| Concern | Existing implementation (verified) | AASI rule |
|---|---|---|
| Persistence | MongoDB only. [`attestra/db.py`](../../attestra/db.py) keeps SQLAlchemy `Base` as a schema; `MongoSession` writes to Mongo; there is no SQL engine | New data goes in Mongo collections only |
| Collections | [`persistence/mongo/collections.py`](../../attestra/persistence/mongo/collections.py) (around 70 collections, including `findings`, `finding_observations`, `evidence`, `automated_test_executions`, `jobs`, `audit_events`) | Reuse first. New: `aasi_runs`, `aasi_decisions` (§6) |
| Migrations | Registered **in code**: list `MIGRATIONS` in [`persistence/mongo/migrations/__init__.py`](../../attestra/persistence/mongo/migrations/__init__.py), entries `0001_mongo_baseline` … `0004_upgrade_int_indexes`, applied by `apply_pending()` | Append the next entry to that list after checking the current last ID. There are no migration *files* and no Alembic |
| Tenant isolation | `db.tenant_scope`, [`persistence/mongo/tenant.py`](../../attestra/persistence/mongo/tenant.py) `effective_scope`, `TenantAccessDenied` | Every AASI read and write goes through it |
| Scope / authorization | [`runner/authorization.py`](../../attestra/runner/authorization.py) `scope_for_engagement`, `authorize_target`, `validate_url_target`, `validate_resolved_ips`; [`automated_vapt/core/authorization_guard.py`](../../attestra/automated_vapt/core/authorization_guard.py) `assert_engagement_ready_for_case`, `load_asset` | Checked again at execution time, never by the LLM |
| Authorizable test types | `TEST_TYPES` and `ASSET_KINDS` in [`models.py`](../../attestra/models.py) (lines 70–92). **There is no AI asset kind and no AI test type** | Add `ai_app` and `ai_llm` / `ai_agent` (Phase 1) |
| Intrusive policy | [`intrusive_policy.py`](../../attestra/automated_vapt/core/intrusive_policy.py): env flag, profile, policy, environment allowlist, production forbidden | AI tests that trigger target tool calls are classed intrusive |
| Test catalogue | [`test_registry.py`](../../attestra/automated_vapt/core/test_registry.py): T01–T22, INJ, XSS, XSSDOM, XSSSTORE, FILE, SSRF, UPLOAD, BIZ, ROLEDIFF, SESSION, SESSLIFE, OIDCMETA | Agents may only output IDs from here plus registered adapter capabilities |
| Planner | [`planner.py`](../../attestra/automated_vapt/core/planner.py) `PlanFacts`, `PlannedCase`, `plan_cases()`, tiers, `NEEDS_SESSION`, `NEEDS_SECONDARY`, rate profiles. Called from `orchestrator.py:493` | Remains the only execution planner. AASI supplies the case IDs and the facts |
| Orchestrator | `orchestrator.run_execution()` (line 344): feature flag, write permission, cancel check, scope re-check | Agents never call it directly. They create recommendations a human or policy approves |
| Scanner SDK | [`runner/scanners/sdk.py`](../../attestra/runner/scanners/sdk.py) `AdapterMeta` (capabilities, asset_kinds, `safety_tier` T0–T3, `network_egress` none/target/third_party/cloud_api, `ResourceProfile`, licence, `image_ref_env`, output_schema), `default_health`, `contract_problems` | Every external tool is a `ScannerAdapter` with `AdapterMeta`. No second SDK |
| Process execution | `base.run_process()`: no shell, `assert_safe_cli_arg`, kills the process tree on timeout or cancel; `docker_run_argv`; digest-pinned `ATTESTRA_IMAGE_*` | The only way any external tool runs |
| Scanner registry | [`runner/scanners/registry.py`](../../attestra/runner/scanners/registry.py) (14 adapters) | One line per new adapter |
| Importers | [`importers/__init__.py`](../../attestra/importers/__init__.py) `parse(tool, raw)` → `NormalizedFinding` ([`importers/base.py`](../../attestra/importers/base.py): `rule_id`, `cwe`, `confidence`, `tool_version`, `original_id`, `evidence_refs` …) | AI tools get importers first |
| Validation classes | [`finding_validation/statuses.py`](../../attestra/finding_validation/statuses.py): unvalidated, confirmed, needs_manual_validation, potential, false_positive, informational, not_reproducible, accepted_risk. Kept separate from workflow status | **No new enum.** See §7 for the mapping |
| Workflow / retest | `models.py` workflow transitions including `retest_passed`; `retest.py`; `retests` collection | Reused for AI regression retests |
| Coverage | [`automated_vapt/coverage/ledger.py`](../../attestra/automated_vapt/coverage/ledger.py) per-case ledger, `snapshot.py` | Extend with AI categories. Do not build a second ledger |
| Evidence / proof | `proof/` (capture, pair, redact, replay, store), `evidence` collection, `raw_sha256` on every `ScannerResult` | Raw AI tool reports are stored as evidence before any verdict |
| Audit | [`audit.py`](../../attestra/audit.py) hash-chained `record()` / `verify()` | Every AASI decision and approval is recorded |
| AI provider | [`ai_narratives.py`](../../attestra/ai_narratives.py): off by default, Ollama or OpenAI-compatible, key from `secret_store.get_secret("ai_api_key")`, `ATTESTRA_AI_TENANTS_OFF`, `redact()`, `finding_metadata()` (redacted, evidence-free) | AASI reuses the `Provider` protocol and redaction. It does not replace this file |
| AI drafts | `DraftStore`: **JSON files on disk** per engagement; approval through `web/ai_routes.py` with RBAC and audit | Don't copy this storage pattern for AASI memory (it isn't tenant-filtered and doesn't work across instances). Use Mongo |
| Compliance — AI | [`iso_42001_2023.yaml`](../../attestra/compliance/data/packs/iso_42001_2023.yaml) `llm_top10` marks **LLM01, 02, 05, 06, 07, 08, 10 as `active_test: true`**; `compliance/owasp.py` `group_findings_by_llm_top10`, `should_show_llm_top10` | **Nothing in the code produces LLM findings today.** Phase 1 supplies them |
| Reports | `reports/render.py` (technical / executive / compliance), QA, four-eyes, hashing, signing | Add AI sections inside the existing renderer |
| Jobs / workers | `jobs/durable.py` (claim, heartbeat, `request_cancel`, retry), Temporal optional | AI tool runs are ordinary jobs |
| Engineering process | `AGENTS.md` (lat.md knowledge graph, `lat check` required) | **`lat` is not installed on this machine** — a Phase 0 blocker |

### Genuine gaps (nothing exists today)
- An AI or LLM asset kind, test types, adapters or importers. The ISO 42001 and LLM Top-10 report sections therefore have no evidence behind them.
- Any agentic reasoning layer, hypothesis records or decision trace.
- Attack-path correlation. No graph code exists.
- GitHub pull-request proposals. `integrations/github.py` only creates issues.
- AI-draft persistence that is tenant-scoped and stored in Mongo.

---

## 3. Corrections to the GPT v3 directive

| GPT v3 says | Verified fact | Effect |
|---|---|---|
| "The repo does not contain the numbered MongoDB migration files… do not assume 0005 exists" | Partly right. There are no migration files, but migrations **are numbered and registered in code** (`0001`–`0004` in `MIGRATIONS`) | Append the next ID to the list. Don't invent files |
| Strix = "Primary multi-agent orchestration" | Strix agents are `openai-agents` `SandboxAgent`s with `Shell` and `Filesystem` capabilities in Docker plus a Caido proxy (`strix/agents/factory.py`) | Use as a pattern source only. Adopting the runtime would give the LLM a shell |
| PyRIT = "Adopt" | PyRIT 1.3.0.dev: 56 runtime dependencies, including `transformers`, `scipy`, the Azure SDKs, its own `SQLAlchemy[asyncio]` memory, `fastapi>=0.133`, `openai>=3,<4` | Isolated container worker only. Never imported into the core app |
| Promptfoo via "supported execution boundary" | Node `^22.22.2 \|\| ^24.15 \|\| >=26`. Red-team attack generation uses Promptfoo's **remote service by default** unless `PROMPTFOO_DISABLE_REMOTE_GENERATION` is set | Container only, with remote generation, telemetry, sharing and update all disabled |
| SafeLabs "agent-security validation" | Its README says the ASI01–ASI10 categories are "OWASP-inspired, not the official OWASP Top 10 for Agentic Applications 2026". Scoring is pattern-based and heuristic | Map to the official taxonomy explicitly. Results are at most `potential` |
| PentAGI = MIT | The code is MIT, but `EULA.md` adds distribution restrictions and `NOTICE` says the VXControl Cloud SDK is AGPL-3.0 with a project-specific exception | Design reference only |
| AgentEval "native Python patterns" | Correct. The project is C# / .NET (`src/AgentEval.*`), version v0.42.0-beta | pytest only |
| Agent orchestration needs a new coverage system | `automated_vapt/coverage/ledger.py` already exists | Extend it |
| Lists of 8 specialist agents | v3 itself says to start small. Agreed | One orchestrator plus role prompts (§5.3) |

Also still open from the first review:
- [`docs/ARCHITECTURE.md:22`](../ARCHITECTURE.md) still says "Attestra never runs testing tools… keeps AGPL, GPL, NPSL out". The code now executes 14 scanners. Reconcile this in Phase 0.
- The tree has 412 `*.bak_*` files and is **not under git**.

---

## 4. External repositories — verified facts (2026-11-23)

| Repo | Commit | Latest release | Licence (GitHub API + LICENSE) | Language / runtime | Key verified modules |
|---|---|---|---|---|---|
| [usestrix/strix](https://github.com/usestrix/strix) | `00912af5d179` | v1.7.1 | Apache-2.0 | Python; openai-agents + LiteLLM, Docker, Caido | `strix/core/agents.py` `AgentCoordinator`; `tools/agents_graph` (create/send/wait/stop agent); `tools/coverage`; `tools/reporting/tool.py` |
| [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) | `d72c082dc873` | v3.6.1 | **AGPL-3.0** | TypeScript (pnpm/turbo), `apps/cli`, `apps/worker` | Not inspected beyond README and licence (code reuse is not allowed) |
| [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi) | `cffed9485aa1` | v2.2.0 | MIT + **EULA**; Cloud SDK AGPL-3.0 with exception | Go backend, React frontend | `backend/pkg/{providers,tools,graph,graphiti,observability,docker}` |
| [bhavsec/autopentest-ai](https://github.com/bhavsec/autopentest-ai) | `5dee23126a45` (last commit 2026-02-22) | v1.0 | Apache-2.0 | Python MCP server (`server/server.py`, uses subprocess) | `task_tree.py`, `endpoint_priority.py`, `tool_verification.py`, `knowledge_graph.py`, `waf_evasion.py` (excluded) |
| [samugit83/redamon](https://github.com/samugit83/redamon) | `73ca9d38ced0` | v7.9.0 | MIT; `THIRD-PARTY-LICENSES.md` lists GPL/AGPL tools and **WPScan's commercial-use restriction** | Python + Neo4j 5.26 + Kali sandbox | `graph_db/`, `agentic/`, `recon_orchestrator/`, `mcp/` |
| [microsoft/PyRIT](https://github.com/microsoft/PyRIT) | `817523458433` | v1.2.1 | MIT | Python 3.11–3.14, 56 dependencies | `executor/attack/multi_turn/{crescendo,pair,tree_of_attacks,red_teaming}.py`; `single_turn/many_shot_jailbreak.py`; `prompt_target/http_target`; `score/`; `scenario/scenarios/{airt,adaptive,garak}` |
| [NVIDIA/garak](https://github.com/NVIDIA/garak) | `725160beb813` | v0.17.1 | Apache-2.0 | Python ≥3.11, 45 dependencies incl. torch | Probes: `promptinject`, `latentinjection`, `sysprompt_extraction`, `leakreplay`, `web_injection`, `agent_breaker`, `packagehallucination`, `dan`, `encoding`, `exploitation`…; generators incl. `rest`, `openai`, `ollama`, `litellm`; JSONL report with `entry_type` `attempt` / `eval` (`attempt.py:281`, `evaluators/base.py:214`) |
| [promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) | `696d3ca44b81` | npm 0.126.0 | MIT (single root LICENSE) | Node 22+ | 69 red-team plugins incl. `bola`, `bfla`, `rbac`, `excessiveAgency`, `indirectPromptInjection`, `promptExtraction`, `ragDocumentExfiltration`, `crossSessionLeak`, `pii`, `toolDiscovery`, `mcp`, `ssrf`, `sqlInjection`, `shellInjection`; strategies incl. `crescendo`, `goat`, `iterative`, `indirectWebPwn` |
| [AgentSafeLabs/safelabs-eval](https://github.com/AgentSafeLabs/safelabs-eval) | `99655d6d9e18` | v0.12.0 | Apache-2.0 | Python ≥3.11; dependencies: pydantic, httpx, click | `safelabs/agents/*_adapter.py` (HTTP, LangChain, OpenAI Agents, AutoGen…); `scoring/detectors`; `judge/`; `DATA_INTEGRITY_RULES.md` |
| [AgentEvalHQ/AgentEval](https://github.com/AgentEvalHQ/AgentEval) | `ec3e5c660074` | v0.42.0-beta | MIT | C# / .NET | `AgentEval.Evals.Agentic`, `AgentEval.Memory`, `AgentEval.Compliance.*` |

Before adopting any tool, re-pin and re-check its licence. The commits above are already outdated for fast-moving repos (Promptfoo and Strix both had commits on 2026-11-22/23).

### 4.1 Patterns to re-implement natively (the value taken from the agent repos)

| Pattern | Source (verified) | Attestra implementation |
|---|---|---|
| **Evidence-ID gate**: a finding is rejected if its evidence IDs don't exist in recorded traffic | Strix `tools/reporting/tool.py` `_verify_http_exchange_ids` | An AASI conclusion may cite only `evidence` / `proof` / `finding` IDs that exist in the same tenant and engagement. Unknown IDs mean the conclusion is rejected and logged |
| **Coverage ledger with dedupe on surface × risk area** | Strix `tools/coverage/tools.py` `_duplicate_of_locked` | Extend `automated_vapt/coverage/ledger.py` with `origin: catalogue \| aasi` and AI categories |
| **Bounded agent graph** (create / wait / stop, completion report) | Strix `tools/agents_graph/tools.py` | Roles are stages inside one orchestrator (§5.3). Hard limits on depth and count |
| **Validated reporting fields** (CWE, CVE, CVSS checked before a report is accepted) | Strix `_validate_cwe`, `_validate_cve`, `_calculate_cvss` | Reuse `importers/base.parse_cwe` and the existing CVSS code. The agent cannot assign CVEs |
| **Task tree with completion propagation** | AutoPentest `server/task_tree.py` | `aasi_runs.tasks[]` with parent IDs and status rollup |
| **Endpoint priority scoring** | AutoPentest `server/endpoint_priority.py` | Ranks the planner's inputs. The planner still orders execution |
| **Tool-output verification** (flags empty or suspicious output as not tested, not passed) | AutoPentest `server/tool_verification.py` | Extend `run_validity.py`: empty or invalid AI-tool output becomes `NOT_TESTED` with a reason |
| **Archive raw responses before computing a verdict** | SafeLabs `DATA_INTEGRITY_RULES.md` Rule 1 | Already Attestra practice (`raw_sha256`). Make it a contract test for every AI importer |
| **Typed attack graph with provenance** | RedAmon `graph_db/` (Neo4j) | Mongo collections with `observed \| inferred \| demonstrated` edge labels (Phase 6) |
| **"No exploit, no report"** | Shannon README | `confirmed` only with replay or proof evidence plus human review. This is the existing rule; enforce it for AASI too |
| **Tool-call assertions** | AgentEval concepts | pytest fixtures that assert which tool was called, with which arguments, in what order and under which identity, for AI-agent targets |

Explicitly **not** adopted: Strix's shell, filesystem and browser tools and its MCP registry; AutoPentest's `waf_evasion.py`; RedAmon's Kali sandbox and WPScan; PentAGI's Go runtime; anything from Shannon.

---

## 5. Target architecture

### 5.1 Layering (the one rule that matters)

```
 Agent reasoning (aasi/)          ── proposes ──▶  TestRecommendation(test_id ∈ registry)
        │ (no execution rights)                         │
        ▼                                               ▼
 Approval (human / policy, RBAC, audit)  ──▶  planner.plan_cases(ids, PlanFacts)
                                                        │ run / skip / defer
                                                        ▼
                     orchestrator.run_execution  |  jobs → runner adapter (AdapterMeta, container)
                                                        │ raw report (sha256, evidence)
                                                        ▼
                     importers.parse(tool) → NormalizedFinding → findings / finding_observations
                                                        │ validation class (statuses.py)
                                                        ▼
                     human review → confirmed / false_positive / …  → reports (QA, four-eyes, signing)
```

AASI sits only in the first box. It reads redacted context and writes recommendations and decision records. Every other box already exists.

### 5.2 New and changed code (smallest set)

| Path | New / extend | Purpose |
|---|---|---|
| `attestra/models.py` | extend | `ASSET_KINDS["ai_app"]`; `TEST_TYPES["ai_llm"]`, `TEST_TYPES["ai_agent"]` with `imports` lists |
| `attestra/importers/garak.py`, `promptfoo.py`, `safelabs.py`, `pyrit.py` | new | Parse native reports into `NormalizedFinding` |
| `attestra/runner/scanners/garak.py`, `promptfoo.py`, `safelabs.py`, `pyrit.py` | new | `ScannerAdapter` + `AdapterMeta`, digest-pinned `ATTESTRA_IMAGE_*` |
| `attestra/runner/scanners/registry.py`, `sdk.py` `DEFAULT_META` | extend | Registration |
| `attestra/compliance/data/ai_taxonomy.yaml` | new | Mapping matrix: tool probe/plugin → OWASP LLM Top-10 2025 / OWASP Agentic → CWE → ISO 42001 control |
| `attestra/compliance/data/packs/iso_42001_2023.yaml` | extend | Link `llm_top10` entries to concrete test refs |
| `attestra/automated_vapt/coverage/ledger.py` | extend | AI categories; `origin` field |
| `attestra/automated_vapt/core/run_validity.py` | extend | AI-tool output validity (empty, refused, or rate-limited means `NOT_TESTED`) |
| `attestra/aasi/contracts.py` | new | Typed dataclasses (§7) |
| `attestra/aasi/context.py` | new | Bounded, redacted, trust-labelled context builder |
| `attestra/aasi/provider.py` | new | Thin wrapper over `ai_narratives.Provider`: structured JSON output, schema validation, call budget |
| `attestra/aasi/orchestrator.py` | new | Bounded loop: context → roles → recommendations → submit for approval |
| `attestra/aasi/roles.py` | new | Role prompts and output schemas (strategist, hypothesis, AI-security, evidence reviewer, quality reviewer) |
| `attestra/aasi/budget.py` | new | Iteration, call, token, time and task limits; cancellation |
| `attestra/aasi/store.py` | new | `aasi_runs`, `aasi_decisions` through the Mongo adapters, tenant-scoped |
| `attestra/aasi/routes.py` | new | FastAPI router behind existing RBAC |
| `attestra/persistence/mongo/{collections,indexes}.py`, `migrations/__init__.py` | extend | New collections, indexes, next migration ID |
| `attestra/reports/render.py` + templates | extend | AI-security section and AASI traceability appendix |
| `tests/…` | new | Inside the existing `tests/` tree (not inside the package) |

Not created: a second planner, SDK, finding model, validation enum, provider framework, database, graph database or vector store.

### 5.3 Agent topology (start small)

There is one `AasiOrchestrator` and five **roles**. A role is a prompt plus an output schema run through the same provider. Roles are not independent agents.

| Role | Input (redacted) | Output (typed) | Phase |
|---|---|---|---|
| Strategist | Engagement objective, authorized assets and test types, coverage gaps | Ordered objectives | 3 |
| Hypothesis | Scanner observations, API inventory, existing findings (metadata only) | `Hypothesis[]` each citing observation IDs | 3 |
| AI-security specialist | `ai_app` asset profile, AI coverage ledger | `TestRecommendation[]` (Garak probes, Promptfoo plugins, PyRIT scenarios) | 3 |
| Evidence reviewer | Finding + evidence metadata | Evidence gaps; suggested retests; `needs_manual_validation` flags | 4 |
| Quality reviewer | Plan, skips, defers, results | Completeness statement; unsupported-claim list | 4 |

Split a role into an independent agent only when a measured benchmark shows it helps (§9, Phase 4 exit).

---

## 6. Data and persistence

| Collection | Key fields | Notes |
|---|---|---|
| `aasi_runs` (new) | `id`, `tenant_id`, `engagement_id`, `correlation_id`, `status` (CREATED → SCOPE_CHECK → PLANNING → AWAITING_APPROVAL → EXECUTING → REVIEW → COMPLETED / BLOCKED / FAILED / CANCELLED), `budget{}`, `usage{calls, tokens_in, tokens_out, wall_s}`, `provider{name, model}`, `tasks[]`, `idempotency_key` (unique per tenant), timestamps, `schema_version` | One record per assessment run |
| `aasi_decisions` (new, append-only) | `id`, `run_id`, `tenant_id`, `engagement_id`, `role`, `kind` (hypothesis / recommendation / planner_outcome / approval / conclusion), `payload` (the typed contract), `cites[]` (validated IDs), `audit_hash` | Never store raw chain-of-thought, only structured summaries. Each insert also calls `audit.record()` |
| `assets` (existing) | `kind = "ai_app"`; config refers to `auth_credential_profiles` / secret-store keys, never raw keys | The AI target to be tested |
| `findings`, `finding_observations`, `evidence` (existing) | Unchanged schema; `tool` = garak / promptfoo / pyrit / safelabs | One canonical finding, many observations |
| `automated_test_executions.result_json.coverage_ledger` (existing) | Add `origin`, AI category | AI coverage |

Migration: append `("00NN_aasi_collections", "AASI runs/decisions + indexes", fn)` to `MIGRATIONS` (use the next free ID at implementation time). The migration must be idempotent: create the collections if missing and create the indexes `(tenant_id, engagement_id)`, `(tenant_id, idempotency_key)` unique, and `(run_id, created_at)`. Rollback: the collections are additive, so dropping them is safe. Write that down in the phase report.

Retention: `aasi_decisions` follow the engagement's `retention_policies`. When an engagement is deleted or expires, its context is never reused (this is tested).

---

## 7. Contracts and how results map to existing validation classes

```python
# attestra/aasi/contracts.py (shape, not final code)
@dataclass(frozen=True)
class Hypothesis:
    id: str; run_id: str; tenant_id: int; engagement_id: int; asset_id: int
    statement: str                 # short, no target secrets
    basis: Literal["observed", "inferred"]
    cites: tuple[str, ...]         # observation / finding / evidence IDs — validated to exist
    uncertainty: str

@dataclass(frozen=True)
class TestRecommendation:
    id: str; hypothesis_id: str; asset_id: int
    test_id: str                   # MUST be in test_registry or a registered adapter capability
    test_type: str                 # MUST be authorized for the asset (TEST_TYPES)
    intrusive: bool                # computed from intrusive_policy, never from the LLM
    expected_evidence: tuple[str, ...]
    rationale: str

@dataclass(frozen=True)
class Conclusion:
    id: str; run_id: str; subject_ids: tuple[str, ...]
    kind: Literal["observed_fact", "hypothesis", "scanner_result", "correlated",
                  "potential_finding", "manually_reviewed", "validated", "rejected", "inconclusive"]
    cites: tuple[str, ...]; recommended_action: str
    confidence: float | None       # evidence-strength score; NOT a validation status
    confidence_basis: str
```

Validation runs in code, not in the model: unknown `test_id`, an unauthorized `test_type`, an off-scope `asset_id`, or a citation that doesn't exist each reject the item and are logged.

| AASI / tool outcome | Stored as | Validation class (existing) |
|---|---|---|
| Agent hypothesis | `aasi_decisions` only | (not a finding) |
| Correlated observation / inferred attack path | `aasi_decisions`, graph edge `inferred` | (not a finding) |
| AI-tool detector hit (Garak / Promptfoo / PyRIT scorer) | finding + observation + raw evidence | `potential` |
| SafeLabs pattern hit | same | `potential` (never higher automatically) |
| Detector "uncertain" / judge disagreement | same | `needs_manual_validation` |
| Tool ran, nothing found | coverage ledger "assessed, no issue" | (no finding) |
| Tool failed, refused or got empty output | coverage ledger `NOT_TESTED` + reason | (no finding; never reported as passed) |
| Reproduced by deterministic replay plus a reviewer | finding | `confirmed` (human action only) |
| Reviewer rejects | finding | `false_positive` |
| Replay fails | finding | `not_reproducible` |
| GPT's "inconclusive" | — | `needs_manual_validation` |

For **agent targets**, the evidence must include the target's *actual* tool-call log (name, arguments, identity, result), taken from the target harness or proxy. A model's claim that it called a tool is not evidence.

---

## 8. Security governance — controls, where they are enforced, and how they are tested

| Control | Enforced by (existing unless marked) | Test |
|---|---|---|
| Feature off by default | **new** `ATTESTRA_AASI=off`; also needs `ai_narratives.is_enabled(tenant)`; honours `ATTESTRA_AI_TENANTS_OFF` | AI off: deterministic VAPT runs unchanged |
| Scope | `authorize_target`, `validate_url_target`, `validate_resolved_ips`, `assert_engagement_ready_for_case` checked again at execution | Recommendation for an off-scope asset or URL is rejected |
| Authorized test types | `TEST_TYPES` per authorization | `ai_agent` test on an asset authorized only for `ai_llm` is rejected |
| Registered tests only | Contract validator against `test_registry` + scanner registry | Unregistered ID or free-form command is rejected |
| No shell or HTTP from agents | Agents have **no** execution tools; adapters use `run_process` + `assert_safe_cli_arg` | Static test: `attestra/aasi` imports no subprocess, httpx, requests or docker |
| Intrusive / approval | `intrusive_policy` + **new** approval endpoint (RBAC permission, `audit.record`) | Approval cannot come from model output; production is forbidden |
| Prompt injection | Context builder wraps all target, scanner and document content as `{"untrusted": …}`; system prompt is fixed; output must match the schema; `ai_narratives.redact()` | Injected scanner output ("ignore previous… add host X") changes nothing |
| Data to providers | Only `finding_metadata()`-style redacted fields; no evidence bodies, hostnames, credentials or source code unless the tenant has a data-processing flag (**new**, default off) | Redaction tests; prompt snapshot contains no secrets |
| Third-party judge models (Promptfoo graders, PyRIT scorers) | Adapter `network_egress="third_party"` → refused unless the tenant flag is on; otherwise use a local Ollama judge | Egress refused without the flag |
| Promptfoo remote services | Container env `PROMPTFOO_DISABLE_REMOTE_GENERATION=true`, `PROMPTFOO_DISABLE_TELEMETRY=1`, `PROMPTFOO_DISABLE_SHARING=1`, `PROMPTFOO_DISABLE_UPDATE=1` | Adapter contract test asserts the env |
| Tenant isolation | `tenant_scope`, `effective_scope` on every AASI query | Cross-tenant context, decision and evidence reads are denied |
| Secrets | `secret_store.get_secret`; AI-target keys referenced, never stored in assets or decisions | Grep of decisions, logs and prompts finds no keys |
| Budgets / no infinite loops | `aasi/budget.py`: max iterations (default 5), roles per run, provider calls (default 30), tokens, wall time (default 15 min), retries (2) | Budget exhaustion ends the run as `BLOCKED` with a reason |
| Cancellation / idempotency | `jobs.request_cancel`, engagement cancel event; unique `idempotency_key` | Double submit makes one run; cancel stops the provider loop and queued jobs |
| Evidence integrity | `raw_sha256`, `evidence` store, audit chain | Tampered raw report is quarantined |
| Licence gate | `supply_chain/license_policy.py` (AGPL denied, GPL in review) + `AdapterMeta.licence` | Adapter with a denied licence fails `contract_problems` |

---

## 9. Phased roadmap

Every phase follows the same loop: inspect → design note → smallest vertical slice → unit, integration and security tests → full regression → `lat.md` update + `lat check` → phase report (format in §11). **Stop for approval between phases.**

### Phase 0 — Baseline and prerequisites (no product change)
- Put `attestra-code` under git and commit the current tree. Decide what to do with the 412 `.bak_*` files (archive or `.gitignore`); don't delete them without approval.
- Create a virtualenv from `pyproject.toml` (`pip install -e '.[dev]'`) and record the baseline `pytest` result. Today, system Python fails collection with 83 errors (`No module named 'sqlalchemy'`).
- Install the `lat` CLI. Run `lat check` and record the baseline.
- Reconcile `docs/ARCHITECTURE.md` "Import, don't execute" with the runner. Record the current licence position on executed tools.
- Re-pin the ten repos (§4) and record the SHAs in this file's appendix.
- **Exit:** baseline test count and pass/fail recorded; `lat check` result recorded; git commit exists.

### Phase 1 — AI targets and AI result importers (first customer value)
- `ASSET_KINDS["ai_app"]`; `TEST_TYPES["ai_llm"]` (imports: garak, promptfoo, safelabs, pyrit) and `["ai_agent"]`. Update the authorization letter and UI labels.
- `importers/garak.py`: parse JSONL. Use `entry_type == "attempt"` records (probe_classname, prompt, outputs, detector_results) and `"eval"` summaries. A failing detector creates an observation; `rule_id = probe.detector`.
- `importers/promptfoo.py`: parse `promptfoo eval -o results.json`. Failed red-team assertions per plugin create observations; keep the test case reference.
- `compliance/data/ai_taxonomy.yaml`: map Garak probes and Promptfoo plugins to LLM01–LLM10, CWE (for example CWE-1427 for prompt injection) and ISO 42001 controls.
- Every AI finding enters as `potential` or `needs_manual_validation`. The raw file is stored as evidence before parsing.
- **Exit:** uploading a real Garak and Promptfoo report (generated against a local synthetic chatbot) fills the existing LLM Top-10 report section and the ISO 42001 evidence; malformed files are quarantined; tenant isolation tests pass.

### Phase 2 — AI tool execution through the adapter SDK
- `runner/scanners/garak.py` (`safety_tier` T2, `network_egress="target"`, image `ATTESTRA_IMAGE_GARAK`), using Garak's `rest` generator pointed at the authorized `ai_app` URL.
- `runner/scanners/promptfoo.py` (Node image, remote generation off, grader = tenant-approved provider or local Ollama).
- `runner/scanners/safelabs.py` (light Python dependencies; still run in a container for isolation).
- AI coverage categories in the ledger; AI output validity rules in `run_validity.py`.
- **Exit:** scheduled run against a local vulnerable LLM app produces findings end to end; cancel and timeout work; an off-scope URL is refused; egress policy is enforced.

### Phase 3 — AASI core (recommend-only)
- `aasi/contracts.py`, `context.py`, `provider.py`, `budget.py`, `store.py`, `orchestrator.py`, roles: strategist, hypothesis, AI-security specialist.
- Recommendations go into the approval queue. Once approved, they are submitted to `planner.plan_cases` or as adapter jobs. The orchestrator records the planner outcome.
- Deterministic fake provider in tests. With AI off, the endpoint returns 404 and nothing else changes.
- **Exit:** a controlled run produces typed hypotheses and recommendations with valid citations; unregistered or off-scope items are rejected; budgets end runs; full decision trace in `aasi_decisions` + audit chain.

### Phase 4 — Evidence reviewer, quality reviewer and Strix patterns
- Evidence-ID gate, coverage dedupe (surface × risk area), evidence-gap → retest recommendation, quality completeness statement.
- Benchmark: a fixed local lab with known planted issues. Compare catalogue-only runs against catalogue + AASI runs on found, false positive, not tested and cost.
- **Exit:** a measurable improvement on the benchmark, or a documented decision not to expand agents further.

### Phase 5 — PyRIT multi-turn worker
- Container worker running selected PyRIT attacks (`crescendo`, `pair`, `tree_of_attacks`, `red_teaming`, `many_shot_jailbreak`) through `prompt_target/http_target`. PyRIT memory is exported to JSON and loaded by `importers/pyrit.py`.
- Scorer and adversarial-model egress follow the §8 third-party rule.
- **Exit:** reproducible multi-turn transcript evidence; conversation IDs cited; costs recorded from actual usage.

### Phase 6 — Correlation, attack paths and remediation proposals
- Mongo-native graph (`aasi_graph_nodes`, `aasi_graph_edges` with `observed | inferred | demonstrated`, provenance and evidence cites). Risk is not raised just because more edges exist.
- GitHub **pull-request proposals** (new; today only issues exist): drafted, need customer approval, never pushed automatically; closure needs a retest (`retest_passed`).
- **Exit:** inferred paths labelled as inferred in reports; demonstrated paths need replay evidence.

### Phase 7 — Reporting and hardening
- AI-security section or report type in `reports/render.py`; AASI traceability appendix (hypothesis → test → result → finding); coverage and limitations.
- Full security suite (§10), performance and cost measurement, licence review, deploy and rollback docs, production-readiness statement.

---

## 10. Test plan

Tests go in the existing `tests/` tree. Each key test gets a `lat.md/tests.md` spec plus a `# @lat:` reference.

| # | Security test | Phase |
|---|---|---|
| 1 | Prompt injection inside scanner output does not change recommendations or scope | 3 |
| 2 | Prompt injection inside retrieved documents / RAG content | 2, 3 |
| 3 | Recommendation for an unauthorized asset is rejected | 3 |
| 4 | Cross-tenant context, decision and evidence leakage | 1, 3 |
| 5 | Unregistered test ID rejected | 3 |
| 6 | Scope escalation (new host or URL from model output) rejected | 3 |
| 7 | Arbitrary command request rejected; static no-execution import test | 3 |
| 8 | Secrets absent from prompts, logs and decisions | 1, 3 |
| 9 | Unbounded loop stopped by budget | 3 |
| 10 | Provider-call ceiling enforced | 3 |
| 11 | Approval bypass (model output claiming approval) has no effect | 3 |
| 12 | Forged evidence ID citation rejected (Strix gate) | 4 |
| 13 | Malformed Garak, Promptfoo, PyRIT or SafeLabs file quarantined | 1, 5 |
| 14 | Duplicate submission (idempotency) gives one run | 3 |
| 15 | Expired authorization stops the run mid-way | 3 |
| 16 | Cancellation reaches the provider loop and queued jobs | 2, 3 |
| 17 | Deleted or expired engagement context is not reused | 5, 6 |
| 18 | AI off: the deterministic regression suite is unchanged | every phase |
| 19 | Tool failure shows as `NOT_TESTED`, never as passed | 2 |
| 20 | Agent-target tool-call assertions (AgentEval-style) | 2, 5 |

End-to-end proof of concept: only local, deliberately vulnerable web apps and **synthetic** LLM/agent targets (for example a small FastAPI chatbot with a planted system prompt, a fake RAG store with two tenants, and a fake tool with an over-privileged action). Never public or customer systems.

---

## 11. Phase report format (required after every phase)

A. Summary · B. Components extended · C. Files added, modified, removed · D. Integration points · E. Security controls and tests · F. Exact test commands, counts and pass/fail · G. Dependency and image changes (version, licence, digest) · H. `lat check` output · I. Open issues and risks · J. Next phase and its exit criteria.
Never claim a result without the command output.

---

## 12. Decisions needed from you

1. **Legal:** confirm Shannon stays at no code reuse, and that PentAGI's EULA and RedAmon's bundled tools rule out any distribution.
2. **Data processing:** may tenant data (redacted metadata, prompts, target responses) go to third-party judge or adversarial models? The default here is no, with a local Ollama judge instead.
3. **Product naming:** `ai_app` asset kind; `ai_llm` and `ai_agent` test types; the report section name.
4. **Isolated lab:** do you ever want a Strix-style autonomous runtime in an internal-only lab? It is out of scope for the product in this plan.
5. **Phase 0 go-ahead:** git, virtualenv, `lat` install.

---

## 13. Instruction for the coding agent (use instead of the GPT directives)

> You are implementing AASI in `attestra-code/`. Read `AGENTS.md`, then `docs/ai_security/AASI_IMPLEMENTATION_BLUEPRINT.md` in full. Source code is authoritative; this blueprint comes next; record any discrepancy in the phase report.
> Implement **only the phase named in the request**, following §9 for scope and exit criteria, §2 for the only allowed extension points, and §8 for the controls. Do not create a second planner, adapter SDK, finding model, validation enum, AI provider framework or database. Agents may only produce typed recommendations of registered test IDs; they get no execution tools. External AI frameworks run as digest-pinned containers through `runner/scanners` adapters and come in through `importers/`.
> Put tests in `tests/`. Update `lat.md/` for implemented behaviour and run `lat check`. Finish with the §11 report and stop for approval.

---

## Appendix A — verification log (2026-11-23)

- Attestra: files and symbols cited in §2 were read directly. `pytest` with system Python 3.13.1: 83 collection errors (missing `sqlalchemy`), so there is no baseline yet. `lat`: not installed.
- Upstream: GitHub REST API (`/repos`, `/commits/<default>`, `/releases/latest`) for licence, branch, SHA and release; shallow clones read with `grep` / `ls` only (nothing executed) for the module and dependency facts in §4.
- Not verified: runtime behaviour of any upstream tool, transitive dependency licences, OWASP Agentic taxonomy version. These belong to Phase 0 and the start of each adoption phase.
