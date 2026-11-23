# AASI external repository adoption matrix

Phase 0/5 research snapshot of ten upstream repositories considered for Attestra Agentic Security Intelligence (AASI). Values were revalidated from GitHub API, LICENSE files, package manifests, and project READMEs on **2026-11-23**. Do not treat older SHAs in prior drafts as current.

**Precedence:** Attestra remains system of record. Agents recommend registered test IDs only. External agent runtimes never receive execution rights. Scanner tools enter only through digest-pinned containers and the existing `ScannerAdapter` SDK. See [`AASI_IMPLEMENTATION_BLUEPRINT.md`](./AASI_IMPLEMENTATION_BLUEPRINT.md) and [`AASI_LICENSE_REVIEW.md`](./AASI_LICENSE_REVIEW.md).

| Decision | Meaning |
|---|---|
| **Adopt (scanner)** | First-class importer and/or container runner |
| **Adopt later (isolated)** | Container worker only; never a core Python dependency |
| **Selective adapter/importer** | Import or wrap outputs; cap validation status |
| **Design / architecture reference** | Re-implement patterns natively; no runtime/code reuse |
| **No code reuse** | Licence or policy prohibition on copying or linking code |

---

## Summary table

| # | Repository | HEAD (default branch) | Latest release | License | Runtime | AASI decision | Complexity |
|---|---|---|---|---|---|---|---|
| 1 | [usestrix/strix](https://github.com/usestrix/strix) | `00912af5d179fda5e52961421f9061240a43676c` (`main`, 2026-11-22) | **v1.7.1** (2026-11-10) | Apache-2.0 | Python ≥3.12 + Docker sandbox | **Primary architecture reference only** | Low (patterns only) |
| 2 | [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) | `d72c082dc873273cb99ea53bdec1c582c2493753` (`main`, 2026-11-20) | **v3.6.1** (2026-11-20) | **AGPL-3.0** | TypeScript / Node 22+, Docker worker | **NO code reuse** (AGPL prohibited) | N/A — blocked |
| 3 | [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi) | `cffed9485aa1cca70762cd08a57ac62a80406258` (`main`, 2026-10-22) | **v2.2.0** (2026-10-05) | MIT + **EULA**; Cloud SDK AGPL-3.0 (project exception) | Go backend + React; Docker sandbox | **Design reference only** | Low (ideas only) |
| 4 | [bhavsec/autopentest-ai](https://github.com/bhavsec/autopentest-ai) | `5dee23126a45990292322aa8d073aabd46a8101b` (`main`, 2026-02-22) | **v1.0** (2026-02-22) | Apache-2.0 | Python ≥3.10 MCP server + Docker tools | **Selective architectural reference** | Low–medium |
| 5 | [samugit83/redamon](https://github.com/samugit83/redamon) | `73ca9d38ced026be6d88d1dc526c72317e7d193c` (`master`, 2026-11-19) | **v7.9.0** (2026-11-19) | MIT; bundled tools include AGPL/GPL and commercial restrictions | Python + Neo4j + Kali sandbox | **Selective architecture reference** | Medium (licence minefield if bundling) |
| 6 | [microsoft/PyRIT](https://github.com/microsoft/PyRIT) | `5b51e968e2fc65d425bb2ec31d9a2db2d4c2b3d1` (`main`, 2026-11-23) | **v1.2.1** (2026-11-18); tree shows `1.3.0.dev0` | MIT | Python 3.11–3.14; ~56 runtime deps | **Isolated container worker later** | High |
| 7 | [NVIDIA/garak](https://github.com/NVIDIA/garak) | `725160beb8137a8294c79b1f78c68a756367f861` (`main`, 2026-11-18) | **v0.17.1** (2026-10-16); tree `0.17.2.pre1` | Apache-2.0 | Python ≥3.11; heavy ML stack (`torch`, `transformers`) | **First-class scanner integration** | Medium–high |
| 8 | [promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) | `696d3ca44b81abfc37e9419c19dd98924845a256` (`main`, 2026-11-23) | **0.126.0** (npm, 2026-11-18) | MIT | Node `^22.22.2 \|\| ^24.15 \|\| >=26` | **First-class scanner**; remote/telemetry/sharing/updates **off** | Medium |
| 9 | [AgentSafeLabs/safelabs-eval](https://github.com/AgentSafeLabs/safelabs-eval) | `99655d6d9e181028a674f1b29be7dbe11935b066` (`main`, 2026-11-06) | **v0.12.0** (2026-10-24) | Apache-2.0 | Python ≥3.11; light deps | **Selective adapter/importer** | Low–medium |
| 10 | [AgentEvalHQ/AgentEval](https://github.com/AgentEvalHQ/AgentEval) | `ec3e5c6600741ec2d3ac472c7e5137ad4d6fe6aa` (`main`, 2026-11-12) | GitHub “latest” **v0.42.0-beta**; newer prereleases **v1.0.0-rc.3** | MIT (AEF contracts Apache-2.0) | **C# / .NET 8–10** | **Native Python/pytest assertions**; no .NET | Low (concepts only) |

---

## 1. usestrix/strix — primary architecture reference

| Field | Value |
|---|---|
| **Commit / release** | HEAD `00912af5d179…` on `main`; release **v1.7.1** (`pyproject` name `strix-agent`) |
| **License** | Apache-2.0 (LICENSE + GitHub SPDX) |
| **Runtime** | Python ≥3.12; Docker sandbox; optional Go TUI sidecar |
| **Main deps** | `openai-agents[litellm]`, `litellm`, `docker`, `caido-sdk-client`, `pydantic`, `reportlab`, cloud SDKs (`boto3`, `google-auth`) |
| **Execution model** | Multi-agent “graph of agents”; agents get HTTP proxy (Caido), browser, **shell**, custom Python exploit runtime, recon tools; results under `strix_runs/` |
| **Security boundaries** | Docker sandbox for tool execution; authorized-use warning in README. LLM still receives broad tool surface (shell/filesystem/browser) inside the sandbox |
| **Adopted features** | Evidence-ID gate on reported HTTP exchanges; coverage ledger with surface×risk dedupe; bounded agent create/wait/stop; validated CWE/CVE/CVSS fields before accept |
| **Rejected features** | Unrestricted shell / filesystem / browser tools; MCP registry as execution path; adopting Strix as orchestration runtime |
| **Integration complexity** | **Low** — re-implement patterns inside Attestra AASI; no package import |

---

## 2. KeygraphHQ/shannon — AGPL-3.0; NO code reuse

| Field | Value |
|---|---|
| **Commit / release** | HEAD `d72c082dc873…`; release **v3.6.1** |
| **License** | **GNU Affero General Public License v3.0** (raw LICENSE verified) |
| **Runtime** | TypeScript monorepo (pnpm/turbo); Docker worker; Node 22+ for `npx @keygraph/shannon` |
| **Main deps** | CLI + worker apps; LLM BYOK (Anthropic/OpenAI/xAI/Bedrock/gateways); browser automation for live exploit |
| **Execution model** | Source analysis → recon/vuln agents → exploitation agents against running app; “no exploit, no report”; SARIF/PDF/Markdown |
| **Security boundaries** | Repo mounted read-only in ephemeral worker; self-hosted OSS; still actively exploits targets |
| **Adopted features** | **None as code.** Conceptual rule only: confirmed findings need exploit/proof evidence (maps to existing Attestra validation) |
| **Rejected features** | **All code reuse, linking, forking into Attestra, or AGPL-contagious combination** |
| **Integration complexity** | **Blocked** by Attestra licence policy |

> **Blocker:** Shannon AGPL-3.0 is **prohibited for code reuse** in Attestra. Ideas may be restated in original Attestra terms without copying Shannon source.

---

## 3. vxcontrol/pentagi — design reference only

| Field | Value |
|---|---|
| **Commit / release** | HEAD `cffed9485aa1…`; release **v2.2.0** |
| **License** | MIT (LICENSE) **plus** `EULA.md` use/distribution terms; `NOTICE` states VXControl Cloud SDK is **AGPL-3.0** with a project-specific exception |
| **Runtime** | Go API + React UI; PostgreSQL/pgvector; optional Neo4j/Graphiti; Docker tool sandbox |
| **Main deps** | Docker Compose stack; 10+ LLM providers; 20+ pentest tools (nmap, Metasploit, sqlmap, …) |
| **Execution model** | Orchestrator + specialist agents (research/dev/executor); tools run in isolated Docker; memory/vector store; optional knowledge graph |
| **Security boundaries** | Sandboxed Docker for tools; self-hosted; EULA restricts use to authorized testing |
| **Adopted features** | High-level supervision / flow / memory ideas only |
| **Rejected features** | Go runtime adoption; Cloud SDK; any AGPL-tainted components; unrestricted agent tool execution |
| **Integration complexity** | **Low** for design notes; **high** if anyone proposed shipping PentAGI (do not) |

---

## 4. bhavsec/autopentest-ai — selective architectural reference

| Field | Value |
|---|---|
| **Commit / release** | HEAD `5dee23126a45…` (last push 2026-02-22); release **v1.0**. Relatively quiet vs other repos |
| **License** | Apache-2.0 |
| **Runtime** | Python MCP server (`mcp[cli]`, `pyyaml`); Claude Code / Ollama orchestrator; Docker image with ~27 CLI security tools; Playwright MCP |
| **Main deps** | MCP SDK; Docker tools container (nuclei, sqlmap, dalfox, katana, ffuf, nmap, …) |
| **Execution model** | 7-phase WSTG workflow; role agents Scout / Analyzer / Exploiter / Reporter; quality gates; evidence-backed findings |
| **Security boundaries** | Tools in Docker; role tool allow/deny lists in prompts; Burp optional. Orchestrator still drives real exploits |
| **Adopted features** | Task tree with completion propagation; endpoint priority scoring; tool-output verification (empty/suspicious → not tested) |
| **Rejected features** | `waf_evasion` module; MCP server as Attestra execution plane; wholesale methodology copy as a second planner |
| **Integration complexity** | **Low–medium** — patterns map onto `aasi_runs.tasks`, planner inputs, and `run_validity` |

---

## 5. samugit83/redamon — selective architecture reference

| Field | Value |
|---|---|
| **Commit / release** | HEAD `73ca9d38ced0…` on `master`; release **v7.9.0** (`VERSION` = 7.9.0) |
| **License** | MIT for RedAmon itself; `THIRD-PARTY-LICENSES.md` lists many **AGPL-3.0** ProjectDiscovery tools (nuclei, naabu, httpx, …) and other restricted components (e.g. WPScan commercial-use limits) |
| **Runtime** | Python services; Neo4j graph; Kali MCP sandbox; multi-tenant webapp |
| **Main deps** | Neo4j 5.x; Docker Compose; large Kali/tool image set; LLM providers |
| **Execution model** | Parallel recon → living attack-surface graph → agentic exploitation with **human approval gates** → triage / CypherFix PRs |
| **Security boundaries** | Self-hosted; RoE enforcement; RBAC; approval gates before exploit; audit trails |
| **Adopted features** | Typed attack-graph ideas with provenance labels (`observed` / `inferred` / `demonstrated`) implemented on **MongoDB**, not Neo4j |
| **Rejected features** | Bundling Kali/AGPL scanner images into Attestra; WPScan; adopting RedAmon agent runtime or Neo4j as SoR |
| **Integration complexity** | **Medium** for graph schema ideas; **high/blocked** for tool-image reuse without separate licence review per tool |

---

## 6. microsoft/PyRIT — isolated container worker later

| Field | Value |
|---|---|
| **Commit / release** | HEAD `5b51e968e2fc…`; release **v1.2.1**; `pyproject` version **1.3.0.dev0** on main |
| **License** | MIT (+ third-party notices / LICENSES tree) |
| **Runtime** | Python ≥3.11,<3.15; CLI (`pyrit_scan`), GUI, FastAPI backend optional |
| **Main deps** | ~56 runtime packages including `openai`, `transformers`, `scipy`, Azure SDKs, `SQLAlchemy[asyncio]`, `fastapi`, `mcp`; optional `torch` / Playwright / LiteLLM extras |
| **Execution model** | Composable attacks (multi-turn Crescendo/PAIR/ToA, single-turn jailbreaks); scorers; prompt targets (HTTP, WebSocket, Playwright, providers) |
| **Security boundaries** | Intended for authorized AI red teaming; heavy dependency and optional browser automation imply **must not** share Attestra process/venv |
| **Adopted features** | Multi-turn attack orchestration as a **later** digest-pinned worker; importer for PyRIT JSON/results |
| **Rejected features** | Direct `import pyrit` in Attestra core; co-installing torch/Azure stack into app env |
| **Integration complexity** | **High** — image pinning, memory/DB isolation, result schema mapping, resource profile |

---

## 7. NVIDIA/garak — first-class scanner integration

| Field | Value |
|---|---|
| **Commit / release** | HEAD `725160beb813…`; release **v0.17.1**; tree version **0.17.2.pre1** |
| **License** | Apache-2.0 |
| **Runtime** | Python ≥3.11; CLI `garak` |
| **Main deps** | `torch`, `transformers`, `datasets`, `litellm`, `langchain`, provider SDKs (OpenAI, Anthropic, Cohere, Bedrock, …) — large footprint |
| **Execution model** | Probe → generator → detector pipeline; JSONL reports (`attempt` / `eval` entry types); REST and many LLM backends |
| **Security boundaries** | Outbound to configured model endpoints only as configured; containerize to keep torch out of Attestra; treat probe traffic as potentially intrusive when it hits customer apps |
| **Adopted features** | Importer first, then `ScannerAdapter` runner (digest-pinned image); map probes to AI test catalogue / OWASP LLM categories |
| **Rejected features** | Installing garak into Attestra’s primary Python environment |
| **Integration complexity** | **Medium–high** — image size, probe selection allowlists, JSONL → `NormalizedFinding` |

---

## 8. promptfoo/promptfoo — first-class scanner (remote off)

| Field | Value |
|---|---|
| **Commit / release** | HEAD `696d3ca44b81…`; npm release **0.126.0** |
| **License** | MIT |
| **Runtime** | Node.js engines `^22.22.2 \|\| ^24.15.0 \|\| >=26`; CLI `promptfoo` / `pf` |
| **Main deps** | Large TypeScript app: Express, Drizzle/libsql, OpenAI/Anthropic SDKs, `posthog-node`, Socket.IO, Zod, etc. |
| **Execution model** | Declarative eval + red-team plugins/strategies; local runner with optional Cloud/remote generation |
| **Security boundaries** | **Must** disable hosted features for Attestra runs (not a full network firewall — combine with egress policy): `PROMPTFOO_DISABLE_REMOTE_GENERATION=true`, `PROMPTFOO_DISABLE_TELEMETRY=1`, `PROMPTFOO_DISABLE_SHARING=1`, `PROMPTFOO_DISABLE_UPDATE=1`, and prefer `PROMPTFOO_SELF_HOSTED=1` per Promptfoo offline FAQ. Documented scope: remote-generation disable is not isolation from all network paths |
| **Adopted features** | Red-team plugins/strategies as containerized scanner; importer for JSON/SARIF-style outputs |
| **Rejected features** | Default remote generation; telemetry; sharing; update checks; Promptfoo Cloud sync in product path |
| **Integration complexity** | **Medium** — Node image separate from Python workers; env lockdown; plugin allowlist |

---

## 9. AgentSafeLabs/safelabs-eval — selective adapter/importer

| Field | Value |
|---|---|
| **Commit / release** | HEAD `99655d6d9e18…`; release **v0.12.0** |
| **License** | Apache-2.0 |
| **Runtime** | Python ≥3.11; CLI `safelabs` |
| **Main deps** | Core: `pydantic`, `httpx`, `click`. Optional framework adapters (LangChain, CrewAI, AutoGen, …) and optional LLM judges |
| **Execution model** | 300 ASI01–ASI10 prompts; pattern-based detectors (no LLM required for scoring); HTTP or callable adapters |
| **Security boundaries** | Client-side eval against user-supplied agent endpoint; detectors are heuristic |
| **Adopted features** | Importer/adapter; archive raw responses before verdict (aligns with Attestra evidence hashing); taxonomy mapping **explicitly** to official OWASP Agentic Top 10 (their ASI IDs are **not** the same as OWASP ASI01–ASI10) |
| **Rejected features** | Treating detector verdicts as `confirmed`; shipping as sole agent-security gate |
| **Integration complexity** | **Low–medium** — light deps; validation cap at **`potential`** until human/proof review |

---

## 10. AgentEvalHQ/AgentEval — pytest assertions; no .NET

| Field | Value |
|---|---|
| **Commit / release** | HEAD `ec3e5c660074…`; GitHub latest non-prerelease tag **v0.42.0-beta**; newer **v1.0.0-rc.3** (prerelease). Preview / experimental per README disclaimer |
| **License** | MIT; AEF evidence format under Apache-2.0 |
| **Runtime** | **C# / .NET** (8.0 \| 9.0 \| 10.0); NuGet `AgentEval` |
| **Main deps** | Microsoft Agent Framework / Microsoft.Extensions.AI ecosystem |
| **Execution model** | Fluent assertions on tool chains, workflows, stochastic runs, RAG metrics, red-team probes |
| **Security boundaries** | Evaluation harness for .NET agents; not an Attestra runtime |
| **Adopted features** | Assertion *concepts*: tool called, args, order, identity, duration — expressed as **native pytest** against Attestra AI-agent targets |
| **Rejected features** | Shipping or depending on the .NET toolkit inside Attestra |
| **Integration complexity** | **Low** for pytest ports; **N/A** for binary integration |

---

## Adoption order (Phase guidance)

1. **Garak** + **Promptfoo** — importers then container adapters (customer-visible AI tests; low orchestration risk).
2. **safelabs-eval** — selective importer; status ≤ `potential`.
3. **PyRIT** — isolated worker after adapter SDK path is proven.
4. **Strix / AutoPentest / PentAGI / RedAmon / AgentEval** — design patterns only, as listed.
5. **Shannon** — licence wall; no code path.

Re-pin commit digests and re-read LICENSE/NOTICE before any implementation PR.
