# AASI licence review (Phase 0)

Legal/engineering licence posture for external repositories considered for Attestra Agentic Security Intelligence. Revalidated **2026-11-23** from GitHub SPDX metadata, raw LICENSE/NOTICE/EULA files, and project third-party notices. This is an engineering review for Attestra policy alignment, **not** formal legal advice.

Companion: [`REPOSITORY_ADOPTION_MATRIX.md`](./REPOSITORY_ADOPTION_MATRIX.md). Blueprint: [`AASI_IMPLEMENTATION_BLUEPRINT.md`](./AASI_IMPLEMENTATION_BLUEPRINT.md).

## Attestra policy constraints (working rules)

1. **Do not copy or link AGPL/GPL code into Attestra** in a way that would impose copyleft on the product. Prefer Apache-2.0 / MIT / BSD for libraries; run copyleft tools only as **separate digest-pinned containers** with clear process boundaries when product policy already allows that pattern for existing scanners.
2. **Shannon (AGPL-3.0) is prohibited for code reuse** — no vendoring, no forking into the Attestra tree, no linking, no “inspired” patches that copy Shannon source.
3. **Agent runtimes that hand the LLM a shell, arbitrary filesystem, or unrestricted MCP tool plane are not adopted as runtimes**, regardless of permissive licence (Strix Apache-2.0, AutoPentest Apache-2.0, PentAGI MIT, RedAmon MIT).
4. **Third-party tool licences inside someone else’s Docker image are not cleared** by that project’s top-level MIT/Apache licence. RedAmon’s `THIRD-PARTY-LICENSES.md` is the canonical example.
5. Re-check HEAD and LICENSE on every adoption PR; SHAs in this file age quickly.

---

## Decision matrix

| Repository | SPDX / declared | Extra terms | Attestra decision | Code reuse? | Notes / blockers |
|---|---|---|---|---|---|
| **usestrix/strix** | Apache-2.0 | — | Architecture reference | **No** (policy: no shell runtime) | Permissive licence; rejected for *execution* adoption, not licence |
| **KeygraphHQ/shannon** | **AGPL-3.0** | Network copyleft (AGPL §13) | **NO code reuse** | **Prohibited** | **Hard blocker** for any source incorporation |
| **vxcontrol/pentagi** | MIT | **EULA.md** + `NOTICE` (Cloud SDK **AGPL-3.0** + project exception) | Design reference only | **No** | MIT covers source; EULA and AGPL SDK make product reuse unsafe |
| **bhavsec/autopentest-ai** | Apache-2.0 | — | Selective architecture reference | **No** wholesale copy; patterns OK | Tool images still need per-tool review if ever reused |
| **samugit83/redamon** | MIT | Bundled **AGPL** tools (nuclei, naabu, httpx, …); other commercial restrictions (e.g. WPScan) | Selective architecture reference | **No** to bundling their tool images | Graph *ideas* OK; do not inherit their sandbox licence set |
| **microsoft/PyRIT** | MIT | Third-party notices / LICENSES tree | Isolated container later | Container/binary boundary only | Do not merge heavy dep tree into Attestra venv |
| **NVIDIA/garak** | Apache-2.0 | — | First-class scanner (container) | Via pinned image + importer | Apache-compatible; isolate `torch` stack |
| **promptfoo/promptfoo** | MIT | Hosted remote generation / telemetry / sharing by default | First-class scanner (container) | Via pinned image + importer | Licence OK; **operational** requirement to disable remote/telemetry/sharing/updates |
| **AgentSafeLabs/safelabs-eval** | Apache-2.0 | Prompt corpus provenance docs | Selective adapter/importer | Adapter/importer OK | Cap findings ≤ `potential` (quality, not licence) |
| **AgentEvalHQ/AgentEval** | MIT (AEF Apache-2.0) | Preview disclaimer | pytest concepts only | **No .NET dependency** | Licence OK; wrong runtime for Attestra |

---

## Prohibited: Shannon AGPL-3.0

**Repository:** https://github.com/KeygraphHQ/shannon  
**Verified:** raw `LICENSE` is the full GNU Affero General Public License v3.0; GitHub API SPDX `AGPL-3.0`; README editions table states OSS is “Open source under AGPL-3.0”.  
**HEAD reviewed:** `d72c082dc873273cb99ea53bdec1c582c2493753` (v3.6.1 announced).

### Why this is a hard blocker

- AGPL is a strong copyleft. Conveying a modified version (or, for network software, interacting with a modified version over a network) triggers source-disclosure obligations that conflict with Attestra’s commercial/product distribution model.
- “Using ideas” is fine; **copying Shannon code, prompts-as-code, worker harness structure, or SARIF emitters from Shannon into Attestra is not**.
- The product rule “no exploit, no report” may be **restated** using Attestra’s existing validation classes (`confirmed` only with proof + human review). That restatement must be original Attestra text and logic.

### Allowed vs forbidden

| Allowed | Forbidden |
|---|---|
| Reading Shannon docs/README for methodology comparison | Vendoring Shannon source into `attestra/` |
| Citing Shannon publicly as prior art in docs | Linking Attestra against Shannon packages |
| Implementing Attestra-native “proof required” gates | Forking Shannon into an Attestra submodule “for reference” that ships |
| | Shipping Shannon worker images as part of Attestra without separate legal clearance (still AGPL) |

---

## Permissive but still non-adoptable as runtimes

These projects are **not** blocked solely by SPDX, but Attestra rejects their **execution models**:

### Strix (Apache-2.0)

Agents receive shell, filesystem, browser, and exploit runtimes inside Docker. That breaks Attestra’s registered-tools-only / no-LLM-shell rule. Licence would allow reference implementation of reporting/coverage patterns; runtime adoption is a **security architecture** rejection.

### AutoPentest AI (Apache-2.0)

MCP server + Docker CLI tools + role agents. Patterns (task tree, endpoint priority, tool verification) are reusable as Attestra-native code. Do not adopt the MCP execution plane or WAF-evasion module.

### PentAGI (MIT + EULA + AGPL Cloud SDK notice)

- `LICENSE`: MIT.  
- `EULA.md`: additional end-user terms for source, Docker images, and UI; authorized-testing only; states MIT prevails for source on conflict, but EULA still constrains product use/distribution expectations.  
- `NOTICE`: VXControl Cloud SDK under **AGPL-3.0** with a special exception for the official PentAGI project — **that exception does not clear Attestra**.  

**Decision:** design reference only; no Cloud SDK; no shipping PentAGI.

### RedAmon (MIT + third-party AGPL/commercial)

Top-level MIT does **not** relicense ProjectDiscovery AGPL tools bundled or pulled at runtime. Attestra already has its own scanner adapter path; do not import RedAmon’s Kali/AGPL image set. Attack-graph schema ideas may be implemented on MongoDB with Attestra provenance labels.

### AgentEval (MIT)

Permissive, but the product is **.NET**. Attestra ports assertion *concepts* to pytest. No NuGet dependency.

---

## Adopted scanners — licence OK with isolation conditions

### Garak (Apache-2.0)

Compatible with Attestra. **Condition:** run as digest-pinned container; do not install `torch`/`transformers` into the core app environment. Importer consumes JSONL; runner uses `AdapterMeta` + `docker_run_argv`.

### Promptfoo (MIT)

Compatible. **Conditions (operational, not SPDX):**

Required env lockdown for Attestra-managed runs (per Promptfoo docs/FAQ; not a substitute for egress controls):

```text
PROMPTFOO_DISABLE_REMOTE_GENERATION=true
PROMPTFOO_DISABLE_TELEMETRY=1
PROMPTFOO_DISABLE_SHARING=1
PROMPTFOO_DISABLE_UPDATE=1
PROMPTFOO_SELF_HOSTED=1
```

Promptfoo documents that disabling remote generation is **not** a network isolation guarantee. Attestra must still pin the image, control egress, and treat Cloud/login paths as out of scope for the product worker.

### PyRIT (MIT)

Compatible for **later** isolated worker. **Condition:** never a core dependency (large Azure/`transformers`/`fastapi` surface). Importer + container only.

### safelabs-eval (Apache-2.0)

Compatible for selective adapter/importer. **Condition:** map their OWASP-*inspired* ASI01–ASI10 IDs carefully (they are **not** the official OWASP Agentic Top 10 2026 IDs). Engineering policy: imported detector hits max validation **`potential`** until stronger evidence/human confirmation.

---

## Blockers summary

| Severity | Item | Impact |
|---|---|---|
| **Hard** | Shannon **AGPL-3.0** | No code reuse, no linked worker derived from Shannon source |
| **Hard** | LLM unrestricted shell / MCP runtimes (Strix, AutoPentest, PentAGI, RedAmon agents) | Architecture rejection even when SPDX is permissive |
| **Hard** | PentAGI Cloud SDK AGPL + EULA | Design-only; no SDK |
| **High** | RedAmon bundled AGPL/commercial tools | Do not reuse their tool images without per-component clearance |
| **High** | Promptfoo default remote generation / telemetry / sharing | Must disable; verify in adapter contract tests |
| **Medium** | PyRIT / Garak dependency weight | Container isolation mandatory |
| **Medium** | AgentEval .NET stack | Concepts only; no runtime |
| **Process** | Fast-moving HEADs (Promptfoo, Strix, PyRIT) | Re-pin digests every implementation PR |

---

## Verification log (2026-11-23)

| Repo | Evidence used |
|---|---|
| All ten | `GET /repos/{owner}/{repo}` (licence SPDX, default branch); `GET /repos/.../commits/{branch}` (HEAD SHA); `GET /repos/.../releases?per_page=3` |
| Shannon | Raw `LICENSE` = AGPL-3.0 text; README editions table |
| PentAGI | Raw `LICENSE` (MIT), `EULA.md`, `NOTICE` |
| RedAmon | Raw `LICENSE` (MIT), `THIRD-PARTY-LICENSES.md` (AGPL tool table), `VERSION` 7.9.0 |
| Strix / Garak / PyRIT / safelabs-eval | Raw `pyproject.toml` licence + dependencies |
| Promptfoo | `package.json` licence MIT, engines Node 22+; public docs for disable flags |
| AgentEval | Raw `LICENSE` MIT; `/releases/latest` → `v0.42.0-beta`; prereleases through `v1.0.0-rc.3` |
| AutoPentest | Raw `LICENSE` Apache-2.0; `server/pyproject.toml` |

Pages that partially failed during HTML fetch (GitHub UI “Latest commit” blank in markdown conversion) were **overridden by GitHub API** for SHAs and release tags. PentAGI README HTML fetch returned truncated base64 API payload; licence conclusions rely on `LICENSE` / `EULA.md` / `NOTICE`, not the full README body.
