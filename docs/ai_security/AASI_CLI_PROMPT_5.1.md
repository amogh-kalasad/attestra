# ATTESTRA AASI — MASTER ENGINEERING IMPLEMENTATION DIRECTIVE

## VERSION 5.1 — SINGLE GLOBAL VIRTUAL ENVIRONMENT | DOCKER-FREE AI SCANNERS | COMPLETE END-TO-END IMPLEMENTATION

**PROJECT:** Attestra  
**FEATURE:** Attestra Agentic Security Intelligence (AASI)  
**IMPLEMENTATION MODE:** Complete sequential repository implementation  
**SOURCE:** `attestra-attestra-asi-bundle.zip`  
**PREVIOUS DIRECTIVE:** Attestra AASI CLI Prompt 4.0  
**SUPERSEDING DIRECTIVE:** Attestra AASI CLI Prompt 5.1  
**PRIMARY EXECUTION REQUIREMENT:** All four AI scanners must execute natively without Docker.  
**DEPENDENCY REQUIREMENT:** Exactly ONE shared Python virtual environment for Attestra and all Python AI scanner dependencies.  
**ADDITIONAL REQUIREMENT:** Promptfoo's Node.js runtime and npm dependencies must be installed under the same shared environment root.  
**PROHIBITED:** Separate scanner virtual environments and Docker scanner image pulls.

---

# 1. YOUR ROLE AND REPOSITORY OWNERSHIP

Act as the principal owner and engineering authority of the existing Attestra repository.

Assume responsibility equivalent to:

- Principal Software Architect.
- Principal Python Backend Engineer.
- AI Security Architect.
- Senior Agentic AI Engineer.
- DevSecOps Architect.
- MongoDB Engineer.
- Application Security Specialist.
- Software Supply Chain Security Engineer.
- Production Release Engineer.

You are responsible for the complete implementation of AASI inside the existing Attestra application.

This is an existing enterprise security platform.

You must extend its actual source code.

Do not create a replacement platform.

Do not create a parallel scanner architecture.

Do not produce an architecture-only response.

Do not stop after creating an MVP.

Do not leave required functionality as TODOs.

Your responsibility is to inspect, implement, integrate, test, secure, document and deployment-validate the entire approved implementation.

**Act as the owner of the repository. Protect existing functionality, data, architecture and customer security.**

# 2. AUTHORITATIVE INPUTS AND PRECEDENCE

Use these exact inputs:

1. `attestra-attestra-asi-bundle.zip` — actual source repository.
2. `Attestra CLI Prompt 4.0.txt` — previous implementation directive.
3. `AGENTS.md` — repository engineering rules.
4. `docs/ai_security/AASI_IMPLEMENTATION_BLUEPRINT.md`.
5. Existing `docs/` architecture, reporting and implementation documents.
6. `lat.md/` knowledge graph.
7. Existing source code and tests.
8. Official upstream repositories and documentation for the four scanner frameworks.

Precedence:

ACTUAL SOURCE CODE  
> `AGENTS.md`  
> Latest user-approved V5.1 requirements  
> AASI implementation blueprint  
> Prompt 4.0  
> Older assumptions and generated documentation.

The latest V5.1 requirements supersede all conflicting earlier instructions concerning:

- Docker-based AI scanner execution.
- Separate scanner virtual environments.
- Scanner dependency installation.
- Scanner runtime layout.
- AI scanner deployment.
- AI scanner image-pull configuration.

Preserve all other valid architectural and security requirements from Prompt 4.0.

When the source and documentation disagree:

1. Inspect the actual source.
2. Establish the real runtime behavior.
3. Record the discrepancy.
4. Preserve working behavior.
5. Correct the implementation.
6. Update documentation.
7. Add regression tests.

Do not silently ignore discrepancies.

# 3. THREE ABSOLUTE NON-NEGOTIABLE REQUIREMENTS

## 3.1 Requirement A — Zero Docker for AI scanners

All four AI scanners must execute natively.

The following are strictly prohibited for Garak, Promptfoo, SafeLabs and PyRIT:

- `docker pull`.
- `docker image pull`.
- `docker run`.
- `docker create`.
- Docker scanner workers.
- Docker scanner containers.
- Docker image dependencies.
- Docker image digest configuration.
- Docker fallback.
- Docker-based health checks.
- Docker-based installation scripts.

Do not replace Docker with Podman or another container runtime.

Do not introduce an alternative container execution architecture.

If a native scanner dependency is unavailable, return an explicit unavailable status.

Never fall back to Docker.

## 3.2 Requirement B — Exactly one shared Python virtual environment

This is a strict dependency-management requirement.

There must be exactly ONE shared Python virtual environment for the Attestra application and all Python AI scanner dependencies.

The following must use the same Python environment:

- Attestra core application.
- Attestra API.
- Attestra workers.
- Garak.
- SafeLabs Eval.
- Microsoft PyRIT.
- AASI Python orchestration.
- Native scanner support libraries.
- Required Python scanner dependencies.

Do not create:

- A Garak virtual environment.
- A SafeLabs virtual environment.
- A PyRIT virtual environment.
- An AASI virtual environment.
- A separate scanner worker virtual environment.
- A second application virtual environment.
- Per-scanner Python environments.

Do not install Python scanner dependencies globally using system `pip`.

Do not use `pip install --user`.

Do not allow different workers to use different Python environments.

All Python installations must use the one shared environment.

The shared environment must be used consistently by:

- Installation scripts.
- API processes.
- Background workers.
- Scanner execution.
- Health checks.
- CLI commands.
- Scheduled jobs.
- Production startup scripts.
- Tests.

## 3.3 Requirement C — All scanner installations under one shared environment root

Promptfoo is a Node.js application, not a Python package.

Do not incorrectly attempt to install Promptfoo using pip or place it in `requirements.txt` as though it were a Python distribution.

Instead, use the same shared environment root for its Node.js runtime and npm dependencies.

The Node.js runtime must be installed under the shared root.

The Promptfoo npm package must also be installed under the shared root.

Do not install Promptfoo into a separate Docker image.

Do not create another Python virtual environment for Promptfoo.

The implementation must maintain one managed installation root and one Python virtual environment.

# 4. REQUIRED SINGLE-ENVIRONMENT ARCHITECTURE

Use one configurable shared environment root.

Suggested configuration:

```text
ATTESTRA_SHARED_ENV_ROOT=/opt/attestra/runtime
```

The required logical layout is:

```text
/opt/attestra/runtime/
│
├── venv/
│   ├── bin/
│   ├── lib/
│   ├── include/
│   └── pyvenv.cfg
│
├── tools/
│   └── node/
│       ├── bin/
│       │   ├── node
│       │   └── npm
│       └── ...
│
├── npm/
│   ├── node_modules/
│   │   └── promptfoo/
│   ├── package.json
│   ├── package-lock.json
│   └── bin/
│       └── promptfoo
│
├── manifests/
│   ├── python-runtime.json
│   ├── garak.json
│   ├── safelabs.json
│   ├── pyrit.json
│   └── promptfoo.json
│
├── logs/
│
├── cache/
│
└── tmp/
```

This is one shared managed installation root.

It contains:

- Exactly one Python virtual environment.
- One Node.js runtime.
- One npm installation prefix.
- Shared runtime manifests.
- Shared controlled temporary and cache locations.

The `tools/node` directory is a native Node.js runtime, not another Python virtual environment.

The `npm` directory is the npm installation prefix, not another virtual environment.

Do not create additional `venv/` directories anywhere for the four scanners.

The environment root must be configurable, but all processes must resolve the same configured root.

## 4.1 Global means application-wide

The shared environment must not be recreated for each:

- User.
- Tenant.
- Engagement.
- Assessment.
- Scanner.
- Worker.
- Job.

It must be a single installation shared by the Attestra deployment.

Scanner jobs may have separate temporary workspaces and report directories.

These are not separate virtual environments.

## 4.2 Permissions

The shared environment must have appropriate service ownership.

Use:

- A dedicated Attestra service account.
- Controlled write permissions during installation and upgrades.
- Read/execute permissions for runtime execution.
- Restricted temporary directories.
- No unnecessary root execution.

Do not make the environment writable by arbitrary scanner jobs.

Do not allow a scanner process to modify its own executable or installed packages.

# 5. SOURCE-CODE BASELINE

Read `AGENTS.md` first.

Inspect the actual repository root.

Inspect Git status.

Preserve all existing changes.

Do not delete `.bak_*` files without explicit authorization.

Inspect existing backups and determine their relevance.

Inspect:

- `pyproject.toml`.
- `requirements.txt`.
- `.env.example`.
- `.env.production.example`.
- `.gitignore`.
- `.dockerignore`.
- `Dockerfile`.
- `compose.yaml`.
- `attestra/`.
- `tests/`.
- `docs/`.
- `lat.md/`.

## 5.1 Important existing source paths

| Responsibility | Source |
|---|---|
| Database | `attestra/db.py` |
| Mongo collections | `attestra/persistence/mongo/collections.py` |
| Mongo migrations | `attestra/persistence/mongo/migrations/__init__.py` |
| Tenant isolation | `attestra/persistence/mongo/tenant.py` |
| Scanner base | `attestra/runner/scanners/base.py` |
| Scanner SDK | `attestra/runner/scanners/sdk.py` |
| Scanner registry | `attestra/runner/scanners/registry.py` |
| Authorization | `attestra/runner/authorization.py` |
| DNS pinning | `attestra/runner/dns_pin.py` |
| Garak adapter | `attestra/runner/scanners/garak.py` |
| Promptfoo adapter | `attestra/runner/scanners/promptfoo.py` |
| SafeLabs adapter | `attestra/runner/scanners/safelabs.py` |
| PyRIT adapter | `attestra/runner/scanners/pyrit.py` |
| Importer base | `attestra/importers/base.py` |
| Importer registry | `attestra/importers/__init__.py` |
| Garak importer | `attestra/importers/garak.py` |
| Promptfoo importer | `attestra/importers/promptfoo.py` |
| SafeLabs importer | `attestra/importers/safelabs.py` |
| PyRIT importer | `attestra/importers/pyrit.py` |
| AASI contracts | `attestra/aasi/contracts.py` |
| AASI context | `attestra/aasi/context.py` |
| AASI provider | `attestra/aasi/provider.py` |
| AASI orchestrator | `attestra/aasi/orchestrator.py` |
| AASI roles | `attestra/aasi/roles.py` |
| AASI store | `attestra/aasi/store.py` |
| Evidence gate | `attestra/aasi/evidence_gate.py` |
| Graph | `attestra/aasi/graph.py` |
| Task tree | `attestra/aasi/task_tree.py` |
| Coverage | `attestra/automated_vapt/coverage/ledger.py` |
| Planner | `attestra/automated_vapt/core/planner.py` |
| Finding validation | `attestra/finding_validation/statuses.py` |
| Reporting | `attestra/reports/render.py` |
| Configuration | `attestra/config.py` |
| Existing PyRIT worker | `docker/aasi/pyrit_worker/` |

These are inspection targets, not assumptions about completeness.

Inspect all runtime call paths.

# 6. DEPENDENCY MANAGEMENT — SINGLE ENVIRONMENT ONLY

This section overrides all earlier scanner dependency isolation instructions.

## 6.1 Authoritative dependency source

Inspect:

- `pyproject.toml`.
- `requirements.txt`.
- Existing development extras.
- Existing packaging and installation scripts.

The project currently identifies `pyproject.toml` as its dependency definition and describes `requirements.txt` as synchronized with the project dependencies.

Preserve that consistency.

Do not introduce divergent dependency inventories.

## 6.2 Required Python packages

The shared Python environment must contain the dependencies needed by:

- Attestra.
- Garak.
- SafeLabs Eval.
- PyRIT.
- AASI.

Investigate the actual official package distributions and compatible dependency versions.

Do not guess package names.

Do not guess package versions.

Do not assume the latest release is compatible with Attestra.

Do not install the full framework dependencies into a second environment.

## 6.3 Update pyproject.toml

Add the required AI scanner Python dependencies to the project dependency configuration.

Use a clearly documented dependency group or optional extra if it is consistent with the existing project design.

For example:

```toml
[project.optional-dependencies]
ai-scanners = [
    # Add actual verified package distributions and compatible pinned versions.
]
```

Do not insert guessed versions.

Inspect the actual PyPI package metadata and official source repositories before choosing versions.

The installation process must install the AI scanner dependencies into the same shared Attestra Python virtual environment.

If the existing application requires the scanner dependencies to be available by default, configure the installation path accordingly.

Do not create another virtual environment for the optional group.

## 6.4 Update requirements.txt

Update `requirements.txt` to reflect the approved scanner dependencies.

Include actual Python package distributions for:

- Garak.
- SafeLabs Eval.
- PyRIT.

Include compatible dependency constraints.

Keep the file consistent with the authoritative `pyproject.toml`.

Do not manually introduce a second conflicting dependency source.

Do not add Promptfoo as a Python requirement.

Promptfoo is installed through npm.

Document that distinction clearly in `requirements.txt`.

The installation command must install all required Python dependencies into the one shared virtual environment.

Example installation pattern:

```bash
source /opt/attestra/runtime/venv/bin/activate

python -m pip install --upgrade pip

python -m pip install -r requirements.txt
```

If the project uses an editable package installation, preserve that workflow:

```bash
python -m pip install -e ".[dev,ai-scanners]"
```

Use the actual final extras and dependency strategy established after inspecting the project.

## 6.5 Dependency conflict resolution

Because all Python frameworks share one environment, dependency compatibility is mandatory.

Perform a complete resolution of:

- Attestra core dependencies.
- Garak dependencies.
- SafeLabs dependencies.
- PyRIT dependencies.
- Existing optional dependencies.
- Test dependencies.

Use:

- Package metadata.
- Official release requirements.
- Python compatibility.
- Transitive dependency constraints.
- Security advisories.
- License compatibility.

Do not solve conflicts by creating another virtual environment.

Do not silently downgrade critical Attestra dependencies.

Do not silently replace framework functionality.

If a conflict exists:

1. Identify the conflicting packages.
2. Identify the affected versions.
3. Inspect supported upstream compatibility.
4. Select a compatible supported release.
5. Run the full regression suite.
6. Record the resolution.

If no compatible combination exists, document the exact blocker. Do not claim a fully working shared environment.

## 6.6 Dependency lock and reproducibility

Generate a reproducible dependency lock or constraints mechanism compatible with the repository's packaging strategy.

Record:

- Exact package versions.
- Source.
- License.
- Python compatibility.
- Dependency relationships.
- Hashes where supported.

The environment must be reproducible on a clean supported host.

Do not use unbounded dependency upgrades in production installation.

# 7. PROMPTFOO — NODE.JS UNDER THE SAME SHARED ENVIRONMENT ROOT

Promptfoo cannot be installed through Python requirements.

Implement its native Node.js runtime under:

```text
ATTESTRA_SHARED_ENV_ROOT/tools/node/
```

Install its npm dependencies under:

```text
ATTESTRA_SHARED_ENV_ROOT/npm/
```

Use an exact supported Node.js version.

Use an exact Promptfoo version.

Use a committed or reproducibly generated:

- `package.json`.
- `package-lock.json`.

Do not use an additional Python virtual environment.

Do not install Promptfoo into the system-wide npm prefix.

Do not use arbitrary global developer installations.

Do not use `npx` to download the latest version at scanner execution time.

The runtime manager must resolve:

- Node executable.
- npm executable.
- Promptfoo executable.
- Promptfoo package version.

All must resolve beneath the shared environment root.

The only allowed exception to the shared Python venv is the native Node.js executable itself, which is not a Python package. It must still reside under the same shared root.

# 8. SINGLE ENVIRONMENT INSTALLATION MANAGER

Implement a central environment manager.

Suggested location:

```text
attestra/
    scanner_runtime/
        __init__.py
        environment.py
        dependency_check.py
        health.py
        process.py
        versions.py
        manifest.py
```

Adjust this location if an equivalent existing implementation is already available.

Do not duplicate existing code.

Responsibilities:

### environment.py

- Resolve the shared environment root.
- Resolve the single Python interpreter.
- Resolve the shared Node runtime.
- Resolve the shared npm prefix.
- Validate environment paths.
- Reject unexpected per-scanner virtual environments.

### dependency_check.py

- Check installed Python packages.
- Check framework versions.
- Check dependency compatibility.
- Check Node version.
- Check npm version.
- Check Promptfoo version.
- Detect missing packages.
- Detect incompatible packages.

### health.py

- Check the shared environment.
- Check all four scanners.
- Verify executable paths.
- Verify framework versions.
- Verify dependency integrity.
- Verify sandbox readiness.
- Verify target egress readiness.

### process.py

- Use the existing process execution infrastructure.
- Execute native commands.
- Enforce timeouts.
- Enforce cancellation.
- Preserve process isolation controls.

### versions.py

- Maintain supported framework versions.
- Validate actual installed versions.
- Prevent unapproved runtime drift.

### manifest.py

Maintain one installation manifest for the shared environment and scanner-specific metadata records.

Do not interpret separate JSON manifests as separate environments.

# 9. SHARED ENVIRONMENT EXECUTION POLICY

All Python scanner execution must use:

```text
ATTESTRA_SHARED_ENV_ROOT/venv/bin/python
```

All Python package checks must use:

```bash
/path/to/shared/venv/bin/python -m pip check
```

All Python framework commands must resolve to the same environment.

Do not use:

- System Python.
- Developer Python.
- Per-scanner interpreters.
- Per-worker interpreters.
- Another venv.
- `pip install --user`.

For Promptfoo, use the Node executable and Promptfoo CLI under the same shared environment root.

Do not use an unrelated system-global Promptfoo executable.

## 9.1 Runtime verification

At startup, record:

- Shared environment root.
- Python executable.
- Python version.
- Installed package versions.
- Node executable.
- Node version.
- npm version.
- Promptfoo version.

Do not expose sensitive environment variables.

## 9.2 Runtime failure

If the shared environment is missing or invalid:

- Mark the affected scanner unavailable.
- Produce an actionable diagnostic.
- Do not execute through another Python installation.
- Do not create a replacement venv automatically during a scan.
- Do not fall back to Docker.

# 10. GARAK — NATIVE EXECUTION

Official repository:

`https://github.com/NVIDIA/garak`

Existing adapter:

`attestra/runner/scanners/garak.py`

Existing importer:

`attestra/importers/garak.py`

Inspect official documentation and the exact pinned release.

Verify:

- License.
- Package distribution.
- Python support.
- Dependencies.
- CLI interface.
- REST generator configuration.
- Output schema.
- Probe structure.
- Detector structure.

Install Garak into the single shared Python environment.

Use:

```text
ATTESTRA_SHARED_ENV_ROOT/venv/bin/python
```

Do not create a Garak venv.

Implement:

- Native execution.
- Fixed arguments.
- Authorized target.
- Existing `PinnedTarget`.
- DNS-pinned target access.
- Structured JSONL output.
- Timeouts.
- Cancellation.
- Resource controls.
- Evidence preservation.
- Version verification.

Use actual Garak-supported configuration.

Do not invent CLI options.

## Garak importer

Preserve:

- Attempt records.
- Eval records.
- Probe identifiers.
- Detector results.
- Attempt references.
- Original record identifiers.
- Tool version.
- Evidence references.

A probe execution alone is not a finding.

A qualifying detector result may become `potential`.

Malformed, failed or empty output must not become a pass.

# 11. PROMPTFOO — NATIVE NODE EXECUTION

Official repository:

`https://github.com/promptfoo/promptfoo`

Existing adapter:

`attestra/runner/scanners/promptfoo.py`

Existing importer:

`attestra/importers/promptfoo.py`

Use the Node.js runtime under the shared environment root.

Use the npm package installation under the shared environment root.

Implement:

- Fixed CLI arguments.
- Authorized target.
- Native execution.
- Validated configuration.
- Local report output.
- Version verification.
- Timeout.
- Cancellation.
- Evidence preservation.

## 11.1 Privacy and network controls

Verify the actual supported settings for the pinned release.

Preserve the required restrictions:

- Remote generation disabled.
- Telemetry disabled.
- Sharing disabled.
- Automatic updates disabled.
- Unapproved remote judges disabled.
- Unauthorized provider egress disabled.

Use actual supported Promptfoo configuration.

Do not assume a documented environment variable is sufficient network isolation.

Implement network controls separately.

## 11.2 Importer

Preserve:

- Evaluation identifiers.
- Test-case references.
- Plugin identifiers.
- Strategy identifiers.
- Assertion results.
- Target metadata.
- Tool version.
- Original record IDs.
- Evidence provenance.

Failed security assertions are potential findings, not automatically confirmed findings.

# 12. SAFELABS EVAL — NATIVE PYTHON EXECUTION

Official repository:

`https://github.com/AgentSafeLabs/safelabs-eval`

Existing adapter:

`attestra/runner/scanners/safelabs.py`

Existing importer:

`attestra/importers/safelabs.py`

Install SafeLabs into the same shared Python environment.

Do not create a separate SafeLabs venv.

Verify:

- Official package distribution.
- Release.
- License.
- Python compatibility.
- CLI.
- API.
- Output schema.

Use actual supported execution methods.

Preserve:

- Test identifiers.
- Detector information.
- Evidence.
- Score.
- Uncertainty.
- Taxonomy source.
- Tool version.

SafeLabs heuristic findings must never automatically become confirmed.

Do not incorrectly label framework-specific ASI categories as the official OWASP Agentic Applications taxonomy.

# 13. PYRIT — GENUINE FRAMEWORK EXECUTION

Official repository:

`https://github.com/microsoft/PyRIT`

Existing adapter:

`attestra/runner/scanners/pyrit.py`

Existing importer:

`attestra/importers/pyrit.py`

Existing worker:

`docker/aasi/pyrit_worker/`

Inspect the existing worker.

Do not simply move its current HTTP probe implementation and claim genuine PyRIT integration.

The existing worker contains handcrafted HTTP probes and simple response-marker detection. This is not equivalent to executing the actual PyRIT framework.

Install PyRIT into the single shared Python environment.

Do not create a separate PyRIT venv.

Use the shared Python interpreter.

Inspect the exact PyRIT release and its actual supported APIs.

Implement actual framework-backed scenarios:

- Crescendo.
- PAIR.
- Tree of Attacks.
- Red Teaming.
- Many-shot jailbreak.

Only expose scenarios actually supported by the pinned release.

Do not invent class names or methods.

Preserve:

- Conversation references.
- Transcript evidence.
- Usage.
- Cost where provided.
- Scenario identifiers.
- Target references.
- Structured output.
- Timeout.
- Cancellation.
- Recovery.

Third-party judge egress must remain disabled unless explicitly authorized.

Acceptance must prove actual PyRIT framework execution, not merely HTTP requests made by custom code.

# 14. EXISTING SCANNER SDK AND EXECUTION ENGINE

Inspect:

- `attestra/runner/scanners/base.py`
- `attestra/runner/scanners/sdk.py`
- `attestra/runner/scanners/registry.py`

Preserve:

- `AdapterMeta`.
- `ScannerAdapter`.
- `ScannerResult`.
- Safety tiers.
- Resource profiles.
- Health checks.
- Contract validation.
- Existing process execution.
- Existing authorization.

The four AI adapters must be explicitly native-only.

Remove their dependency on:

- `ATTESTRA_IMAGE_GARAK`.
- `ATTESTRA_IMAGE_PROMPTFOO`.
- `ATTESTRA_IMAGE_SAFELABS`.
- `ATTESTRA_IMAGE_PYRIT`.
- Docker image configuration.
- Docker entrypoints.
- Docker mounts.
- Docker argv.

Do not globally remove Docker support for unrelated scanners.

The AI adapters must use the shared runtime manager.

## 14.1 No shell execution

Never use:

```python
shell=True
```

Never accept arbitrary agent-generated commands.

Use fixed argument arrays.

Use the existing `run_process()` implementation wherever possible.

Implement:

- Timeouts.
- Cancellation.
- Process-tree termination.
- Output limits.
- Resource restrictions.
- Sanitized environment.
- Correct exit-code handling.
- Structured output validation.

# 15. NATIVE NETWORK AND PROCESS SECURITY

A shared venv does not provide process isolation.

A shared venv does not provide network isolation.

A shared venv does not protect Attestra secrets from malicious scanner code.

Removing Docker must not weaken the security architecture.

Implement and verify host-level controls.

## 15.1 Target authorization

Preserve:

- Existing engagement authorization.
- Existing asset authorization.
- Existing `PinnedTarget`.
- Existing DNS pinning.
- Existing safety tiers.
- Existing intrusive policy.

Do not allow a scanner to test a target merely because an agent recommends it.

## 15.2 Network egress

Implement a verified target-bound network boundary.

Investigate the actual network behavior of all four frameworks.

Use an enforceable controlled egress mechanism.

Requirements:

- Authorized hostname.
- Authorized IP.
- Authorized port.
- TLS SNI correctness.
- HTTP Host correctness.
- Redirect validation.
- DNS rebinding protection.
- Private network restrictions.
- Cloud metadata protection.
- No unauthorized third-party judge.
- No unrestricted DNS resolution.

Do not assume HTTP proxy variables alone provide complete enforcement.

If the target-bound egress boundary cannot be established, do not run the scanner.

Fail closed.

## 15.3 Process security

Use:

- Dedicated service account.
- Restricted permissions.
- Controlled working directories.
- Private temporary storage.
- CPU limits.
- Memory limits.
- Process limits.
- Timeout.
- Cancellation.
- Restricted environment.
- No application signing-key access.
- No unnecessary MongoDB credential access.
- No unrestricted application filesystem access.

Because all scanners share the same Python installation, do not allow a scanner job to install or modify packages.

Make the installed environment read-only during execution.

Perform package upgrades only through an authorized maintenance operation.

# 16. IMPORTERS AND EVIDENCE

Reuse the existing importer registry.

Reuse the existing evidence pipeline.

Persist raw output before parsing.

Preserve:

- Original bytes.
- SHA-256.
- Tenant.
- Engagement.
- Asset.
- Scanner.
- Tool version.
- Run ID.
- Original result identifiers.
- Evidence references.

Quarantine malformed reports.

Do not silently discard invalid output.

Reuse:

`attestra/finding_validation/statuses.py`

Finding mapping:

| Result | Classification |
|---|---|
| Garak qualifying detector hit | potential |
| Promptfoo failed security assertion | potential |
| SafeLabs heuristic hit | potential |
| Uncertain detector | needs_manual_validation |
| Conflicting judge | needs_manual_validation |
| Successful execution without finding | assessed with no issue |
| Failed execution | NOT_TESTED |
| Refused execution | NOT_TESTED |
| Rate limited | NOT_TESTED |
| Empty or invalid report | NOT_TESTED |
| Human-reviewed reproducible proof | confirmed |
| Reviewer rejection | false_positive |
| Failed replay | not_reproducible |

Never treat an LLM confidence score as validation status.

# 17. AASI ORCHESTRATION

Inspect the existing `attestra/aasi/` implementation.

Preserve and complete:

- Contracts.
- Context.
- Provider.
- Budget.
- Store.
- Orchestrator.
- Roles.
- Routes.
- Evidence gate.
- Task tree.
- Graph.
- Prioritization.

Five logical roles:

1. Strategist.
2. Hypothesis.
3. AI-security specialist.
4. Evidence reviewer.
5. Quality reviewer.

Use one bounded orchestration engine.

Agents must not:

- Execute shell commands.
- Invoke arbitrary Python.
- Directly execute scanners.
- Modify the shared environment.
- Install dependencies.
- Change authorization.
- Expand scope.
- Approve their own recommendations.

Agents only recommend registered tests.

Reuse the authoritative Attestra planner.

Preserve:

`ATTESTRA_AASI=off`

AASI must remain disabled by default.

Preserve existing tenant AI restrictions and `ATTESTRA_AI_TENANTS_OFF`.

# 18. MONGODB AND PERSISTENCE

MongoDB remains the authoritative persistence system.

Inspect:

- `attestra/db.py`.
- `attestra/persistence/mongo/collections.py`.
- `attestra/persistence/mongo/tenant.py`.
- `attestra/persistence/mongo/migrations/__init__.py`.
- `attestra/aasi/store.py`.

Reuse existing collections.

Preserve:

- `aasi_runs`.
- `aasi_decisions`.
- `aasi_graph_nodes`.
- `aasi_graph_edges`.

Do not introduce another database.

Implement tenant isolation, indexes, migrations, idempotency, retention, audit and recovery.

Do not store raw chain-of-thought.

# 19. COVERAGE AND COMPLIANCE

Reuse:

- Existing coverage ledger.
- Existing run validity.
- Existing compliance implementation.
- Existing ISO 42001 integration.

Preserve:

`origin = catalogue | aasi`

Map only source-supported taxonomy references.

Support:

- OWASP LLM Top 10.
- Official OWASP Agentic Applications taxonomy.
- CWE.
- ISO 42001.
- Garak.
- Promptfoo.
- SafeLabs.
- PyRIT.

Do not invent compliance coverage.

Missing evidence is not a pass.

# 20. REPORTING

Extend the existing report renderer.

Do not create a separate report engine.

Include:

- AI asset inventory.
- AI security posture.
- Scanner coverage.
- Findings.
- Manual-review items.
- Unresolved hypotheses.
- Evidence gaps.
- Assessment limitations.
- Framework versions.
- Execution configuration.
- Evidence hashes.
- Validation status.
- Reproduction status.
- Remediation.

Preserve:

- Report QA.
- Four-eyes approval.
- Hashing.
- Signing.
- Existing export mechanisms.

# 21. CONFIGURATION

Inspect all existing environment variables.

Introduce a consistent shared-environment configuration.

Suggested configuration:

```dotenv
ATTESTRA_AASI=off

ATTESTRA_SHARED_ENV_ROOT=/opt/attestra/runtime

ATTESTRA_SHARED_PYTHON_ENV=/opt/attestra/runtime/venv

ATTESTRA_NODE_HOME=/opt/attestra/runtime/tools/node

ATTESTRA_NPM_PREFIX=/opt/attestra/runtime/npm

ATTESTRA_SCANNER_RUNTIME_MODE=native

ATTESTRA_SCANNER_REQUIRE_SANDBOX=1

ATTESTRA_SCANNER_GARAK_ENABLED=1
ATTESTRA_SCANNER_PROMPTFOO_ENABLED=1
ATTESTRA_SCANNER_SAFELABS_ENABLED=1
ATTESTRA_SCANNER_PYRIT_ENABLED=1

ATTESTRA_SCANNER_TIMEOUT_GARAK=3600
ATTESTRA_SCANNER_TIMEOUT_PROMPTFOO=3600
ATTESTRA_SCANNER_TIMEOUT_SAFELABS=3600
ATTESTRA_SCANNER_TIMEOUT_PYRIT=3600
```

These are proposed settings.

Inspect existing naming conventions before implementing.

The environment manager must reject:

- Separate scanner venv paths.
- Different Python interpreters.
- System Python fallback.
- Unmanaged Promptfoo installations.
- Docker scanner execution.

Do not print secrets.

# 22. INSTALLATION SCRIPTS

Create or update the appropriate installation scripts under existing repository conventions.

Suggested:

```text
scripts/
    runtime/
        install-shared-environment.sh
        verify-shared-environment.sh
        upgrade-shared-environment.sh
        health-check-shared-environment.sh
        backup-runtime-manifest.sh
```

The installer must:

1. Validate operating system.
2. Validate Python version.
3. Validate Node.js compatibility.
4. Create exactly one shared Python venv.
5. Install Attestra dependencies.
6. Install Garak.
7. Install SafeLabs.
8. Install PyRIT.
9. Install Node.js under the shared root.
10. Install Promptfoo under the shared root.
11. Generate or verify dependency locks.
12. Verify package versions.
13. Run `pip check`.
14. Verify npm dependency integrity.
15. Verify scanner executables.
16. Verify sandbox availability.
17. Verify health.
18. Produce a clear installation report.

Do not create per-scanner virtual environments.

Do not install packages during normal scanner execution.

Do not run customer scans during installation.

Installation and upgrades must be separate from scanning.

## 22.1 Upgrade requirements

All four scanners must be upgraded through one controlled shared-environment maintenance workflow.

Before upgrading:

- Verify current environment manifest.
- Back up dependency manifests.
- Resolve all dependencies.
- Verify compatibility.
- Check licenses.
- Run regression tests.
- Preserve existing customer evidence.

Never perform automatic upgrades during scanner jobs.

# 23. DOCKER CONFIGURATION CLEANUP

Inspect:

- `Dockerfile`.
- `compose.yaml`.
- `.dockerignore`.
- `docker/`.
- `deploy/`.
- `docker/scanner-digests.env`.
- Existing image-pull scripts.

Remove the four AI scanners from Docker image configuration.

Remove obsolete AASI image-pull requirements.

Preserve unrelated Docker services and scanner images.

Do not delete the entire Docker deployment.

Do not break existing application deployment.

The four AI scanners must run through the shared native environment even when the main Attestra deployment uses Docker.

Document the supported host/runtime arrangement accurately.

# 24. TESTING

Mocks are allowed for unit tests.

Mocks alone are not acceptance evidence.

## 24.1 Single-environment tests

Prove:

- Exactly one Python venv is used.
- All Python scanners use the same interpreter.
- Attestra uses the same interpreter.
- No scanner-specific venv exists.
- No system Python fallback occurs.
- Promptfoo is installed beneath the shared environment root.
- Node is installed beneath the shared environment root.
- No unmanaged global Promptfoo is used.
- Dependency resolution succeeds.
- `pip check` succeeds.
- Dependency locks are reproducible.

## 24.2 Docker prohibition tests

Prove:

- No AI adapter calls Docker.
- No AI adapter calls `docker_run_argv()`.
- No AI adapter calls `build_docker_argv()`.
- No AI adapter inspects scanner images.
- No AI scanner installation script runs `docker pull`.
- Docker availability does not change scanner execution.
- Docker image variables cannot override native execution.
- Docker absence does not prevent native scanner execution.

Use monkeypatches and static checks to catch forbidden calls.

## 24.3 Real scanner tests

Use a local synthetic vulnerable AI target.

Prove genuine execution of:

- Garak.
- Promptfoo.
- SafeLabs.
- PyRIT.

For every scanner verify:

- Actual framework loaded.
- Correct shared runtime.
- Correct version.
- Correct authorized target.
- Correct command.
- Actual output.
- Output validation.
- Evidence persistence.
- Importer integration.
- Correct finding classification.
- Correct coverage.
- Timeout.
- Cancellation.

For PyRIT, prove actual framework-backed scenario execution.

A handcrafted HTTP request is insufficient.

## 24.4 Security tests

Test:

1. Unauthorized target.
2. Cross-tenant evidence leakage.
3. DNS rebinding.
4. Unauthorized redirects.
5. Private IP access.
6. Metadata endpoint access.
7. Prompt injection.
8. Arbitrary command injection.
9. Secret leakage.
10. Environment leakage.
11. Unauthorized judge egress.
12. Filesystem traversal.
13. Stale report reuse.
14. Malformed output.
15. Duplicate run.
16. Cancellation failure.
17. Timeout failure.
18. Expired authorization.
19. Unregistered test.
20. Approval bypass.
21. Runtime version mismatch.
22. Dependency tampering.
23. Package modification during scanning.
24. Missing sandbox.
25. Unrestricted egress.
26. Forged evidence.
27. False confirmed finding.
28. Creation of an unexpected second venv.
29. System Python fallback.
30. Promptfoo global-path fallback.

# 25. FULL END-TO-END VALIDATION

Prove this complete workflow:

```text
AI asset creation
    |
Engagement authorization
    |
AASI recommendation
    |
Human/policy approval
    |
Existing Attestra planner
    |
Shared native scanner environment
    |
Garak / Promptfoo / SafeLabs / PyRIT
    |
Raw result
    |
Evidence persistence
    |
Importer
    |
Finding
    |
Validation
    |
Coverage
    |
Compliance
    |
AASI evidence review
    |
Reporting
    |
Remediation
    |
Retest
```

Run the complete existing regression suite.

Do not modify existing tests merely to make them pass.

Fix actual defects.

Document justified incompatibilities.

# 26. DOCUMENTATION AND LAT

Follow `AGENTS.md`.

Inspect existing Lat references before changes.

Update only actual implemented behavior.

Preserve stable IDs.

Run `lat check`.

Do not claim success if Lat is unavailable.

Update:

- README.
- SETUP_GUIDE.
- Architecture.
- Implementation status.
- Roadmap.
- Changelog.
- Environment documentation.
- Dependency documentation.
- Scanner installation.
- Scanner operations.
- Deployment guides.
- Lat knowledge graph.

Document explicitly:

**All Attestra Python packages and Python AI scanner frameworks run in one shared Python virtual environment. Promptfoo's native Node runtime and npm dependencies reside under the same shared environment root. No scanner-specific virtual environments are created.**

# 27. IMPLEMENTATION PHASES

Execute sequentially.

## Phase 0 — Repository audit

Inspect source, dependencies, tests, Git, architecture and deployment.

## Phase 1 — Shared environment architecture

Implement one shared Python venv and one managed runtime root.

## Phase 2 — Dependency resolution

Resolve and pin Attestra, Garak, SafeLabs and PyRIT Python dependencies.

Resolve Node and Promptfoo separately under the same root.

Update `pyproject.toml` and `requirements.txt`.

## Phase 3 — Native scanner execution

Modify the existing scanner base, SDK and registry.

Enforce native-only execution.

## Phase 4 — Garak

Complete native execution, reports, importers and evidence.

## Phase 5 — Promptfoo

Complete native Node execution, privacy controls, output and evidence.

## Phase 6 — SafeLabs

Complete native framework execution and evidence.

## Phase 7 — PyRIT

Implement genuine PyRIT framework execution and supported scenarios.

## Phase 8 — Security hardening

Complete network restrictions, DNS pinning, filesystem controls, process management and resource limits.

## Phase 9 — AASI integration

Complete orchestration, authorization, planning, evidence correlation and coverage.

## Phase 10 — Reporting and compliance

Complete executive, technical and compliance reporting.

## Phase 11 — Installation and deployment

Complete the single-environment installer, verification, upgrade and recovery processes.

## Phase 12 — Full testing

Run unit, integration, security, end-to-end and regression tests.

## Phase 13 — Documentation and production readiness

Synchronize documentation, Lat and final implementation reports.

Do not stop after Phase 0.

Do not stop after one scanner.

Do not stop after tests are written.

Complete all safe and approved implementation work.

# 28. PRESERVATION REQUIREMENTS

Never:

- Replace Attestra.
- Create another Python venv.
- Create per-scanner environments.
- Install Python scanner packages outside the shared venv.
- Use system Python as a fallback.
- Install Promptfoo through pip.
- Create a separate Node environment outside the shared root.
- Introduce Docker scanner execution.
- Pull AI scanner images.
- Introduce Podman or an alternative container runtime.
- Create another scanner registry.
- Create another planner.
- Create another database.
- Create another finding model.
- Create another validation enum.
- Bypass tenant authorization.
- Bypass human approval.
- Allow arbitrary agent commands.
- Allow scanner jobs to modify installed packages.
- Delete existing backups.
- Overwrite user modifications.
- Fabricate test results.
- Claim incomplete capabilities are implemented.

# 29. FINAL ACCEPTANCE MATRIX

| Requirement | Proof |
|---|---|
| Exactly one Python venv | Environment inspection |
| Attestra uses shared venv | Runtime interpreter verification |
| Garak uses shared venv | Executable and interpreter verification |
| SafeLabs uses shared venv | Executable and interpreter verification |
| PyRIT uses shared venv | Executable and interpreter verification |
| Promptfoo under shared root | Node/npm path verification |
| No separate scanner venvs | Static and runtime verification |
| Dependency consistency | pyproject/requirements/lock checks |
| Dependency compatibility | `pip check` and integration tests |
| No Docker pulls | Static and runtime tests |
| No Docker scanner execution | Static and runtime tests |
| Native framework execution | Actual scanner runs |
| Network security | Target-bound egress tests |
| Authorization | Positive and negative tests |
| Evidence | Persisted reports and hashes |
| AASI orchestration | End-to-end tests |
| MongoDB | Migration and tenant tests |
| Compliance | Evidence-backed mapping |
| Reporting | Real generated reports |
| Deployment | Clean environment installation |
| Documentation | Synchronized documents |
| Lat | Actual validation output |

# 30. FINAL DELIVERABLES

Create or update meaningful implementation documents:

```text
docs/ai_security/
    AASI_NATIVE_BASELINE_AUDIT.md
    AASI_NATIVE_IMPLEMENTATION_PLAN.md
    AASI_NATIVE_IMPLEMENTATION_STATUS.md
    AASI_NATIVE_SCANNER_ARCHITECTURE.md
    AASI_SHARED_ENVIRONMENT_SPECIFICATION.md
    AASI_SHARED_ENVIRONMENT_INSTALLATION.md
    AASI_SHARED_ENVIRONMENT_OPERATIONS.md
    AASI_SHARED_ENVIRONMENT_UPGRADE.md
    AASI_NATIVE_SCANNER_SECURITY.md
    AASI_NATIVE_TEST_RESULTS.md
    AASI_NATIVE_SECURITY_VALIDATION.md
    AASI_NATIVE_DEPENDENCY_LICENSE_INVENTORY.md
    AASI_NATIVE_FINAL_IMPLEMENTATION_REPORT.md
    AASI_NATIVE_PRODUCTION_READINESS_REPORT.md
```

Update:

- `pyproject.toml`.
- `requirements.txt`.
- Dependency lock files.
- `.env.example`.
- `.env.production.example`.
- `.gitignore`.
- `.dockerignore`.
- `attestra/config.py`.
- Scanner SDK.
- Scanner registry.
- Four AI adapters.
- Four importers.
- AASI modules where required.
- Mongo migrations where required.
- Coverage.
- Compliance.
- Reporting.
- Installation scripts.
- Upgrade scripts.
- Health checks.
- README.
- SETUP_GUIDE.
- CHANGELOG.
- Architecture documents.
- Deployment documentation.
- `lat.md/`.

Do not create empty files to satisfy the list.

# 31. FINAL REPORT

Report:

A. Executive summary.

B. Initial repository status.

C. Existing implementation discovered.

D. Files added.

E. Files modified.

F. Files removed or deprecated.

G. Single shared environment architecture.

H. Actual shared Python interpreter path.

I. Actual Node.js runtime path.

J. Exact Python framework versions.

K. Exact Promptfoo and Node versions.

L. Dependency conflict resolution.

M. Actual Garak execution.

N. Actual Promptfoo execution.

O. Actual SafeLabs execution.

P. Actual PyRIT execution.

Q. Docker prohibition verification.

R. Security and network controls.

S. Evidence integration.

T. AASI integration.

U. MongoDB integration.

V. Reporting and compliance.

W. Exact commands executed.

X. Unit-test results.

Y. Integration-test results.

Z. Security-test results.

AA. Regression-test results.

AB. Lat validation.

AC. Deployment validation.

AD. Outstanding issues.

AE. Final production-readiness classification.

Never fabricate test counts or successful results.

# 32. PRODUCTION-READINESS CLASSIFICATION

Use:

- READY FOR STAGING.
- READY FOR PRODUCTION REVIEW.
- PRODUCTION READY.

PRODUCTION READY requires:

- All four scanners genuinely execute natively.
- All Python components use the single shared venv.
- Promptfoo executes from the shared environment root.
- No separate scanner venv exists.
- No Docker image pull dependency exists.
- No Docker scanner execution exists.
- Dependencies are compatible and reproducible.
- Security controls are verified.
- Evidence integrity is verified.
- Tenant isolation is verified.
- Full regression tests pass.
- Backup and restore are verified.
- Clean deployment succeeds.
- No unresolved critical or high security findings.
- Operational acceptance is complete.

Do not claim production deployment without actual deployment evidence.

# 33. FINAL EXECUTION COMMAND

BEGIN IMPLEMENTATION.

Work directly in the supplied Attestra repository.

Read `AGENTS.md`.

Inspect the entire existing source.

Establish the baseline.

Implement the new shared-environment architecture.

Resolve all Python dependency conflicts.

Create exactly one shared Python virtual environment.

Install Attestra, Garak, SafeLabs and PyRIT into that same environment.

Install the Node.js runtime and Promptfoo under the same shared environment root.

Never create another Python virtual environment.

Never use Docker image pulls or Docker scanner execution for the four AI scanners.

Modify the existing scanner execution engine.

Complete all four native scanner integrations.

Complete the AASI orchestration and evidence pipeline.

Complete MongoDB, coverage, compliance and reporting integration.

Complete security hardening.

Complete installation, upgrade, health-check and deployment documentation.

Run all relevant tests.

Run Lat validation.

Produce the complete implementation and production-readiness reports.

Do not stop after writing documentation.

Do not stop after creating installation scripts.

Do not stop after implementing one scanner.

Do not leave unresolved work hidden behind TODO comments.

Do not weaken security controls to force success.

If a genuine external dependency or compatibility blocker exists, document it precisely and continue all independent approved work.

Preserve all existing user modifications and customer data.

**FINAL PRODUCT OBJECTIVE**

Deliver Attestra AASI with:

1. One globally shared Python virtual environment.
2. All Attestra Python dependencies in that environment.
3. Garak in that same environment.
4. SafeLabs in that same environment.
5. Microsoft PyRIT in that same environment.
6. Promptfoo's Node.js runtime and npm dependencies under the same shared environment root.
7. Zero separate scanner virtual environments.
8. Zero Docker image pulls for AI scanners.
9. Zero Docker execution for AI scanners.
10. Native, governed scanner execution through existing Attestra infrastructure.
11. Evidence-driven AASI reasoning.
12. Existing authorization and planning.
13. MongoDB-backed decision history.
14. Evidence integrity and finding validation.
15. AI-aware compliance and reporting.
16. Reproducible installation and production operations.

The objective is one shared, consistent, maintainable runtime — not multiple isolated scanner installations.

**INSPECT. RESOLVE. IMPLEMENT. INTEGRATE. TEST. SECURE. DOCUMENT. DEPLOYMENT-VALIDATE. REPORT.**

**DO NOT CLAIM COMPLETION WITHOUT PROOF.**