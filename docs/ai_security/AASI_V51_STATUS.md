# AASI V5.1 status (master tracker)

Master tracker for **Attestra AASI CLI Prompt 5.1**: one shared environment root, Docker-free native AI scanners (Garak, Promptfoo, SafeLabs, PyRIT). Branch: `attestra-asi-bundle`. Directive archive: [`AASI_CLI_PROMPT_5.1.md`](AASI_CLI_PROMPT_5.1.md). Companion roll-up: [`AASI_IMPLEMENTATION_STATUS.md`](AASI_IMPLEMENTATION_STATUS.md).

**Policy:** V5.1 **supersedes** the V4 Docker AI image / digest-pin approach for Garak, Promptfoo, SafeLabs, and PyRIT. Web scanners (ZAP, Nuclei, testssl, naabu, …) keep their existing digest-pinned images. **Do not claim production AI image digests.**

| Field | Value |
|---|---|
| **Directive** | AASI CLI Prompt **5.1** |
| **Overall V5.1 track** | **Code complete — openai pin resolved; live e2e proven (lab)** |
| **AI execution model** | Native under `ATTESTRA_SHARED_ENV_ROOT` (one Python venv + Node/npm for Promptfoo) |
| **Docker AI scanner images** | **Deprecated / unused** for execution (`allows_docker=False`) |
| **Production digests claimed?** | **No** |
| **openai pin strategy** | Prefer `openai>=3,<4` (PyRIT); install `garak==0.17.1` with `--no-deps` (REST/Anthropic/LiteLLM). Accepted `pip check` WARN for garak↔openai. No second venv. |

---

## Track table

| Track | Status | Notes |
|---|---|---|
| Docs / env templates | **Complete** | `ATTESTRA_SHARED_ENV_ROOT`; AI `ATTESTRA_IMAGE_*` deprecated |
| Shared env runtime manager | **Complete** | `attestra/scanner_runtime/` |
| Install scripts | **Complete** | Staged `install_shared_env.py` (openai 3.x + garak `--no-deps`); `install_promptfoo_npm.py`; `runtime/npm/package.json` |
| `pyproject` `ai-scanners` extra | **Complete** | SafeLabs + PyRIT + openai 3.x + anthropic + litellm (garak via installer `--no-deps`) |
| Native Garak / SafeLabs | **Complete** | `allows_docker=False`; Garak REST only; shared python `-m` |
| Native Promptfoo | **Complete** | Shared npm CLI; privacy env retained |
| Native PyRIT (framework-backed) | **Complete** | `attestra/aasi/pyrit_native.py`; old Docker worker deprecated |
| Native egress helpers | **Complete** | `scanner_runtime/egress.py` |
| Offline importers | **Complete** (V4) | Unchanged |
| Recommend-only AASI core | **Complete** (V4) | Flag-gated |
| Live e2e on authorized AI lab | **Proven (lab)** | Anthive webcheck + mock SafeLabs/PyRIT done; Garak REST ran (exit 0) but import failed; Promptfoo/ZAP follow-ups — [`AASI_V51_E2E_ANTHIVE_VERIFICATION.md`](AASI_V51_E2E_ANTHIVE_VERIFICATION.md) |
| Production AI digests | **N/A (superseded)** | |

---

## Operator knobs (V5.1)

| Variable | Role |
|---|---|
| `ATTESTRA_SHARED_ENV_ROOT` | Single managed root (default `.attestra-runtime`) |
| `ATTESTRA_AASI` | Recommend-only flag (default **off**) |
| `ATTESTRA_IMAGE_GARAK` / `PROMPTFOO` / `SAFELABS` / `PYRIT` | **Unused** for AI execution |
| Other `ATTESTRA_IMAGE_*` | Still used for non-AI scanners |

Install:

```bash
python scripts/aasi/install_shared_env.py
python scripts/aasi/install_promptfoo_npm.py
```

See [`AASI_V51_INSTALL.md`](AASI_V51_INSTALL.md) and [`AASI_V51_DEPENDENCIES.md`](AASI_V51_DEPENDENCIES.md).

---

## Related docs

| Doc | Role |
|---|---|
| [`AASI_CLI_PROMPT_5.1.md`](AASI_CLI_PROMPT_5.1.md) | Directive |
| [`AASI_V51_SHARED_ENV.md`](AASI_V51_SHARED_ENV.md) | Runtime layout |
| [`AASI_V51_NO_DOCKER.md`](AASI_V51_NO_DOCKER.md) | Base `allows_docker` |
| [`AASI_V51_GARAK_SAFELABS_NATIVE.md`](AASI_V51_GARAK_SAFELABS_NATIVE.md) | Native adapters |
| [`AASI_V51_PROMPTFOO_NATIVE.md`](AASI_V51_PROMPTFOO_NATIVE.md) | Native Promptfoo |
| [`AASI_V51_PYRIT_NATIVE.md`](AASI_V51_PYRIT_NATIVE.md) | Genuine PyRIT |
| [`AASI_V51_NATIVE_EGRESS.md`](AASI_V51_NATIVE_EGRESS.md) | Egress helpers |
| [`AASI_V51_DEPENDENCIES.md`](AASI_V51_DEPENDENCIES.md) | openai 3.x + garak `--no-deps` policy |
| [`AASI_V51_E2E_ANTHIVE_VERIFICATION.md`](AASI_V51_E2E_ANTHIVE_VERIFICATION.md) | Live Anthive + mock LLM verification results |
