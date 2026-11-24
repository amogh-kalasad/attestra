# AASI V5.1 dependencies (shared environment)

Pinned distributions for native, Docker-free AI scanners under one shared environment root (`ATTESTRA_SHARED_ENV_ROOT`). Authoritative joint Python pins live in `pyproject.toml` `[project.optional-dependencies].ai-scanners`. Garak is installed by `scripts/aasi/install_shared_env.py` with `--no-deps`. Promptfoo is **npm-only**.

Companions: [`AASI_V51_INSTALL.md`](./AASI_V51_INSTALL.md), [`AASI_DEPENDENCY_AND_LICENSE_INVENTORY.md`](./AASI_DEPENDENCY_AND_LICENSE_INVENTORY.md), committed [`runtime/npm/package.json`](../../runtime/npm/package.json).

## Policy

1. **One** Python virtual environment at `<SHARED_ENV_ROOT>/venv` for Attestra + Garak + SafeLabs + PyRIT.
2. Promptfoo Node runtime under `<SHARED_ENV_ROOT>/tools/node` and npm prefix under `<SHARED_ENV_ROOT>/npm`.
3. Do **not** add AI scanners to core `[project].dependencies`.
4. Do **not** add `promptfoo` to `requirements.txt` as a pip package.
5. Do **not** `docker pull` AI scanner images for V5.1 native mode.
6. Do **not** create per-scanner venvs (`*-venv`, second `venv`).
7. Prefer **`openai>=3,<4`** so PyRIT works. Install Garak with **`--no-deps`** so it does not pull `openai>=2,<3`.

## Verified pins (2026-11-24)

| Component | Channel | Pin | Source |
|---|---|---|---|
| Garak | pip (`--no-deps`) | `garak==0.17.1` | PyPI `garak` 0.17.1 (`requires_python>=3.11`) |
| SafeLabs Eval | pip | `safelabs-eval==0.12.0` | PyPI `safelabs-eval` 0.12.0 (`requires_python>=3.11`) |
| PyRIT | pip | `pyrit==1.2.1` | PyPI `pyrit` 1.2.1 (`requires_python>=3.11,<3.15`) |
| OpenAI SDK | pip | `openai>=3,<4` | Required by PyRIT; preferred in shared env |
| Anthropic SDK | pip | `anthropic>=0.40.0,<1.0.0` | Garak generators (non-OpenAI) |
| LiteLLM | pip | `litellm>=1.84.0` | Garak generators / routing |
| Promptfoo | npm | `promptfoo@0.118.17` | npm (`engines.node: >=20.0.0`) |
| Node.js | portable | `20.20.2` (LTS Iron) | nodejs.org dist |

`ai-scanners` extras list (exact — **no garak**; installer stages garak separately):

```toml
ai-scanners = [
  "safelabs-eval==0.12.0",
  "pyrit==1.2.1",
  "openai>=3,<4",
  "anthropic>=0.40.0,<1.0.0",
  "litellm>=1.84.0",
]
```

## Licences (declared upstream)

| Package | Declared licence |
|---|---|
| garak | Apache-2.0 |
| safelabs-eval | Apache-2.0 |
| pyrit | MIT |
| promptfoo | MIT |

Re-check SPDX on every pin bump. Shannon AGPL remains **no code reuse**.

## Resolved openai pin strategy

Upstream clash (unchanged upstream):

- `garak==0.17.1` declares `openai>=2,<3`.
- `pyrit==1.2.1` declares `openai>=3,<4`.

**Attestra V5.1 resolution (single shared venv — no second venv):**

1. Install Attestra editable core into `<root>/venv`.
2. Install joint pins: SafeLabs + PyRIT + `openai>=3,<4` + `anthropic` + `litellm`.
3. Install `garak==0.17.1` with `pip install --no-deps`.
4. Install Garak's other runtime deps from its METADATA, **excluding** `openai` and extras.
5. Re-pin `openai>=3,<4` so a transitive install cannot silently downgrade.
6. Verify imports (`openai` major ≥ 3, `garak`, `pyrit`, `anthropic`, `litellm`, SafeLabs).
7. `pip check` may still report garak wanting `openai<3` while openai 3.x is installed. That **single** mismatch is an **accepted WARN** when import verification passed.

**Garak generator policy in the shared env:**

- Attestra adapter uses **REST only** (`--target_type rest`) against authorized `ai_app` URLs.
- Garak's native **OpenAI** generator is **unsupported** here (openai 3.x vs garak's `<3` bound).
- Use **REST**, **Anthropic**, or **LiteLLM** generators instead.

SafeLabs (`safelabs-eval==0.12.0`) core deps do not participate in the openai clash (optional judge extras are unused by the Attestra adapter).

## Heavy transitive stacks

Garak and PyRIT pull large ML stacks (`torch`, `transformers`, Azure SDKs, etc.). Expect multi-GB installs and longer cold installs. Keep them out of the default core `.venv` used for API-only development unless you intentionally share the V5.1 root.

## Sync with requirements.txt

`requirements.txt` mirrors the pins as **commented** optional lines plus an explicit note that Promptfoo is npm and Garak is installer-staged. Uncommented runtime lines stay core-only so a plain `pip install -r requirements.txt` does not drag AI frameworks into every environment.

## Install commands (summary)

```bash
# Shared root (example)
export ATTESTRA_SHARED_ENV_ROOT=/opt/attestra/runtime   # or omit → .attestra-runtime

# Preferred: staged install (openai 3.x + garak --no-deps)
python scripts/aasi/install_shared_env.py
# or
python scripts/aasi/install_shared_env.py --root "$ATTESTRA_SHARED_ENV_ROOT"

# Joint extras only (does NOT install garak — use the installer for garak)
"$ATTESTRA_SHARED_ENV_ROOT/venv/bin/python" -m pip install -e ".[ai-scanners]"

# Promptfoo half only (after Node is present under tools/node)
python scripts/aasi/install_promptfoo_npm.py
```

Windows PowerShell equivalents and Node portable steps: [`AASI_V51_INSTALL.md`](./AASI_V51_INSTALL.md).
