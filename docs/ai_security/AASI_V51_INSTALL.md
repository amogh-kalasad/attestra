# AASI V5.1 shared environment install

Operator steps to create **one** shared runtime root for Attestra + native AI scanners (no Docker pulls, no second Python venv). Pins and openai 3.x / Garak `--no-deps` policy: [`AASI_V51_DEPENDENCIES.md`](./AASI_V51_DEPENDENCIES.md).

## Layout

```text
$ATTESTRA_SHARED_ENV_ROOT/          # default local: <repo>/.attestra-runtime
├── venv/                           # ONLY Python virtualenv
├── tools/node/                     # Node 20.20.2 LTS (Iron)
├── npm/                            # promptfoo@0.118.17 (+ lock after install)
├── manifests/                      # python-runtime.json, garak/safelabs/pyrit/promptfoo.json
├── logs/
├── cache/
└── tmp/
```

Set the root explicitly in production:

```bash
export ATTESTRA_SHARED_ENV_ROOT=/opt/attestra/runtime
```

```powershell
$env:ATTESTRA_SHARED_ENV_ROOT = "D:\attestra\runtime"
```

If unset, the installer uses `<repo>/.attestra-runtime` (gitignored).

## Prerequisites

- Python **3.11+** on `PATH` (same major you will run Attestra with).
- Network access to PyPI and (for Node auto-download) `nodejs.org` / npm registry.
- Disk: multi-GB free (Garak/PyRIT ML wheels).
- Do **not** run `docker pull` for Garak / Promptfoo / SafeLabs / PyRIT as part of this flow.

## One-shot installer (preferred)

From the repository root:

```bash
python scripts/aasi/install_shared_env.py
```

```powershell
python scripts\aasi\install_shared_env.py
```

What it does:

1. Creates the layout under the shared root.
2. Creates `<root>/venv` **only if missing** (`python -m venv`).
3. Staged Python install into that venv only:
   - `pip install -e .` (Attestra core)
   - joint pins: SafeLabs + PyRIT + `openai>=3,<4` + anthropic + litellm
   - `pip install garak==0.17.1 --no-deps`
   - Garak support deps from METADATA (openai excluded), then re-pin openai 3.x
   - import verification; `pip check` may WARN on the known garak↔openai mismatch (accepted)
4. Attempts Node 20.20.2 portable download into `tools/node` (see Windows note below).
5. Copies committed `runtime/npm/package.json` → `<root>/npm/package.json` and runs `npm install`.
6. Writes manifests under `<root>/manifests/`.
7. Never creates a second venv; never docker-pulls.

Useful flags:

| Flag | Effect |
|---|---|
| `--root PATH` | Override shared root |
| `--skip-python` | Skip venv/pip |
| `--skip-node` | Skip Node download (use manual Node) |
| `--skip-promptfoo` | Skip npm install |
| `--promptfoo-only` | Layout + Node (unless skipped) + Promptfoo + manifests |
| `--force-node` | Re-download Node |

Promptfoo-only wrapper:

```bash
python scripts/aasi/install_promptfoo_npm.py
```

## Python-only (manual)

Prefer the one-shot installer. A bare `pip install -e ".[ai-scanners]"` installs the **joint** extras only (SafeLabs, PyRIT, openai 3.x, anthropic, litellm) and does **not** install Garak. For Garak, use the staged path below or `install_shared_env.py`.

```bash
export ATTESTRA_SHARED_ENV_ROOT=/opt/attestra/runtime
mkdir -p "$ATTESTRA_SHARED_ENV_ROOT"/{venv,tools/node,npm,manifests,logs,cache,tmp}
python3 -m venv "$ATTESTRA_SHARED_ENV_ROOT/venv"
PY="$ATTESTRA_SHARED_ENV_ROOT/venv/bin/python"
"$PY" -m pip install --upgrade pip
cd /path/to/attestra
"$PY" -m pip install -e .
"$PY" -m pip install -e ".[ai-scanners]"
"$PY" -m pip install --no-deps garak==0.17.1
# Then install garak METADATA deps excluding openai, re-pin openai>=3,<4
# (see scripts/aasi/install_shared_env.py), and verify imports.
"$PY" -m pip check   # garak↔openai WARN alone is accepted
```

Windows:

```powershell
$root = $env:ATTESTRA_SHARED_ENV_ROOT
if (-not $root) { $root = ".\.attestra-runtime" }
New-Item -ItemType Directory -Force -Path "$root\venv","$root\tools\node","$root\npm","$root\manifests","$root\logs","$root\cache","$root\tmp" | Out-Null
python -m venv "$root\venv"
$py = "$root\venv\Scripts\python.exe"
& $py -m pip install --upgrade pip
& $py -m pip install -e .
& $py -m pip install -e ".[ai-scanners]"
& $py -m pip install --no-deps garak==0.17.1
& $py -m pip check
```

Joint extras list (`ai-scanners`):

```text
safelabs-eval==0.12.0
pyrit==1.2.1
openai>=3,<4
anthropic>=0.40.0,<1.0.0
litellm>=1.84.0
```

Garak (`garak==0.17.1`) is installer-staged with `--no-deps`. Attestra Garak runs REST against `ai_app`; OpenAI generator unsupported; Anthropic/LiteLLM present. Do **not** create another venv. Details: [`AASI_V51_DEPENDENCIES.md`](./AASI_V51_DEPENDENCIES.md).

## Node + Promptfoo

### Auto (Linux / macOS / Windows when download works)

```bash
python scripts/aasi/install_shared_env.py --skip-python
# or
python scripts/aasi/install_promptfoo_npm.py
```

### Manual Node on Windows (recommended if auto-download is blocked)

1. Download the official zip (x64 example):

   `https://nodejs.org/dist/v20.20.2/node-v20.20.2-win-x64.zip`

2. Extract so the shared root contains:

   ```text
   <SHARED_ENV_ROOT>\tools\node\node.exe
   <SHARED_ENV_ROOT>\tools\node\npm.cmd
   ```

   (If the zip has a single top folder `node-v20.20.2-win-x64`, move its contents into `tools\node\`.)

3. Install Promptfoo from the committed pin:

   ```powershell
   $root = $env:ATTESTRA_SHARED_ENV_ROOT
   if (-not $root) { $root = ".\.attestra-runtime" }
   Copy-Item .\runtime\npm\package.json "$root\npm\package.json" -Force
   Push-Location "$root\npm"
   & "$root\tools\node\npm.cmd" install --omit=dev --no-fund --no-audit
   Pop-Location
   ```

4. Or re-run the helper (skips re-download when `node.exe` exists):

   ```powershell
   python scripts\aasi\install_promptfoo_npm.py --skip-node
   ```

Verify:

```powershell
& "$root\tools\node\node.exe" --version    # expect v20.20.2
& "$root\npm\node_modules\.bin\promptfoo.cmd" --version
```

```bash
"$ATTESTRA_SHARED_ENV_ROOT/tools/node/bin/node" --version
"$ATTESTRA_SHARED_ENV_ROOT/npm/node_modules/.bin/promptfoo" --version
```

Committed pin file: `runtime/npm/package.json` → `"promptfoo": "0.118.17"` (Node engine `>=20 <21`). Newer Promptfoo lines (for example 0.125.x) require Node **≥22.22.0**; do not bump the npm pin without also bumping Node and re-testing.

## What not to do

- Do not `pip install promptfoo`.
- Do not `npm install -g promptfoo` into a system prefix.
- Do not `npx promptfoo@latest` at scan time.
- Do not create `garak-venv`, `pyrit-venv`, or a second app venv.
- Do not `docker pull` / `docker run` AI scanner images for V5.1 native execution.
- Do not install AI packages into a random developer `.venv` and call that the shared root unless that `.venv` **is** `$ATTESTRA_SHARED_ENV_ROOT/venv`.

## After install

- Point Attestra processes at the same root (`ATTESTRA_SHARED_ENV_ROOT`).
- Use `<root>/venv`’s Python for API, worker, CLI, and Python scanners.
- Keep AASI off until native adapters and health checks are ready (`ATTESTRA_AASI=off` default).
- Re-run the installer (or maintenance upgrade flow) for pin bumps; never `pip install` from a live scan job.
