# AASI V5.1 — Shared scanner environment

One shared runtime root for AI scanners (Garak, SafeLabs, PyRIT, Promptfoo). No per-scanner venvs. No Docker for AI scanners.

## Root and layout

- Env var: `ATTESTRA_SHARED_ENV_ROOT` (default: `<repo>/.attestra-runtime`)
- Layout under the root:

| Path | Purpose |
| --- | --- |
| `venv/` | Single shared Python virtualenv |
| `tools/node/` | Node 20.x binary tree |
| `npm/` | npm prefix (Promptfoo CLI lives here) |
| `manifests/` | Install / version manifests (JSON) |
| `logs/` | Runtime logs |
| `cache/` | Tool caches |
| `tmp/` | Scratch |

Windows paths use `venv/Scripts/python.exe` and `promptfoo.cmd`. POSIX uses `venv/bin/python` and `promptfoo`.

## Version pins

| Component | Pin | Install path |
| --- | --- | --- |
| garak | `0.17.1` | shared venv (pip) |
| safelabs-eval | `0.12.0` | shared venv (pip) |
| pyrit | `1.2.1` | shared venv (pip) |
| promptfoo | `~0.118.x` | shared npm (Node — **not** pip) |
| node | `20.x` | `tools/node` |

## Absolute rules

1. Exactly **one** Python venv: `<root>/venv`.
2. Promptfoo is **Node/npm** under the same root — never pip into the venv.
3. **No Docker** for AI scanners; never fall back to Docker from this runtime.
4. **Reject** per-scanner venvs (`venv-garak`, `.venv-promptfoo`, extra `venv`/`.venv` under the root, etc.).

## Python API

Package: `attestra.scanner_runtime`

| API | Role |
| --- | --- |
| `resolve_shared_env()` / `SharedEnvironment` | Resolve root + layout paths |
| `require_python()` / `require_promptfoo()` | Hard-require shared binaries |
| `shared_python()` / `shared_promptfoo()` | Soft resolvers (`str | None`) for adapters |
| `reject_extra_venvs()` | Fail if forbidden venvs exist |
| `check_python_package` / `check_node` / `check_promptfoo` / `check_all` | Pin checks via `importlib.metadata` / CLIs |
| `health_report()` | Readiness for all four scanners (`docker: false`) |
| `run_with_shared_env()` | Thin wrapper over `run_process` with sanitized PATH |
| `write_manifest` / `read_manifest` | JSON under `manifests/` |

Design snapshot: `lat.md/aasi.md` § V5.1 shared scanner runtime.
