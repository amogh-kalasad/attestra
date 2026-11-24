# AASI V5.1 — AI scanners are native-only (no Docker)

AASI V5.1 stops AI security scanners (Garak, Promptfoo, SafeLabs, PyRIT) from running via Docker. Those adapters install into a shared local environment and run as host processes. Non-AI scanners (ZAP, Nuclei, Trivy, …) keep digest-pinned Docker images unchanged.

## Why

Docker-in-Docker / DooD for heavy Python/Node AI toolchains was fragile on Windows Desktop, complicated digest pinning for private builds, and duplicated deps that belong in one shared venv. V5.1 makes AI adapters declare `allows_docker = False` so the runner never selects a container path for them.

## Mechanism

| Piece | Behavior |
|---|---|
| `ScannerAdapter.allows_docker` | Class attribute; default `True`. AI adapters set `False`. |
| `ScannerAdapter.uses_docker()` | Returns `False` when `allows_docker` is `False`, even if `ATTESTRA_IMAGE_*` is set and Docker is present. |
| `ScannerAdapter.unavailable_reason()` | When `allows_docker` is `False`, points operators at `ATTESTRA_SHARED_ENV_ROOT` and never suggests Docker Desktop or image digests. |
| `ATTESTRA_SHARED_ENV_ROOT` | Optional path for the shared native install root. Empty → runtime resolves to `.attestra-runtime` under the process CWD (`config.shared_env_root()`). |

Placeholder entries for `garak` / `promptfoo` / `safelabs` / `pyrit` may remain in `config._PLACEHOLDER_IMAGES` for env-key stability, but AI adapters ignore them under V5.1.

## Operator notes

1. Install AI CLIs into the shared env root (or ensure they are on `PATH` from that env).
2. Do **not** rely on `ATTESTRA_IMAGE_GARAK` / `PROMPTFOO` / `SAFELABS` / `PYRIT` for live AI scans.
3. Leave ZAP/Nuclei/Trivy/etc. image pins as before.
4. Restart the worker after changing `ATTESTRA_SHARED_ENV_ROOT`.

## Related

- Adapter base: `attestra/runner/scanners/base.py` (`allows_docker`, `uses_docker`, `unavailable_reason`)
- Config: `attestra/config.py` (`SHARED_ENV_ROOT`, `shared_env_root`)
- Tests: `tests/runner/test_ai_adapters_no_docker.py`
- Historical Docker recipes (no longer the runtime path for AI tools): `docker/aasi/README.md`, `AASI_WORKER_IMAGES.md`
