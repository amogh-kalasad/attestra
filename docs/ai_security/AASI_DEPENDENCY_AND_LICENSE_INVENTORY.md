# AASI dependency and licence inventory (Phase 10)

Phase 10 documentation of Attestra **core** Python dependency sources, local `.venv` installed versions, and the rule that AI red-team frameworks stay out of the core environment. Branch: `attestra-asi-bundle`. Inventory date: **2026-11-23**. This is an engineering inventory, **not** formal legal advice.

Companions: [`AASI_LICENSE_REVIEW.md`](./AASI_LICENSE_REVIEW.md), [`REPOSITORY_ADOPTION_MATRIX.md`](./REPOSITORY_ADOPTION_MATRIX.md), [`AASI_IMPLEMENTATION_BLUEPRINT.md`](./AASI_IMPLEMENTATION_BLUEPRINT.md), [`../LICENSES.md`](../LICENSES.md), [`AASI_WORKER_IMAGES.md`](./AASI_WORKER_IMAGES.md).

## Authoritative dependency source

| Source | Role |
|---|---|
| **`pyproject.toml`** (`[project].dependencies` and `[project.optional-dependencies]`) | **Authoritative** package metadata for installs, floors, extras, and packaging. Prefer `pip install -e ".[dev]"` (and named extras) for development. |
| **`requirements.txt`** | Convenience mirror kept in sync with `[project].dependencies` plus common `[dev]` tools. Comments state floors were refreshed from PyPI (2026-11-10). Optional extras remain commented. **Not** the source of truth when the two disagree — update `pyproject.toml` first, then mirror. |

Phase 10 does **not** change floors in either file. It records the policy that core stays minimal and that AI frameworks are **not** added to core dependencies.

## Core must stay minimal

1. Attestra’s API / worker Python environment installs only packages declared for the core app (and opted-in extras).
2. **Do not** add **PyRIT**, **Garak**, **Promptfoo**, or their heavy transitive stacks (`torch`, `transformers`, Azure SDKs, Node 22 runtime, etc.) to `pyproject.toml` `[project].dependencies` or to the uncommented lines of `requirements.txt`.
3. AI frameworks run as **digest-pinned isolated worker/scanner images** through the existing `ScannerAdapter` / `AdapterMeta` path (`ATTESTRA_IMAGE_GARAK`, `ATTESTRA_IMAGE_PROMPTFOO`, `ATTESTRA_IMAGE_SAFELABS`, and later PyRIT). Offline **importers** parse tool exports inside Attestra; they do not import those frameworks as libraries.
4. Re-check SPDX and digests on every adoption PR (see licence review). Shannon (AGPL-3.0) remains **no code reuse**.

Verified on this tree (2026-11-23): `pyproject.toml` and `requirements.txt` contain **no** `garak`, `pyrit`, `promptfoo`, or `safelabs` package names.

## Declared core floors (`pyproject.toml`)

Floors below are copied from `[project].dependencies` as of this inventory. Optional extras also exist (`dev`, `oidc`, `docs`, `s3`, `screenshots`, `temporal`, `observability`). Note: several packages appear both in core `dependencies` and in extras (pre-existing layout; not changed in Phase 10).

| Package | Declared floor |
|---|---|
| fastapi | `>=0.162.3` |
| uvicorn | `>=0.54.0` |
| sqlalchemy | `>=2.1.8` |
| pydantic | `>=2.14.3` |
| jinja2 | `>=3.1.6` |
| pyyaml | `>=6.0.3` |
| python-multipart | `>=0.0.33` |
| cryptography | `>=50.0.2` |
| dnspython | `>=2.9.2` |
| defusedxml | `>=0.7.1` |
| xhtml2pdf | `>=0.2.28` |
| python-docx | `>=1.2.0` |
| openpyxl | `>=3.1.5` |
| pymongo | `>=4.19.0` |
| pytest | `>=9.2.0` |
| httpx | `>=0.28.1` |
| httpx2 | `>=2.16.0` |
| ruff | `>=0.17.4` |
| authlib | `>=1.9.5` |
| docxtpl | `>=0.20.2` |
| weasyprint | `>=70.0` |
| boto3 | `>=1.43.127` |
| Pillow | `>=13.0.0` |
| temporalio | `>=1.35.0` |

`requirements.txt` mirrors the same floors for the non-optional set and lists the extras as comments.

## Local `.venv` installed versions (core packages only)

Exact versions from `.\.venv\Scripts\python.exe -m pip list` / `pip show` on **2026-11-23**. These are **installed** versions on this machine, not “latest on PyPI” claims. Several sit **below** current `pyproject.toml` floors — refresh with `pip install -e ".[dev]"` when aligning the venv; Phase 10 does not bump floors here.

| Package (pip Name) | Installed version | `pip show` License field |
|---|---|---|
| fastapi | 0.143.2 | *(empty)* |
| uvicorn | 0.54.0 | *(empty)* |
| SQLAlchemy | 2.1.4 | *(empty)* |
| pydantic | 2.14.1 | *(empty)* |
| Jinja2 | 3.1.6 | *(empty)* |
| PyYAML | 6.0.3 | MIT |
| python-multipart | 0.0.32 | *(empty)* |
| cryptography | 50.0.2 | *(empty)* |
| dnspython | 2.9.0 | *(empty)* |
| defusedxml | 0.7.1 | PSFL |
| xhtml2pdf | 0.2.27 | *(empty)* |
| python-docx | 1.2.0 | MIT |
| openpyxl | 3.1.5 | MIT |
| pymongo | 4.19.0 | *(empty)* |
| pytest | 9.1.1 | *(empty)* |
| httpx | 0.28.1 | BSD-3-Clause |
| httpx2 | 2.13.1 | *(empty)* |
| ruff | 0.17.1 | *(empty)* |
| pillow | 13.0.0 | *(empty)* |

**Not installed** in this `.venv` (among packages named in `pyproject.toml`): `authlib`, `boto3`, `temporalio`, `weasyprint`, `docxtpl`. Empty License fields mean metadata was blank in `pip show` for that install; do not treat blank as an SPDX decision — use package METADATA / PyPI classifiers or a release `pip-licenses` run before shipping ([`../LICENSES.md`](../LICENSES.md) §Python dependencies).

Editable install present: `attestra 1.0.0` → `E:\GitHub\attestra`.

## AI frameworks — isolated images only (not core deps)

| Framework | Declared project licence (Phase 0 review) | Attestra integration | Core Python dep? |
|---|---|---|---|
| NVIDIA Garak | Apache-2.0 | Importer + digest-pinned adapter (`ATTESTRA_IMAGE_GARAK`, `AdapterMeta.licence="Apache-2.0"`) | **No** |
| Promptfoo | MIT | Importer + digest-pinned adapter (`ATTESTRA_IMAGE_PROMPTFOO`, licence MIT); remote/telemetry/sharing/update disabled in worker env | **No** |
| SafeLabs Eval | Apache-2.0 | Importer + digest-pinned adapter (`ATTESTRA_IMAGE_SAFELABS`); findings capped at `potential` | **No** |
| Microsoft PyRIT | MIT | Importer now; **isolated container worker later** (Phase 5) — never merge its dependency tree into the Attestra venv | **No** |

Upstream HEADs and release tags age quickly; re-pin digests and re-read LICENSE on adoption. Details: [`AASI_LICENSE_REVIEW.md`](./AASI_LICENSE_REVIEW.md).

Placeholder AI image lines (refused until real digests) live in `docker/scanner-digests.env` comments. Worker image dependency policy: [`AASI_WORKER_IMAGES.md`](./AASI_WORKER_IMAGES.md).

## Explicit non-goals for Phase 10

- Adding or bumping core dependency floors in `pyproject.toml` / `requirements.txt`.
- Installing Garak / Promptfoo / PyRIT / SafeLabs into `.venv`.
- Claiming “latest” versions from PyPI without a recorded `pip` observation.
- Shipping Shannon or other AGPL-derived workers as Attestra product code.
