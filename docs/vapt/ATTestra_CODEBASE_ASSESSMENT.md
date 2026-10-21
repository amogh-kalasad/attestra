# Attestra Codebase Assessment

Baseline architecture and implemented behavior as of this gap-closure pass. Source of truth for “what exists” is the repository, not the DOCX.

## Stack

| Layer | Technology | Entry points |
| --- | --- | --- |
| Backend API | FastAPI | `attestra/api.py` |
| Web UI | Jinja + Starlette routes | `attestra/web/ui.py` |
| CLI | Typer/Click-style CLI | `attestra/cli.py` |
| ORM | SQLAlchemy 2 | `attestra/models.py`, `attestra/db.py` |
| Migrations | Alembic | `migrations/versions/` |
| Compliance | YAML hub-and-spoke | `attestra/compliance/engine.py`, `data/controls.yaml`, `data/packs/` |
| Reports | Jinja HTML + export | `attestra/reports/render.py`, `templates/`, `export.py` |
| Runner | Scoped scanners + jobs | `attestra/runner/`, `attestra/jobs/` |
| Auth | Users, API keys, RBAC, optional OIDC | `attestra/auth/` |
| Tests | pytest | `tests/` (~432 collected) |

## Assessment types

Canonical keys in `ENGAGEMENT_TYPES`: `va`, `pt`, `vapt`, `retest`, `continuous`. Display labels via `ENGAGEMENT_TYPE_LABELS` (`vapt` → `VA + PT`). Lifecycle covers create → authorize → assets/tests → import/scan → findings → compliance → report → retest.

## Frameworks (nine)

| Key | Source |
| --- | --- |
| `pci_dss_4` | Built-in `controls.yaml` |
| `iso_27001_2022` | Built-in |
| `soc2` | Built-in |
| `iso_42001_2023` | Pack YAML (+ `iso42001.py` helpers) |
| `cert_in_2022` | Pack YAML |
| `nist_csf_2` | Pack YAML |
| `rbi_csf_2016` | Pack YAML |
| `sebi_cscrf_2024` | Pack YAML |
| `dora_2022` | Pack YAML |

Packs only attach existing control objectives; they do not invent CWE mappings.

## Reporting architecture

- Shared renderer: `generate_report` → `_context` → Jinja (`{kind}.html.j2`) or tenant sandbox template.
- Kinds: technical, executive, compliance, iso_soa, ageing, closure_letter, attestation_letter, **retest**.
- Metadata config: `attestra/reports/data/template_config.yaml` loaded by `template_config.py`.
- Freeze: SHA-256 file under tenant data dir; QA/sign via four-eyes workflow; Ed25519/HMAC signing.
- Exports: DOCX/PDF (optional rich engines), SARIF, OSCAL, CSV, framework pack zip.

## Security-relevant controls already present

- Tenant scoping on services and storage prefixes.
- Authorization gate on imports/scans.
- Evidence hashing and masking.
- Append-only audit chain.
- Retest false-close guard (`asset_reached`).
- Propose-then-confirm compliance statuses (`no_exceptions` ≠ `met`).

## Gaps closed in this pass (summary)

Phase 1 “stored-not-rendered” Must items and several Phase 2 Must template items: cover, TOC, document control, environment, test types/standards, CVSS vector, OWASP/ASVS/WSTG, retest overview + retest kind, screenshot embeds, disclaimer, risk legend, DRAFT watermark, methodology phases, conclusion, tenant branding on built-ins.

## Residual risks

- No dedicated Impact/References columns (migration deferred).
- Box-type (black/grey/white) not modeled.
- Date sanity checks before sign-off not enforced.
- Rich DOCX/PDF styling still environment-dependent.
- Framework pack titles are summaries, not licensed regulatory text — human expert review required before audit use.
