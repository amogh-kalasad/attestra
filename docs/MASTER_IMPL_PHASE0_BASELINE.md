# Master Implementation — Phase 0 Baseline

Baseline from repository inspection before subscription, credits, recommendations, dedup, and evidence work. Authoritative for Phases 1–12 of the master implementation command.

## Stack

| Area | Implementation |
| --- | --- |
| Backend | FastAPI (`attestra/api.py`), SQLAlchemy models, Alembic migrations |
| Frontend | Server-rendered Jinja templates (`attestra/web/`), static CSS/JS |
| Database | SQLite default; PostgreSQL via `ATTESTRA_DATABASE_URL` |
| AuthN | Bearer API keys, signed session cookies; optional OIDC |
| AuthZ | RBAC in `attestra/auth/roles.py` (`admin`, `lead`, `tester`, `reviewer`, `client_viewer`, `auditor`) |
| Config | `attestra/config.py` (env vars); no `.env.example` before Phase 1 |
| Migrations | `migrations/versions/` through `0022_auth_web` |

There is no separate Super Admin role string. Platform-wide admin is role `admin`. Organizational lead is `lead`. Tester is `tester`.

## Tenants and engagements

- `Tenant` has optional free-text `industry`; no country / regulatory-status / technical-scope catalogue fields yet.
- Engagements store `type` in `ENGAGEMENT_TYPES = (va, pt, vapt, retest, continuous)`.
- New engagement UI and API currently accept all five types; master Phase 4 will limit new creates to VA / PT / VAPT while preserving historical retest/continuous rows.
- Product display label for key `vapt` is `VA + PT` (do not print the legacy acronym in user-facing text).
- Separate `TEST_TYPES` map covers authorized scan categories (web_dast, api_dast, sast, …), distinct from engagement type.

## Subscription and credits

**Gap:** No subscription, billing, credit balance, quota, or payment-gateway code exists. Grep finds only unrelated “credit” wording in compliance assessor text.

Test-run admission today: `scan.start` permission + runner gate (signed authorization, ownership, SSRF/DNS pin, rate limits). Entry points:

- API `POST` scan start (`attestra/api.py#start_scan`)
- UI scan actions (`attestra/web/ui.py`)
- CLI scan / worker (`attestra/cli.py#cmd_worker`)
- Schedules → `services.enqueue_due_schedules`
- Durable jobs (`attestra/jobs/durable.py`) and optional Temporal orchestration

Phase 2 must add organization-wide credits with one atomic charge at admission, gated by `SUBSCRIPTION_SERVICE`.

## Signed authorization documents

- Model `Authorization` stores `document_name`, `document_path`, `sha256`, signer, window, environments.
- Add via API/UI/CLI (`services.add_authorization`); import and scans require a currently valid authorization.
- **Gap for Phase 3:** Upload/add is limited to `admin`/`lead` (`authorization.add`). No Super-Admin-only download/view route was found; document path is stored and used for validity, but retrieval is not locked to `admin` alone. Phase 3 must enforce view/download on every retrieval path.

## Compliance frameworks (authoritative catalogue)

Loaded from `attestra/compliance/data/controls.yaml` plus packs under `attestra/compliance/data/packs/`. Runtime catalogue via `load_library().frameworks`:

| ID | Source |
| --- | --- |
| `pci_dss_4` | core |
| `iso_27001_2022` | core |
| `soc2` | core |
| `asvs_4_0` | pack |
| `cert_in_2022` | pack |
| `dora_2022` | pack |
| `iso_42001_2023` | pack |
| `nist_csf_2` | pack |
| `rbi_csf_2016` | pack |
| `sebi_cscrf_2024` | pack |

Also listed in `attestra/reports/data/template_config.yaml` `supported_frameworks`. Do not invent new framework IDs. No automatic industry/country recommendation engine yet (Phase 5).

## Scanners

**Importers** (`attestra/importers/__init__.py#PARSERS`): zap, nuclei, trivy, sarif, cyclonedx, dependency_track, prowler, kube_bench, testssl, gitleaks, checkov, naabu, webcheck, observatory, ssllabs, burp, nessus.

**Runner adapters** (`attestra/runner/scanners/registry.py`): trivy, semgrep, nuclei, zap, prowler, kube_bench, testssl, gitleaks, checkov, naabu, webcheck. (Semgrep imports via SARIF.)

## Findings and deduplication

- Normalized via importers → `NormalizedFinding`; persisted as `Finding` with fingerprint merge in `services.import_results`.
- Fingerprint service: `attestra/fingerprint.py` (location/CWE/CVE/title/param/package/variant; special CAA and cert-expiry merges).
- Findings carry a `tools` list for detecting scanners; UI/report attribution exists but Phase 6 wants stronger cross-tool canonical consolidation, observation history, and conservative ambiguous-match handling.

## Evidence and screenshots

- Content-addressed storage (`attestra/storage`), masking (`attestra/evidence/mask.py`), `Evidence` model, download API with auth.
- HTTP proof pairs and replay (`attestra/proof/`).
- Screenshot redaction and auto-attach (`attestra/proof/screenshot_redact.py`, `screenshots.py`); capture_fn registry defaults empty so imports stay network-free.
- Phase 7 extends annotated derivatives, provenance, and honest failure reporting.

## Reports

HTML (Jinja), PDF, Markdown-related paths, JSON engagement export, XLSX, DOCX, SARIF, OSCAL, packs. Shared rendering in `attestra/reports/`. Phase 8 must feed all formats from the same canonical finding/evidence model.

## Security controls to preserve

Tenant scoping on services, RBAC permissions, signed-authorization import/scan gate, runner SSRF/DNS pin/ownership/rate limits, evidence masking, audit hash chain, secret store / Fernet credentials for auth-web. `SUBSCRIPTION_SERVICE=OFF` must bypass only subscription credit enforcement.

## Database changes likely in later phases

- Org credit balance + ledger (+ idempotency keys)
- Tenant/engagement profile: country, regulatory status, technical scope; industry catalogue
- Framework recommendation metadata / statuses
- Scanner observation ↔ canonical finding relationships (if schema gaps remain)
- Evidence annotation / provenance fields

## Tests and conventions

- Pytest under `tests/`; `fresh_db` fixture; `@lat:` comments for specs in `lat.md/tests.md`.
- After code changes: update `lat.md/`, run `lat check`.
- Prefer focused pytest for new work; full suite has historically had some pre-existing PDF/importer noise (see workspace notes).
- Alembic required for every schema change; do not break the audit hash chain.
- End-of-phase: ruff + relevant pytest; report files/tests; stop before next phase when scoped that way.

## Phase checklist (implementation order)

1. **Phase 1** — `SUBSCRIPTION_SERVICE` ON/OFF flag, startup validation, centralized helpers.
2. **Phase 2** — Org credits (default 3), atomic consume at scan admission, UI balance, renewal request / admin grant (no new payment provider without authorization).
3. **Phase 3** — Super Admin (`admin`) only for signed authorization document retrieval.
4. **Phase 4** — New engagement types limited to VA / PT / VAPT.
5. **Phase 5** — Industry + Country mandatory; optional regulatory/technical scope; recommend only configured frameworks.
6. **Phase 6** — Cross-tool normalization and conservative dedup with tool attribution.
7. **Phase 7** — Evidence gallery, authentic screenshots/annotations, logs, req/res, code/deps.
8. **Phase 8** — UI + PDF/MD/JSON and other formats use canonical findings/evidence.
9. **Phase 9** — Security/privacy/RBAC review.
10. **Phase 10** — Migrations and backward compatibility.
11. **Phase 11** — Automated tests for all of the above.
12. **Phase 12** — Final verification report.

## Gaps summary

| Capability | Current state |
| --- | --- |
| Subscription flag | Missing → Phase 1 |
| Org credits / renewal | Missing → Phase 2 |
| Authz doc Super-Admin-only download | Incomplete → Phase 3 |
| New engagement type filter | All five types offered → Phase 4 |
| Industry/country catalogues + recommendations | Free-text industry only → Phase 5 |
| Cross-tool canonical dedup | Fingerprint merge exists; deepen → Phase 6 |
| Annotated evidence pipeline | Partial screenshots/proof → Phase 7–8 |
