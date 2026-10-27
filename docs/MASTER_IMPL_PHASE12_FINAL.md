# Master Implementation — Phase 12 Final Verification and Delivery

Final verification for Phases 0–11 of `# ATTESTRA — MASTER IMPLEMENTATION.txt`. This document is the required delivery report (sections A–L). **No git commit was made for Phase 12** (per request).

Verification date: 2026-10-27. Head revision: `0027_finding_observations_rls`. Last implementation commit on `main`: `11a7adb` (Phase 11).

---

## Checklist (Phase 12 items 1–12)

| # | Item | Result |
| --- | --- | --- |
| 1 | Relevant unit tests | **Pass** — flag, credits, auth docs, engagement types, frameworks (see J) |
| 2 | Integration: scan/dedup/evidence/reporting | **Pass** (automated) — dedup, gallery, Phase 8 reports, PDF export; live scanner E2E **not** run |
| 3 | Authorization / tenant isolation | **Pass** — `test_authorization*`, `test_tenant_matrix`, `test_phase9_security` |
| 4 | Migration checks | **Pass** — `test_phase10_migrations` + `test_migrations`; alembic head `0027_finding_observations_rls` |
| 5 | Existing regression (focused) | **Pass** on focused master-related suites; **full** `pytest -q` not re-run in Phase 12 (see K) |
| 6 | Lint / type / build | **Ruff** on credits/dedup/config/evidence/recommend/export modules: clean. No mypy/pyright configured. No frontend build (Jinja SSR) |
| 7 | Representative PDF / MD / JSON | **Inspected** via automated generation (see I); browser visual pass not requested |
| 8 | Subscription ON and OFF | **Pass** — flag suite + OFF skips consume + OFF still enforces authz docs |
| 9 | Engagement create / test execution | **Pass** (API/service level) — create VA/PT/VA+PT, admit consume, import merge; live runner workflow not exercised |
| 10 | No unsupported frameworks | **Pass** — catalogue-only recommend + invalid id rejected; library ids listed in F |
| 11 | Observations / evidence preserved | **Pass** — 2 observations + evidence under one canonical finding in DB/JSON/MD/PDF text |
| 12 | Document unexecuted tests | See **K** and table notes above |

---

## A. Implementation summary

Attestra gained organization-wide test-run credits gated by `SUBSCRIPTION_SERVICE`, Super Admin–only signed authorization download, new-engagement types limited to VA / PT / VA+PT, industry/country framework recommendations (catalogue-only), confidence-based cross-tool finding deduplication with preserved observations, evidence provenance/gallery with annotated derivatives and honest capture failures, canonical findings in HTML/PDF/Markdown/JSON exports, tenant/path/size security controls, and Alembic migrations through `0027` with SQLite-safe provenance and Postgres observation RLS. Automated coverage for Phases 1–9 areas was executed and extended in Phase 11.

Product text uses **VA + PT** for engagement key `vapt`. There is no payment provider. Credits charge once at successful scan admission. `SUBSCRIPTION_SERVICE=OFF` bypasses only subscription/credit enforcement.

---

## B. Changed files

Non-`tests/` paths introduced or modified across Phases 0–11 (`git diff 8c8735d^..11a7adb`, ~56 files / +5008/−176). Purpose by area:

| Area | Paths | Purpose |
| --- | --- | --- |
| Config / CLI | `attestra/config.py`, `attestra/cli.py` | `SUBSCRIPTION_SERVICE`, credit/refund env, `validate_runtime_config` at entrypoints |
| Credits | `attestra/credits/*` | Balance, admit consume, refund, allocate, renewal |
| AuthZ | `attestra/auth/roles.py`, `attestra/services.py`, `attestra/api.py` | `credits.allocate`; Super Admin authz document download |
| Models / RLS | `attestra/models.py`, `attestra/rls.py` | Credits, profile fields, observations, evidence provenance, NEW_ENGAGEMENT_TYPES |
| Recommend | `attestra/compliance/recommend.py`, `compliance/data/*.yaml` | Industry/country catalogues and rules |
| Dedup | `attestra/dedup.py`, importers | Soft/exact merge, observations |
| Evidence | `attestra/evidence/*`, `attestra/proof/*` | Gallery, annotate, capture failure, size/path |
| Reports | `attestra/reports/*`, templates | Canonical findings, MD export, JSON v2 provenance |
| UI | `attestra/web/templates/*`, `ui.py`, CSS | Credits page, new engagement recommend, finding gallery |
| Migrations | `migrations/versions/0023`–`0027` | Schema for credits → observation RLS |
| Docs / lat | `docs/MASTER_IMPL_PHASE*.md`, `lat.md/*` | Baseline, migrations, testing, knowledge graph |

Uncommitted by habit: `tests/` modules for Phases 1–11 (present locally; not in the Phase commits).

Phase 12 adds this file and lat updates only (uncommitted until you ask).

---

## C. Database changes

| Revision | Change | Backfill |
| --- | --- | --- |
| `0023_subscription_credits` | `tenant_credit_accounts`, `credit_transactions`, `credit_renewal_requests` (+ Postgres RLS) | Accounts created on first use / allocate |
| `0024_tenant_profile_recommend` | `tenants.country`, `regulatory_status`, `technical_scope` | Empty until profile edit |
| `0025_finding_observations` | `finding_observations`; finding dedup columns | Empty for pre-0025 findings; filled on new imports |
| `0026_evidence_provenance` | Additive evidence columns/FKs (SQLite batch + idempotent) | Defaults (`role=original`, etc.); paths/sha256 unchanged |
| `0027_finding_observations_rls` | Postgres RLS for observations; no-op on SQLite | N/A |

No automatic historical dedup merge or evidence rewrite. Details: `docs/MASTER_IMPL_PHASE10_MIGRATIONS.md`.

Upgrade: `alembic upgrade head` (or `attestra init` / serve path). Backup before production upgrade.

---

## D. APIs and UI

**APIs (representative):**

- Credits: `POST /api/credits/allocate`, renewal-request create/list/resolve, balance reads (tenant-scoped)
- Frameworks: `POST /api/frameworks/recommend`, profile catalogues
- Findings: `GET /api/findings/{fid}/observations`, `GET .../evidence/gallery`, annotate
- Authz docs: `GET /api/authorizations/{aid}/document` (admin only)
- Scans: admit path returns 402 when credits exhausted and enforcement ON
- Engagement create: rejects unsupported new types and unknown framework ids

**UI:**

- Credits page (`credits.html`) — balance, renewal, admin allocate
- New engagement — Industry/Country required for recommend; VA / PT / VA+PT only; catalogue frameworks
- Finding detail — detected-by, observations, evidence gallery / annotate
- Engagement / layout — credits link and type labels (`VA + PT`)

---

## E. Subscription and credit behaviour

- **Env:** `SUBSCRIPTION_SERVICE=ON|OFF` (missing → ON; invalid → startup `ConfigurationError`).
- **Helpers:** `parse_subscription_service`, `subscription_enforcement_enabled`, `validate_runtime_config` (API lifespan, CLI init/serve/worker).
- **Charge:** one credit at successful scan admission (`consume_for_scan_admit`); engagement create does not consume.
- **Defaults:** `ATTESTRA_INITIAL_TEST_RUN_CREDITS` (default 3).
- **Refunds:** `ATTESTRA_CREDIT_REFUND_ON_PRE_START_FAILURE` (default ON), `ATTESTRA_CREDIT_REFUND_ON_POST_START_FAILURE` (default OFF); `refund_for_scan` idempotent.
- **Allocate / renewal:** admin-only (`credits.allocate`); audited; tenant balances isolated.
- **OFF:** skips credit checks/consume only; authz docs, tenant isolation, SSRF/scope remain enforced.

No payment gateway.

---

## F. Framework recommendations

- **Mandatory:** Industry, Country.
- **Optional:** Regulatory Status/Jurisdiction, Technical Scope (refine when present).
- **Catalogue only:** recommendations and selections must exist in `load_library().frameworks`.
- **Verified catalogue ids:** `asvs_4_0`, `cert_in_2022`, `dora_2022`, `iso_27001_2022`, `iso_42001_2023`, `nist_csf_2`, `pci_dss_4`, `rbi_csf_2016`, `sebi_cscrf_2024`, `soc2`.
- **Rules:** YAML-driven (`recommend_rules.yaml`); e.g. India payments → PCI + review for CERT-In/RBI; DORA not blanket for all EU retail.
- **Limitations:** advisory / requires_review statuses; does not claim legal applicability from country alone; confirmed user selections preserved as `user_added`.

---

## G. Finding consolidation

- Engagement-scoped soft/exact matching (`attestra/dedup.py`) using location, CWE/CVE, parameter, tool evidence.
- Confidence threshold: merge when evidence supports; ambiguous mid-band flagged or left separate.
- Canonical finding keeps one top-level id; `tools` / detected-by list all scanners; `FindingObservation` rows retain originals.
- Protections: different endpoints/params stay separate; CVE alone insufficient; cross-engagement / cross-tenant never merge; reimport idempotent; historical suggestions non-destructive.
- Soft merges audited (`finding.dedup`).

---

## H. Evidence collection

| Source | What Attestra stores | Notes |
| --- | --- | --- |
| Scanner imports (ZAP, Nuclei, …) | Finding fields + observations; optional request/response/log when importer supplies | No fabricated evidence |
| Manual / API upload | Evidence rows with provenance (`role`, `source_tool`, sha256) | Size capped (`EVIDENCE_MAX_BYTES`) |
| Proof screenshots | Optional auto-capture when a capture function is registered; redaction helpers | Requires optional screenshot stack (e.g. Pillow / browser capture); missing capability → `record_capture_failure` |
| Annotations | Separate `role=annotated` derivative with `parent_evidence_id` | Original bytes/sha256 preserved |
| Capture failures | `kind=capture_failure` with reason | Honest limitation text in reports |

Unsupported without integration: arbitrary live browser capture in CI without a registered `capture_fn`; inventing screenshots when capture fails.

---

## I. Reports

Formats updated to share canonical findings:

- **HTML technical** (and related templates) — one finding; detected-by; evidence embeds prefer annotated; capture limitations listed
- **PDF** — via xhtml2pdf/weasyprint from prepared HTML (Phase 12 sample: 8 pages, contains SQL Injection, ZAP, Nuclei, F-1)
- **Markdown** — `export_engagement_markdown`: one `## F-{id}`, scanner observations, evidence metadata, authenticated download note (no public URLs)
- **JSON** — schema v2: `tools` / `detected_by`, observations, evidence provenance; no storage paths
- **XLSX** — evidence columns include provenance fields

Phase 12 automated inspection (temp engagement, ZAP+Nuclei soft merge + console evidence):

- Findings: 1; tools `zap`,`nuclei`; observations: 2; evidence: 1 (`console.txt`)
- MD: one `## F-` heading; `### Scanner observations`; `### Evidence`
- JSON: `export_schema_version` 2
- PDF engine: `xhtml2pdf`; text extract confirms finding and both tools

---

## J. Test results

Executed in Phase 12 (all green unless noted):

```text
# Master Phase 1–11 focused (+ phase10)
pytest tests/test_subscription_service_flag.py \
  tests/test_subscription_credits.py \
  tests/test_authorization_document_access.py \
  tests/test_engagement_types.py \
  tests/test_framework_recommend.py \
  tests/test_cross_tool_dedup.py \
  tests/test_evidence_gallery.py \
  tests/test_phase8_reports.py \
  tests/test_phase9_security.py \
  tests/test_phase10_migrations.py -q
# → 92 passed

pytest tests/test_phase10_migrations.py tests/test_migrations.py \
  tests/security/test_authorization.py tests/auth/test_tenant_matrix.py -q
# → 31 passed

pytest tests/security/test_authorization.py tests/auth/test_tenant_matrix.py \
  tests/test_phase9_security.py tests/test_cross_tool_dedup.py \
  tests/test_evidence_gallery.py -q
# → 55 passed

pytest tests/test_phase8_reports.py tests/test_pdf_export.py -q
# → 26 passed (PDF: 179 pypdf DeprecationWarnings only)

pytest tests/test_authorization_document_access.py::test_subscription_off_still_enforces \
  tests/test_subscription_credits.py::test_off_skips_consume -q
# → 2 passed

ruff check attestra/credits attestra/dedup.py attestra/config.py \
  attestra/evidence attestra/compliance/recommend.py \
  attestra/reports/markdown_export.py attestra/reports/engagement_export.py
# → All checks passed
```

Unresolved failures in these Phase 12 runs: **none**.

---

## K. Remaining limitations

- **Full suite** (`pytest -q` entire tree) not re-executed in Phase 12; historical notes cite intermittent/pre-existing importer or env issues — use focused suites above as the verified gate for this delivery.
- **Live scanner / Docker E2E** and Temporal/worker soak not run.
- **Browser UI** walkthrough not run (automated exports chosen for report inspection).
- **Threaded concurrent overspend** stress deferred (sequential overspend covered).
- **MIME/scope evidence** edge matrix beyond Phase 9 caps/path containment not expanded.
- **PDF visual crop / screenshot readability** not manually judged beyond text extract.
- **Regulatory mappings** remain advisory; country alone does not assert legal applicability.
- **Screenshot auto-capture** depends on optional registered capture function / extras.
- **`tests/`** for master phases remain uncommitted by project habit.
- **No payment / billing provider** (by design).

---

## L. Operational instructions

1. **Backup** production data before migrate.
2. **Migrate:** `alembic upgrade head` → expect `0027_finding_observations_rls` (see `docs/MASTER_IMPL_PHASE10_MIGRATIONS.md`, `docs/RELEASE.md`).
3. **Env (subscription):**
   - `SUBSCRIPTION_SERVICE=ON` or `OFF` (restart API and workers after change; no hot reload)
   - `ATTESTRA_INITIAL_TEST_RUN_CREDITS` (default `3`)
   - `ATTESTRA_CREDIT_REFUND_ON_PRE_START_FAILURE` (default `ON`)
   - `ATTESTRA_CREDIT_REFUND_ON_POST_START_FAILURE` (default `OFF`)
4. **Entrypoints** call `validate_runtime_config` — invalid `SUBSCRIPTION_SERVICE` fails startup.
5. **Postgres:** observation RLS applies on `0027`; SQLite uses app-level tenant checks.
6. **Optional extras:** `screenshots` (Pillow), PDF engines per install (`xhtml2pdf` in base deps; weasyprint in docs extra).
7. **Deploy:** follow `docs/RELEASE.md`; restart API/workers after config or migration changes.

---

## Commits (Phases 0–11 on local `main`)

| Commit | Phase |
| --- | --- |
| `8c8735d` | 0–1 baseline + `SUBSCRIPTION_SERVICE` |
| `968fa6c` | 2 credits |
| `37e0dcd` | 3 authz documents |
| `06e6e8d` | 4 engagement types |
| `32a99ce` | 5 framework recommend |
| `aee1eb1` | 6 cross-tool dedup |
| `a521d3d` | 7 evidence gallery |
| `e84ffef` | 8 canonical reports |
| `e9fc156` | 9 security |
| `cf77d18` | 10 migrations |
| `11a7adb` | 11 automated testing docs |

Phase 12: verification + this report (+ lat) — **not committed**.
