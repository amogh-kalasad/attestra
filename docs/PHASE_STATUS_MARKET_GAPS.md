# Market-gap phases — final status (Phase 9)

Snapshot of the revised market-gaps plan (`Attestra_GrokCLI_Market_Gaps_Phase_Wise_Revised.md`) against this repository. Status values: **Done** / **Partly** / **Not done**.

Evidence basis: commits `2ad9127` (Phases 1–2), `efe4cc4` (Phase 3), `b2fa472` (Phase 4), `e18bafd` (Phase 5); uncommitted Phase 6–9 trees. Focused market-gap modules green. Old ASV / unsupported-tool / Postgres-head failures fixed. PDF export suite green after xhtml2pdf install + `prepare_html` fixes.

Phases 6–9 implementation and tests are still **uncommitted** (Section 0: leave `tests/` uncommitted; owner reviews pushes).

---

## Status table

| Plan item | Status | Files changed (high level) | Tests added |
| --- | --- | --- | --- |
| **Phase 1 — Integrity (P0-1…P0-6)** | **Done** | `services` / compliance confirm gates, share badge, `/metrics` auth, risk-acceptance CLI/API/UI, audit `control.confirm_refused` | `tests/test_phase0_integrity.py` (12) |
| P0-1 Auditor-only control confirm | Done | `attestra/services.py`, roles/API 403 + audit | phase0 integrity |
| P0-2 Block `met` with open C/H/M findings | Done | confirm path names open findings; override flag | phase0 integrity |
| P0-3 Risk acceptance requires record | Done | `accept_risk` API/UI/CLI | phase0 integrity |
| P0-4 Share untested ≠ A+/100 | Done | share service + public badge | phase0 integrity |
| P0-5 Protect `/metrics` | Done | default 401 unless token/admin/anon opt-in | phase0 / observability |
| P0-6 Risk acceptance ≠ met for CC3.2 / Art.6 | Done | evidence derivation → partial | phase0 integrity |
| **Phase 2 — Bugs/UX (P1-4…P1-15 + labels)** | **Done** | engagement filters, evidence download, ownership TXT UI, confirm modal, workflow deactivate, display labels, alerts emails, iso_soa display TZ | `tests/test_phase2_bugs.py` (11), `tests/test_phase1_stability.py` |
| P1-4 ISO/SOC 2 shared sampling | Done | `compliance/sampling.py`, SOC 2 path | phase1 stability |
| P1-5 Select-all frameworks | Done | `new_engagement.html` + JS | phase1 / UI |
| P1-6 Findings filters | Done | engagement page + API filters | phase2 bugs |
| P1-7 Library apply flash | Done | library UI flash | phase2 (covered in UX pass) |
| P1-8 Invite may create lead (admin) | Done | users invite form | phase2 UX commit |
| P1-9 Alerts skip revoked invites | Done | `alerts/service.py` known emails | phase2 bugs |
| P1-10 iso_soa display name + TZ | Done | PDF/render display time | phase2 bugs |
| P1-11 Evidence download + replay status | Done | UI download route | phase2 bugs |
| P1-12 Workflow rule deactivate | Done | API/UI/docs consistent deactivate | phase2 bugs |
| P1-13 In-page confirm modal | Done | `_layout.html` + `attestra.js` | phase2 bugs |
| P1-14 Authorization upload one-click | Done | upload form UX | phase2 UX commit |
| P1-15 Ownership token + DNS/well-known copy | Done | `asset.html` | phase2 bugs |
| Display labels (secure_config, web_dast, …) | Done | UI/PDF/Word label map | phase2 bugs |
| **Phase 3 — Report content (P2-*)** | **Done** | technical/retest templates, finding fields migration `0021`, CVSS validate, HTTP pair embeds, LoF, branding, distribution/sign-off/appendix | `tests/test_phase3_reports.py` (14) |
| P2-1 Version / change history | Done | document-control Change column | phase3 reports |
| P2-2 CVSS vector | Done | `scoring.py` + finding detail | phase3 reports |
| P2-3 OWASP/ASVS/WSTG refs shown | Done | technical template | phase3 reports |
| P2-4 Retest column + retest kind | Done | retest template / overview | phase3 + earlier |
| P2-5 Screenshot embeds + captions | Done | HTML/DOCX; PDF soft if no pypdf | phase3 reports |
| P2-6 Tenant logo / cover | Done | ReportTemplate branding | phase3 reports |
| P2-7 Scope env / types / standards | Done | technical scope section | phase3 reports |
| P2-9 List of figures + TOC note | Done | `_figures_list`; Word update-field note | phase3 reports |
| P2-10 Risk legend in Word | Done | docx inject when missing | phase3 reports |
| P2-11 Editable disclaimer | Done | branding override | phase3 reports |
| P2-14 Front/back matter | Done | distribution, methodology, conclusion, appendix, sign-off, date check | phase3 reports |
| P2-15 Impact / Affected URLs / References | Done | model + API + template | phase3 reports |
| P2-16 HTTP request/response in report | Done | masked `http_pair` embeds | phase3 reports |
| **Phase 4 — Exports (P3-*)** | **Done** | `xlsx_export.py`, `engagement_export.py`, PDF health fields, OSCAL schema helper, `requirements.txt` / `pyproject` align | `tests/test_phase4_market_exports.py` (12) |
| P3-4 Excel XLSX (3 sheets) + UI/API | Done | Findings/Controls/Evidence; formula guard | phase4 market exports |
| P3-6 JSON engagement export + UI/API | Done | versioned payload; evidence metadata only | phase4 market exports |
| P3-5 OSCAL AR/POA&M schema tests | Done | min schema + kind helper | phase4 market exports |
| P3-3 PDF engine health message | Done | `/api/health` `pdf` / `pdf_engine` / `pdf_message` | phase4 market exports |
| Word re-export twice every kind | Done | `export_report_formats` loop | phase4 market exports |
| **Phase 5 — Workflow (P4-1…P4-6)** | **Done** | assignments, ticket two-way + ServiceNow/Azure stubs, webhook tests, AI env-only keys, ownership token reuse + Verify now, GRC push off-by-default | `tests/test_phase5_*.py` (assignment, tickets, webhooks, ai, ownership, grc) |
| P4-1 Finding assignment UI/filter/audit | Done | `assignments.py` + engagement/finding UI | test_phase5_assignment |
| P4-2 Ticket sync + SNOW/ADO stubs | Done | `integrations/tickets.py` + stubs | test_phase5_tickets |
| P4-3 Webhooks delivery/retry/signature | Done | local receiver coverage | test_phase5_webhooks |
| P4-4 AI drafts env-only key | Done | OpenAI header-only; Ollama default | test_phase5_ai |
| P4-5 Ownership token reuse + Verify now | Done | asset page + audit | test_phase5_ownership |
| P4-6 GRC Vanta/Drata/Sprinto/webhook | Done | `integrations/grc.py` off by default | test_phase5_grc |
| **Phase 6 — Auth website testing** | **Partly** | New package tree + migration `0022_auth_web`; feature flag off by default; no durable crawl job queue yet; New Engagement wizard does not yet host credential form (post-create coverage page instead) | `tests/test_phase6_*.py` (credentials, crawl, checklists, profiles API, mock smoke, screenshot_redact) ~34 |
| Phase 6 credentials store | Done | `attestra/credentials/store.py` Fernet + opaque `secret_ref`; fail-closed without key | test_phase6_credentials |
| Phase 6 auth profiles API/UI | Done | `auth_web/profiles.py` + `/api/auth-web` + `/engagements/{id}/auth-coverage` | test_phase6_auth_profiles_api (+ UI templates) |
| Phase 6 New Engagement auth step | Partly | Guidance on create flow; secret form lives on auth-coverage after engagement exists (no `eid` at create) | docs/AUTH_WEB_TESTING.md; UI coverage page |
| Phase 6 crawl / scope / SSRF | Done | `auth_web/crawl.py`, `scope.py`, `limits.py`; Playwright preferred, httpx fallback | test_phase6_auth_web_crawl |
| Phase 6 forms / synthetic data | Done | `auth_web/forms.py` non-secret synthetic fills | crawl/forms unit tests |
| Phase 6 checklists + coverage | Done | WSTG/ASVS subset; skipped ≠ passed; coverage summary | test_phase6_checklists_coverage |
| Phase 6 screenshot redaction | Done | DOM prep JS, PNG metadata strip, optional Pillow region redact | test_phase6_screenshot_redact |
| Phase 6 local mock smoke | Done | `tests/fixtures/auth_web_mock_app.py` | test_phase6_auth_mock_smoke |
| Phase 6 live browser/job e2e | Partly | Unit/API/mock coverage; no separate durable Temporal/job worker for auth-web crawl | — |
| **Phase 7 — Testing depth (P5-1…P5-6)** | **Partly** | Reuses Phase 6 components; ZAP auth prepared; screenshots optional `capture_fn` | `tests/test_phase7_{cli_scan,zap_auth,role_scan,tamper,screenshots,checklist_report}.py` (~36) |
| P5-1 CLI `attestra scan` → `request_scan` | Done | `attestra/cli.py` same gate/audit as UI | test_phase7_cli_scan |
| P5-2 ZAP auth contexts | Partly | `auth_web/zap_auth.py` form/header/cookie; secrets via store; `ZapAdapter` `-n`/`-U` when enabled — **prepared, not live Docker e2e** | test_phase7_zap_auth |
| P5-3 Multi-role comparison | Done | `auth_web/role_scan.py` read-only diffs → findings | test_phase7_role_scan |
| P5-4 Gated IDOR / tamper | Done | `auth_web/tamper.py` plan-default; intrusive gate + ownership | test_phase7_tamper |
| P5-5 Auto screenshots on findings | Partly | `proof/screenshots.py`; **`capture_fn` optional / registry empty by default** (imports stay network-free); redaction reused | test_phase7_screenshots |
| P5-6 Checklist in technical report | Done | `#auth-checklist` via report context; seeds when flag on | test_phase7_checklist_report |
| **Phase 8 — Packs / portal / extras (P6-1…P6-6)** | **Done** | ASVS pack, Top 10 report, portal remediation, dashboard, library/CERT-In, public verify+QR, Safe-to-Host + SEBI timeline | `tests/test_phase8_*.py` |
| P6-1 ASVS 4.0 pack + OWASP Top 10 view | Done | `compliance/data/packs/asvs_4_0.yaml`, `owasp_top10` template | test_phase8_asvs_top10 |
| P6-2 Client remediation portal | Done | comment / `client_fix` evidence / retest; auditor read-only; branding | test_phase8_portal_remediation |
| P6-3 Staff metrics dashboard | Done | `dashboards.py` + `/dashboard` | test_phase8_dashboard |
| P6-4 Library seed/import + CERT-In verify | Done | import convert + CERT-In titles | test_phase8_library_certin |
| P6-5 Public verify + QR (respects P0-4) | Done | `attestra/verify/` HMAC URL + QR SVG | test_phase8_verify_public |
| P6-6 Safe-to-Host + SEBI timeline | Done | attestation block; `sebi_timeline` staff UI | test_phase8_safe_to_host_sebi |
| **Phase 9 — Final check** | **Done** | Status doc; README/SETUP; VAPT scrub; importer/PDF/Postgres fixes | (this file) |
| P9-1 ruff + pytest + `lat check` | Done | `ruff` / `lat check` clean; PDF suite + old failures green | — |
| P9-2 Old failures (ASV / unsupported tool / Postgres head) | Done | unsupported tool → `not_a_real_tool`; RLS head `0022_auth_web`; ASV green | — |
| P9-3 README / SETUP_GUIDE / requirements | Done | Auth-web, ASVS, verify, SEBI, Safe-to-Host, CLI scan documented | — |
| P9-4 No user-facing "VAPT" / machine paths | Done | Marketing/docs use “security testing” / “VA + PT”; type key `vapt` kept | — |
| P9-5 Status table for owner | Done | `docs/PHASE_STATUS_MARKET_GAPS.md` | — |

---

## Known remaining limitations

**Previously cited leftovers (ASV import, unsupported-tool, Postgres alembic head) are fixed.** PDF export suite passes with xhtml2pdf installed and `prepare_html` Contents/legend injection.

**Phase-focused market modules** (Phases 0–8 tests listed in the table) were green in dedicated runs.

**Notes / limitations (honest Partly):**

- ZAP authenticated scanning is **unit/config prepared**; no live ZAP Docker end-to-end in CI.
- Finding screenshots require an injected/registered **`capture_fn`** (or PNG bytes); default import path stays network-free.
- Auth-web credential UI is on the **post-create coverage page**, not a full New Engagement multi-step wizard.
- Playwright is preferred for crawl when installed; pure-Python fallback is used otherwise.
- Phases 6–8 code/tests are largely **uncommitted**; Phases 1–5 are on `main` via the commits above.

---

## How to re-verify

```bash
ruff check .
pytest -q tests/test_phase0_integrity.py tests/test_phase1_stability.py tests/test_phase2_bugs.py tests/test_phase3_reports.py tests/test_phase4_market_exports.py tests/test_phase5_assignment.py tests/test_phase5_tickets.py tests/test_phase5_webhooks.py tests/test_phase5_ai.py tests/test_phase5_ownership.py tests/test_phase5_grc.py tests/test_phase6_credentials.py tests/test_phase6_auth_web_crawl.py tests/test_phase6_checklists_coverage.py tests/test_phase6_auth_profiles_api.py tests/test_phase6_auth_mock_smoke.py tests/test_phase6_screenshot_redact.py tests/test_phase7_cli_scan.py tests/test_phase7_zap_auth.py tests/test_phase7_role_scan.py tests/test_phase7_tamper.py tests/test_phase7_screenshots.py tests/test_phase7_checklist_report.py tests/test_phase8_asvs_top10.py tests/test_phase8_portal_remediation.py tests/test_phase8_dashboard.py tests/test_phase8_library_certin.py tests/test_phase8_verify_public.py tests/test_phase8_safe_to_host_sebi.py
pytest -q
lat check
```
