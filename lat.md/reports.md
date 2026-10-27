# Reports and signing

Produces versioned HTML reports (plus letters), freezes them by SHA-256, runs a three-step approval workflow, and signs with Ed25519 (HMAC fallback).

## Kinds

Supported report kinds for [[attestra/reports/render.py#generate_report]].

[[attestra/reports/render.py#KINDS]]: `technical`, `executive`, `compliance`, `iso_soa`, `ageing`, `closure_letter`, `attestation_letter`, `retest`, `owasp_top10`. Framework required for compliance; defaulted for iso_soa. The `retest` kind renders remediation verification from [[attestra/models.py#Retest]] rows without overwriting historical evidence. The `owasp_top10` kind groups findings by OWASP Top 10 2021 (optional LLM Top 10 2025 block).

## Template configuration

Metadata-driven section lists, CVSS legend, methodology phases, and disclaimer for built-in reports.

[[attestra/reports/template_config.py#load_template_config]] reads `attestra/reports/data/template_config.yaml` (assessment types, built-in plus pack frameworks including `asvs_4_0`, per-kind sections including `owasp_top10`, export formats). Helpers: [[attestra/reports/template_config.py#kind_config]], [[attestra/reports/template_config.py#cvss_legend]], [[attestra/reports/template_config.py#methodology_phases]], [[attestra/reports/template_config.py#disclaimer_text]]. Tenant [[attestra/models.py#ReportTemplate]] may set `disclaimer` (migration `0021_finding_fields_disclaimer`); [[attestra/reports/render.py#_branding]] prefers a non-empty template disclaimer, else [[attestra/reports/template_config.py#disclaimer_text]]. Empty Jinja `source` keeps the built-in kind template so cover, logo and disclaimer still apply.

## Generation

How a report row and frozen HTML file are created.

[[attestra/reports/render.py#generate_report]]:

1. Refuse when the engagement has `window_start` and today is before that date ([[attestra/reports/render.py#_assert_not_before_window]]); a missing window start does not block. The same check runs on [[attestra/reports/render.py#submit_report]] and [[attestra/reports/render.py#sign_report]].
2. Build context from findings, imports, authorizations, compliance, and prior-engagement trend ([[attestra/reports/render.py#_context]]). Finding comments are omitted unless `include_comments=True` (default off); see [[findings#Comments]]. Context also includes test types/standards, report history with `change` labels ([[attestra/reports/render.py#_report_history]]), retests, screenshot data-URI embeds (hash-verified; annotated preferred over originals via [[attestra/reports/render.py#_evidence_embeds]]), list-of-figures rows ([[attestra/reports/render.py#_figures_list]]), pretty-printed `http_pair` evidence ([[attestra/reports/render.py#_http_pair_embeds]]), scanner observations ([[attestra/reports/render.py#_observations_by_finding]]), capture-failure limitations ([[attestra/reports/render.py#_evidence_limitations]]), tenant branding (logo/cover/disclaimer override), distribution rows ([[attestra/reports/render.py#_distribution_list]]), scan history, template-config fields, authenticated security-testing checklist data via [[attestra/reports/render.py#_auth_web_report_context]] (`auth_checklist` / optional `auth_coverage`; never secrets), Safe-to-Host fields via [[attestra/reports/render.py#_safe_to_host_context]], and optional SEBI timeline via [[attestra/reports/render.py#_sebi_timeline_report_context]].
3. Render Jinja templates under `attestra/reports/templates` (built-in cover, TOC, document control with Change column, distribution list, list of figures, risk legend, disclaimer, sign-off placeholders, appendix on technical; dedicated `retest.html.j2` for retests). Tenant sandbox Jinja wins only when `source` is non-empty; empty source keeps the built-in kind template.
4. Write under `DATA_DIR/tenants/<id>/reports/`.
5. Create [[attestra/models.py#Report]] as `draft` with version and sha256.
6. Audit the write.

## Titles

Names shown at the top of each report and in OSCAL output.

- Technical template (`attestra/reports/templates/technical.html.j2`): cover via `_base`, TOC, document control (Change column), distribution list from tenant contact ([[attestra/reports/render.py#_distribution_list]]), list of figures, scope with environment, methodology phases, standards, risk legend, findings overview with retest column, CVSS vector / OWASP / ASVS / WSTG when set, Impact / Affected URLs / References when set on the finding, detecting tools plus scanner observations, embedded screenshots with attributed Fig. captions (aspect preserved), pretty-printed HTTP request/response pairs, evidence capture limitations when screenshot capture failed, optional `#auth-checklist` / "Authenticated security testing checklist" table when `auth_checklist` is non-empty (skipped/blocked ≠ passed; no `secret_ref`), disclaimer (branding override wins over template-config default), conclusion, in-report sign-off placeholders (live status stays in [[reports#Sign-off record]]), appendix of tool imports and scan runs.
- Retest template (`attestra/reports/templates/retest.html.j2`): document control with Change column, retest results, asset-reached flag, unresolved risks, evidence register.
- Compliance template (`attestra/reports/templates/compliance.html.j2`): heading "<framework name>: security testing evidence pack", page title "Compliance evidence pack".
- OWASP Top 10 template (`attestra/reports/templates/owasp_top10.html.j2`): category headings from [[attestra/compliance/owasp.py#group_findings_by_top10]]; optional LLM 2025 section when [[attestra/compliance/owasp.py#should_show_llm_top10]] is true.
- Attestation template (`attestra/reports/templates/attestation_letter.html.j2`): count-only letter plus Safe-to-Host block (see [[reports#Safe-to-Host attestation]]).
- Executive template (`attestra/reports/templates/executive.html.j2`): "Executive summary: <engagement name>"; may show a one-line authenticated checklist coverage summary when `auth_coverage.checklist.total` is set.
- [[attestra/reports/oscal.py#assessment_results]] names its result "Attestra security testing control roll-up".

Report context includes `type_label` from [[attestra/models.py#engagement_type_label]] (for key `vapt`, that is `VA + PT`). Built-in templates print that label instead of `eng.type|upper`, so generated report pages do not contain the legacy acronym.

The shared base template (`attestra/reports/templates/_base.html.j2`) adds a cover (logo/title when configured), DRAFT watermark for generated drafts, and print CSS for Page X of Y. The footer shows who generated the file, when, and the Attestra version. QA, approval and signature remain in the separate sign-off record (see [[reports#Sign-off record]]) and can be checked with `attestra verify-report`.

## Safe-to-Host attestation

Safe-to-Host style wording on the attestation letter without claiming certification.

[[attestra/reports/render.py#_safe_to_host_context]] always sets `safe_to_host` plus client, engagement, authorization-present, environments, and open critical/high count. The attestation template keeps the existing letter and, when `safe_to_host` is true, adds a `#safe-to-host` section stating that hosting/go-live remains the client's decision and that the letter is not a compliance certification. Wording uses "security testing" only (never the legacy acronym).

## Workflow

Draft reports move through submit → QA → sign, with reject back to draft.

Statuses: `draft` → `submitted` → `qa_approved` → `signed`, or `rejected` (resubmittable). Functions: [[attestra/reports/render.py#submit_report]], [[attestra/reports/render.py#qa_approve]], [[attestra/reports/render.py#qa_reject]], [[attestra/reports/render.py#sign_report]]. Author ≠ QA ≠ signer by user id; sign requires lead/admin. Legacy [[attestra/reports/render.py#approve_report]] remains as a two-person shortcut.

In the web dashboard the reports table has a "Next step" column (`attestra/web/templates/engagement.html`). It shows only the button the current user may press: "Submit for QA" (or "Resubmit for QA" after a reject) for draft or rejected reports, "QA approve" and "QA reject" (a reason is required) for submitted reports, and "Approve and sign" for QA-approved reports. Each button posts to a route in [[attestra/web/ui.py]] ([[attestra/web/ui.py#ui_submit_report]], [[attestra/web/ui.py#ui_qa_approve_report]], [[attestra/web/ui.py#ui_qa_reject_report]], [[attestra/web/ui.py#ui_sign_report]]). All four go through [[attestra/web/ui.py#_report_step]], which checks login, the role permission (`report.submit`, `report.approve`, `report.sign`) and that the report belongs to the engagement, then calls the reports service. The service still enforces status order and separation of duties: the author cannot QA, and the signer must be neither the author nor the QA reviewer. The table hides the QA buttons from the author and the sign button from the author and the QA reviewer, and shows a short "waiting for ..." note instead. Service errors come back as plain messages on the page.

## Sign-off record

A status banner added when a report is viewed in Attestra; the sealed file is never changed.

[[attestra/reports/signoff.py#banner_html]] builds one HTML block from the [[attestra/models.py#Report]] row and the result of [[attestra/reports/render.py#verify_report]]. It shows the status in plain words (draft, in QA, rejected with the QA note, QA approved, or signed by whom and when, with the QA reviewer), who made the report and when, whether the SHA-256 still matches, whether the signature is valid, the full SHA-256, and a link to the sealed file. A hash mismatch turns the banner red with a warning. When the view route passes `pdf_url` / `docs_url`, the banner also shows screen-only **Download PDF** and **Download Docs** buttons (hidden when printing); those links are not written into the sealed file.

[[attestra/reports/signoff.py#inject]] returns a copy of the sealed HTML with the banner placed right after `<body>`. The view route `GET /reports/{rid}` in [[attestra/api.py#download_report]] serves that copy with `Cache-Control: no-store` and the PDF/Docs export links. `GET /reports/{rid}/export/{fmt}` in [[attestra/api.py#download_report_export]] builds or rebuilds PDF (`fmt=pdf`) or Word (`fmt=docx`) via [[attestra/reports/export.py#export_report_formats]] and downloads the file (`report.exported` audit). `GET /reports/{rid}/sealed` in [[attestra/api.py#download_sealed_report]] returns the file byte for byte, so its hash and signature still verify. View and sealed routes need `report.read`, use [[attestra/api.py#_report_file]] for tenant and data-folder checks, and write a `report.download` audit event (the sealed one is marked `sealed`). PDF/Docs buttons appear only on the report HTML view, not on the engagement page.

## Retests

False-close guard for remediation verification.

[[attestra/retest.py#request_retest]] accepts findings in `validated` or `fixed` status (used by staff and the client portal with a required note). [[attestra/retest.py#finalize_retest]] marks `fixed` only when [[attestra/retest.py#scan_reached_finding]] is true for the linked [[attestra/models.py#ScanRun]]; otherwise `inconclusive`. Fingerprints may include `asset_id` ([[attestra/fingerprint.py#fingerprint]]). Client portal requests need `portal.retest_request`; see [[interfaces#Client remediation portal]].

## Signing

Ed25519 signatures verifiable with the published public key; HMAC still accepted.

[[attestra/reports/signing.py#sign]] prefers Ed25519 (`data/keys/signing.pub`); falls back to HMAC. [[attestra/reports/signing.py#verify]] accepts both. Algorithm stored on [[attestra/models.py#Report]].

## Exports

DOCX/PDF, framework packs, SARIF, OSCAL, and full-engagement JSON.

- [[attestra/reports/export.py#to_docx]] / [[attestra/reports/export.py#to_pdf]] (WeasyPrint optional; minimal PDF/DOCX always). PDF prefers weasyprint then xhtml2pdf; when both fail, [[attestra/reports/export.py#to_pdf]] runs [[attestra/reports/pdf.py#prepare_html]] with `for_engine="minimal"` before [[attestra/reports/export.py#_minimal_pdf]] so legends, disclaimer, display times, and DRAFT text still appear. Operators download via **Download PDF** / **Download Docs** on the report HTML view only (`GET /reports/{rid}/export/pdf|docx` in [[attestra/api.py#download_report_export]]); API `POST /api/reports/{rid}/export` still builds both formats.
- [[attestra/reports/pdf.py#pdf_engine_status]] probes weasyprint then xhtml2pdf for `/api/health` / admin UI: `{"available": bool, "engine": "weasyprint"|"xhtml2pdf"|"none", "message": str}` with an actionable install hint when none load
- [[attestra/reports/packs.py#build_framework_pack]] — zip + MANIFEST.sha256
- [[attestra/reports/sarif.py#findings_to_sarif]], [[attestra/reports/oscal.py#assessment_results]], [[attestra/reports/oscal.py#poam]]; structure checks via [[attestra/reports/oscal.py#validate_oscal_structure]] and [[attestra/reports/oscal.py#schema_for_oscal_kind]] against `tests/schemas/oscal_ar_poam_min.json` (`required_top_level_ar` / `required_top_level_poam`)
- [[attestra/reports/engagement_export.py#export_engagement_json]] — full engagement JSON data export (see [[reports#Exports#JSON engagement export]]); API `GET /api/engagements/{eid}/export/json` and UI `/engagements/{eid}/export/json`
- [[attestra/reports/markdown_export.py#export_engagement_markdown]] — consolidated findings Markdown with evidence references (see [[reports#Exports#Markdown engagement export]]); API `GET /api/engagements/{eid}/export/markdown` and UI `/engagements/{eid}/export/markdown`
- [[attestra/reports/xlsx_export.py#export_engagement_xlsx]] — Excel workbook with Findings, Controls, and Evidence sheets (frozen header, auto-filter, formula-guarded); API `GET /api/engagements/{eid}/export/xlsx` and UI `/engagements/{eid}/export/xlsx`
- PDF/Word display: [[attestra/reports/pdf.py#_human_times]] formats timestamps in `ATTESTRA_DISPLAY_TZ` (same approach as [[attestra/web/ui.py#_display_tz]]); [[attestra/reports/pdf.py#_framework_names]] swaps raw framework keys for library display names. Iso SoA sets `soa_framework` to the library name in [[attestra/reports/render.py#generate_report]].
- PDF Contents / legend: [[attestra/reports/pdf.py#prepare_html]] replaces the screen TOC with a plain `<h2 class="toc-title">Contents</h2>` (plus `<pdf:toc />` for xhtml2pdf), injects Severity Legend / Disclaimer when the sealed HTML lacks them, stamps DRAFT via ReportLab under the page text while unsigned, and emits extractable `Page X of Y` footers.
- Word TOC note tells readers to right-click / References › Update Table (or Update Field); [[attestra/reports/docx_export.py#_ensure_risk_legend]] injects a CVSS risk legend when the HTML lacks one (executive path), matching PDF behaviour.

### JSON engagement export

Full engagement JSON via [[attestra/reports/engagement_export.py#export_engagement_json]]: findings, observations, controls, evidence metadata, and report metadata only (no sealed HTML, evidence bodies, or secrets); audited as `engagement.exported`.

Payload includes `version` ([[attestra/__init__.py#__version__]]), `export_schema_version` ([[attestra/reports/engagement_export.py#EXPORT_SCHEMA_VERSION]], currently 2), engagement metadata (`id`, `name`, `type`, `type_label` via [[attestra/models.py#engagement_type_label]] so `vapt` shows as `VA + PT`, `frameworks`, window dates, tenant name), findings (API-aligned fields including `detected_by`, dedup fields, impact, remediation — self-contained, no import from `api.py`), `observations` from [[attestra/models.py#FindingObservation]], `controls` keyed by framework from [[attestra/services.py#compliance]], evidence metadata (kind/role/source/capture status/parent — never path or body), and report metadata (`id`, `kind`, `framework`, `version`, `status`, `sha256`, `generated_at`, `generated_by`). Audited as `engagement.exported` with `format=json`.

### Markdown engagement export

Readable Markdown of the same consolidated finding set via [[attestra/reports/markdown_export.py#export_engagement_markdown]].

Includes detecting tools, scanner observations, remediation, and evidence references by id/sha256/role (authenticated download only; no public URLs). Audited as `engagement.exported` with `format=markdown`.

## Framework packs

Zip binders with a sha256 manifest for PCI / ISO / SOC 2 evidence export.

[[attestra/reports/packs.py#build_framework_pack]] builds a framework-indexed zip under `DATA_DIR/tenants/<id>/packs/` with `MANIFEST.sha256`. The path is fixed per engagement/framework and sealed `0o444`; rebuilds chmod+unlink the prior zip before rewrite so re-download does not hit PermissionError.

## Verification

Checking that a frozen report still matches its hash and signature.

[[attestra/reports/render.py#verify_report]] checks hash + signature. Tampering the frozen HTML breaks verification.

### Public page

HMAC-signed public URL that shows sealed-report verification without login.

`GET /verify/reports/{rid}?sig=…` ([[attestra/verify/routes.py#public_verify_report]]) where `sig` is HMAC-SHA256 of `{rid}:{sha256}` over the session secret ([[attestra/verify/service.py#make_sig]] / [[attestra/verify/service.py#check_sig]]). Only `status=signed` reports with a valid sig render; bad or missing sig and unsigned drafts return 404. The page (`attestra/web/templates/verify_public.html`, extends `_public.html`) shows kind, engagement name, SHA-256, signed_at, signer, algorithm, and hash/signature validity — never findings, evidence, sealed HTML, or letter grades. [[attestra/verify/service.py#public_view]] also sets `untested` via [[attestra/verify/service.py#engagement_untested]] (P0-4) and embeds an inline QR of the absolute URL from [[attestra/verify/qr_svg.py#qr_svg]].

