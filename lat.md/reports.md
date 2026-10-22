# Reports and signing

Produces versioned HTML reports (plus letters), freezes them by SHA-256, runs a three-step approval workflow, and signs with Ed25519 (HMAC fallback).

## Kinds

Supported report kinds for [[attestra/reports/render.py#generate_report]].

[[attestra/reports/render.py#KINDS]]: `technical`, `executive`, `compliance`, `iso_soa`, `ageing`, `closure_letter`, `attestation_letter`, `retest`. Framework required for compliance; defaulted for iso_soa. The `retest` kind renders remediation verification from [[attestra/models.py#Retest]] rows without overwriting historical evidence.

## Template configuration

Metadata-driven section lists, CVSS legend, methodology phases, and disclaimer for built-in reports.

[[attestra/reports/template_config.py#load_template_config]] reads `attestra/reports/data/template_config.yaml` (assessment types, nine frameworks, per-kind sections, export formats). Helpers: [[attestra/reports/template_config.py#kind_config]], [[attestra/reports/template_config.py#cvss_legend]], [[attestra/reports/template_config.py#methodology_phases]], [[attestra/reports/template_config.py#disclaimer_text]]. Tenant [[attestra/models.py#ReportTemplate]] may set `disclaimer` (migration `0021_finding_fields_disclaimer`); [[attestra/reports/render.py#_branding]] prefers a non-empty template disclaimer, else [[attestra/reports/template_config.py#disclaimer_text]]. Empty Jinja `source` keeps the built-in kind template so cover, logo and disclaimer still apply.

## Generation

How a report row and frozen HTML file are created.

[[attestra/reports/render.py#generate_report]]:

1. Refuse when the engagement has `window_start` and today is before that date ([[attestra/reports/render.py#_assert_not_before_window]]); a missing window start does not block. The same check runs on [[attestra/reports/render.py#submit_report]] and [[attestra/reports/render.py#sign_report]].
2. Build context from findings, imports, authorizations, compliance, and prior-engagement trend ([[attestra/reports/render.py#_context]]). Finding comments are omitted unless `include_comments=True` (default off); see [[findings#Comments]]. Context also includes test types/standards, report history with `change` labels ([[attestra/reports/render.py#_report_history]]), retests, screenshot data-URI embeds (hash-verified), list-of-figures rows ([[attestra/reports/render.py#_figures_list]]), pretty-printed `http_pair` evidence ([[attestra/reports/render.py#_http_pair_embeds]]), tenant branding (logo/cover/disclaimer override), distribution rows ([[attestra/reports/render.py#_distribution_list]]), scan history, and template-config fields.
3. Render Jinja templates under `attestra/reports/templates` (built-in cover, TOC, document control with Change column, distribution list, list of figures, risk legend, disclaimer, sign-off placeholders, appendix on technical; dedicated `retest.html.j2` for retests). Tenant sandbox Jinja wins only when `source` is non-empty; empty source keeps the built-in kind template.
4. Write under `DATA_DIR/tenants/<id>/reports/`.
5. Create [[attestra/models.py#Report]] as `draft` with version and sha256.
6. Audit the write.

## Titles

Names shown at the top of each report and in OSCAL output.

- Technical template (`attestra/reports/templates/technical.html.j2`): cover via `_base`, TOC, document control (Change column), distribution list from tenant contact ([[attestra/reports/render.py#_distribution_list]]), list of figures, scope with environment, methodology phases, standards, risk legend, findings overview with retest column, CVSS vector / OWASP / ASVS / WSTG when set, Impact / Affected URLs / References when set on the finding, embedded screenshots with Fig. captions, pretty-printed HTTP request/response pairs, disclaimer (branding override wins over template-config default), conclusion, in-report sign-off placeholders (live status stays in [[reports#Sign-off record]]), appendix of tool imports and scan runs.
- Retest template (`attestra/reports/templates/retest.html.j2`): document control with Change column, retest results, asset-reached flag, unresolved risks, evidence register.
- Compliance template (`attestra/reports/templates/compliance.html.j2`): heading "<framework name>: security testing evidence pack", page title "Compliance evidence pack".
- Executive template (`attestra/reports/templates/executive.html.j2`): "Executive summary: <engagement name>".
- [[attestra/reports/oscal.py#assessment_results]] names its result "Attestra security testing control roll-up".

Report context includes `type_label` from [[attestra/models.py#engagement_type_label]] (for key `vapt`, that is `VA + PT`). Built-in templates print that label instead of `eng.type|upper`, so generated report pages do not contain the legacy acronym.

The shared base template (`attestra/reports/templates/_base.html.j2`) adds a cover (logo/title when configured), DRAFT watermark for generated drafts, and print CSS for Page X of Y. The footer shows who generated the file, when, and the Attestra version. QA, approval and signature remain in the separate sign-off record (see [[reports#Sign-off record]]) and can be checked with `attestra verify-report`.

## Workflow

Draft reports move through submit → QA → sign, with reject back to draft.

Statuses: `draft` → `submitted` → `qa_approved` → `signed`, or `rejected` (resubmittable). Functions: [[attestra/reports/render.py#submit_report]], [[attestra/reports/render.py#qa_approve]], [[attestra/reports/render.py#qa_reject]], [[attestra/reports/render.py#sign_report]]. Author ≠ QA ≠ signer by user id; sign requires lead/admin. Legacy [[attestra/reports/render.py#approve_report]] remains as a two-person shortcut.

In the web dashboard the reports table has a "Next step" column (`attestra/web/templates/engagement.html`). It shows only the button the current user may press: "Submit for QA" (or "Resubmit for QA" after a reject) for draft or rejected reports, "QA approve" and "QA reject" (a reason is required) for submitted reports, and "Approve and sign" for QA-approved reports. Each button posts to a route in [[attestra/web/ui.py]] ([[attestra/web/ui.py#ui_submit_report]], [[attestra/web/ui.py#ui_qa_approve_report]], [[attestra/web/ui.py#ui_qa_reject_report]], [[attestra/web/ui.py#ui_sign_report]]). All four go through [[attestra/web/ui.py#_report_step]], which checks login, the role permission (`report.submit`, `report.approve`, `report.sign`) and that the report belongs to the engagement, then calls the reports service. The service still enforces status order and separation of duties: the author cannot QA, and the signer must be neither the author nor the QA reviewer. The table hides the QA buttons from the author and the sign button from the author and the QA reviewer, and shows a short "waiting for ..." note instead. Service errors come back as plain messages on the page.

## Sign-off record

A status banner added when a report is viewed in Attestra; the sealed file is never changed.

[[attestra/reports/signoff.py#banner_html]] builds one HTML block from the [[attestra/models.py#Report]] row and the result of [[attestra/reports/render.py#verify_report]]. It shows the status in plain words (draft, in QA, rejected with the QA note, QA approved, or signed by whom and when, with the QA reviewer), who made the report and when, whether the SHA-256 still matches, whether the signature is valid, the full SHA-256, and a link to the sealed file. A hash mismatch turns the banner red with a warning.

[[attestra/reports/signoff.py#inject]] returns a copy of the sealed HTML with the banner placed right after `<body>`. The view route `GET /reports/{rid}` in [[attestra/api.py#download_report]] serves that copy with `Cache-Control: no-store`. `GET /reports/{rid}/sealed` in [[attestra/api.py#download_sealed_report]] returns the file byte for byte, so its hash and signature still verify. Both routes need `report.read`, use [[attestra/api.py#_report_file]] for tenant and data-folder checks, and write a `report.download` audit event (the sealed one is marked `sealed`).

## Retests

False-close guard for remediation verification.

[[attestra/retest.py#finalize_retest]] marks `fixed` only when [[attestra/retest.py#scan_reached_finding]] is true for the linked [[attestra/models.py#ScanRun]]; otherwise `inconclusive`. Fingerprints may include `asset_id` ([[attestra/fingerprint.py#fingerprint]]).

## Signing

Ed25519 signatures verifiable with the published public key; HMAC still accepted.

[[attestra/reports/signing.py#sign]] prefers Ed25519 (`data/keys/signing.pub`); falls back to HMAC. [[attestra/reports/signing.py#verify]] accepts both. Algorithm stored on [[attestra/models.py#Report]].

## Exports

DOCX/PDF, framework packs, SARIF, OSCAL, and full-engagement JSON.

- [[attestra/reports/export.py#to_docx]] / [[attestra/reports/export.py#to_pdf]] (WeasyPrint optional; minimal PDF/DOCX always)
- [[attestra/reports/pdf.py#pdf_engine_status]] probes weasyprint then xhtml2pdf for `/api/health` / admin UI: `{"available": bool, "engine": "weasyprint"|"xhtml2pdf"|"none", "message": str}` with an actionable install hint when none load
- [[attestra/reports/packs.py#build_framework_pack]] — zip + MANIFEST.sha256
- [[attestra/reports/sarif.py#findings_to_sarif]], [[attestra/reports/oscal.py#assessment_results]], [[attestra/reports/oscal.py#poam]]; structure checks via [[attestra/reports/oscal.py#validate_oscal_structure]] and [[attestra/reports/oscal.py#schema_for_oscal_kind]] against `tests/schemas/oscal_ar_poam_min.json` (`required_top_level_ar` / `required_top_level_poam`)
- [[attestra/reports/engagement_export.py#export_engagement_json]] — full engagement JSON data export (see [[reports#Exports#JSON engagement export]]); API `GET /api/engagements/{eid}/export/json` and UI `/engagements/{eid}/export/json`
- [[attestra/reports/xlsx_export.py#export_engagement_xlsx]] — Excel workbook with Findings, Controls, and Evidence sheets (frozen header, auto-filter, formula-guarded); API `GET /api/engagements/{eid}/export/xlsx` and UI `/engagements/{eid}/export/xlsx`
- PDF/Word display: [[attestra/reports/pdf.py#_human_times]] formats timestamps in `ATTESTRA_DISPLAY_TZ` (same approach as [[attestra/web/ui.py#_display_tz]]); [[attestra/reports/pdf.py#_framework_names]] swaps raw framework keys for library display names. Iso SoA sets `soa_framework` to the library name in [[attestra/reports/render.py#generate_report]].
- Word TOC note tells readers to right-click / References › Update Table (or Update Field); [[attestra/reports/docx_export.py#_ensure_risk_legend]] injects a CVSS risk legend when the HTML lacks one (executive path), matching PDF behaviour.

### JSON engagement export

Full engagement JSON via [[attestra/reports/engagement_export.py#export_engagement_json]]: findings, controls, evidence metadata, and report metadata only (no sealed HTML, evidence bodies, or secrets); audited as `engagement.exported`.

Payload includes `version` ([[attestra/__init__.py#__version__]]), `export_schema_version` ([[attestra/reports/engagement_export.py#EXPORT_SCHEMA_VERSION]], currently 1), engagement metadata (`id`, `name`, `type`, `type_label` via [[attestra/models.py#engagement_type_label]] so `vapt` shows as `VA + PT`, `frameworks`, window dates, tenant name), findings (API-aligned fields including impact, affected_urls, references, cvss_vector, location — self-contained, no import from `api.py`), `controls` keyed by framework from [[attestra/services.py#compliance]], evidence metadata only (`kind`, `filename`, `sha256`, `note`, `finding_id`), and report metadata (`id`, `kind`, `framework`, `version`, `status`, `sha256`, `generated_at`, `generated_by`). Audited as `engagement.exported` with `format=json`.

## Framework packs

Zip binders with a sha256 manifest for PCI / ISO / SOC 2 evidence export.

[[attestra/reports/packs.py#build_framework_pack]] builds a framework-indexed zip under `DATA_DIR/tenants/<id>/packs/` with `MANIFEST.sha256`. The path is fixed per engagement/framework and sealed `0o444`; rebuilds chmod+unlink the prior zip before rewrite so re-download does not hit PermissionError.

## Verification

Checking that a frozen report still matches its hash and signature.

[[attestra/reports/render.py#verify_report]] checks hash + signature. Tampering the frozen HTML breaks verification.
