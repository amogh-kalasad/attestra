# Reports and signing

Produces versioned HTML reports (plus letters), freezes them by SHA-256, runs a three-step approval workflow, and signs with Ed25519 (HMAC fallback).

## Kinds

Supported report kinds for [[attestra/reports/render.py#generate_report]].

[[attestra/reports/render.py#KINDS]]: `technical`, `executive`, `compliance`, `iso_soa`, `ageing`, `closure_letter`, `attestation_letter`. Framework required for compliance; defaulted for iso_soa.

## Generation

How a report row and frozen HTML file are created.

[[attestra/reports/render.py#generate_report]]:

1. Build context from findings, imports, authorizations, compliance, and prior-engagement trend ([[attestra/reports/render.py#_context]]). Finding comments are omitted unless `include_comments=True` (default off); see [[findings#Comments]].
2. Render Jinja templates under `attestra/reports/templates`.
3. Write under `DATA_DIR/tenants/<id>/reports/`.
4. Create [[attestra/models.py#Report]] as `draft` with version and sha256.
5. Audit the write.

## Titles

Names shown at the top of each report and in OSCAL output.

- Technical template (`attestra/reports/templates/technical.html.j2`): page title "Technical security testing report", heading "Technical security testing report: <engagement name>".
- Compliance template (`attestra/reports/templates/compliance.html.j2`): heading "<framework name>: security testing evidence pack", page title "Compliance evidence pack".
- Executive template (`attestra/reports/templates/executive.html.j2`): "Executive summary: <engagement name>".
- [[attestra/reports/oscal.py#assessment_results]] names its result "Attestra security testing control roll-up".

Report context includes `type_label` from [[attestra/models.py#engagement_type_label]] (for key `vapt`, that is `VA + PT`). Built-in templates print that label instead of `eng.type|upper`, so generated report pages do not contain the legacy acronym.

The shared footer in `attestra/reports/templates/_base.html.j2` shows who generated the file, when, and the Attestra version. It says QA, approval and signature are not inside the file; they live in the separate sign-off record (see [[reports#Sign-off record]]) and can be checked with `attestra verify-report`.

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

DOCX/PDF, framework packs, SARIF, and OSCAL.

- [[attestra/reports/export.py#to_docx]] / [[attestra/reports/export.py#to_pdf]] (WeasyPrint optional; minimal PDF/DOCX always)
- [[attestra/reports/packs.py#build_framework_pack]] — zip + MANIFEST.sha256
- [[attestra/reports/sarif.py#findings_to_sarif]], [[attestra/reports/oscal.py#assessment_results]], [[attestra/reports/oscal.py#poam]]

## Framework packs

Zip binders with a sha256 manifest for PCI / ISO / SOC 2 evidence export.

[[attestra/reports/packs.py#build_framework_pack]] builds a framework-indexed zip under `DATA_DIR/tenants/<id>/packs/` with `MANIFEST.sha256`. The path is fixed per engagement/framework and sealed `0o444`; rebuilds chmod+unlink the prior zip before rewrite so re-download does not hit PermissionError.

## Verification

Checking that a frozen report still matches its hash and signature.

[[attestra/reports/render.py#verify_report]] checks hash + signature. Tampering the frozen HTML breaks verification.
