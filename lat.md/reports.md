# Reports and signing

Produces versioned HTML reports (plus letters), freezes them by SHA-256, runs a three-step approval workflow, and signs with Ed25519 (HMAC fallback).

## Kinds

Supported report kinds for [[attestra/reports/render.py#generate_report]].

[[attestra/reports/render.py#KINDS]]: `technical`, `executive`, `compliance`, `iso_soa`, `ageing`, `closure_letter`, `attestation_letter`. Framework required for compliance; defaulted for iso_soa.

## Generation

How a report row and frozen HTML file are created.

[[attestra/reports/render.py#generate_report]]:

1. Build context from findings, imports, authorizations, compliance, and prior-engagement trend ([[attestra/reports/render.py#_context]]).
2. Render Jinja templates under [[attestra/reports/templates]].
3. Write under `DATA_DIR/tenants/<id>/reports/`.
4. Create [[attestra/models.py#Report]] as `draft` with version and sha256.
5. Audit the write.

## Workflow

Draft reports move through submit → QA → sign, with reject back to draft.

Statuses: `draft` → `submitted` → `qa_approved` → `signed`, or `rejected` (resubmittable). Functions: [[attestra/reports/render.py#submit_report]], [[attestra/reports/render.py#qa_approve]], [[attestra/reports/render.py#qa_reject]], [[attestra/reports/render.py#sign_report]]. Author ≠ QA ≠ signer by user id; sign requires lead/admin. Legacy [[attestra/reports/render.py#approve_report]] remains as a two-person shortcut.

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

## Verification

Checking that a frozen report still matches its hash and signature.

[[attestra/reports/render.py#verify_report]] checks hash + signature. Tampering the frozen HTML breaks verification.
