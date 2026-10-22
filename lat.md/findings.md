# Findings

One normalized finding schema, keyed for dedup and ranked for work order. Reports still show CVSS as the severity of record.

## Data model

SQLAlchemy finding entity and related engagement constants.

[[attestra/models.py#Finding]] holds title, description, recommendation, impact, affected_urls, references, tools, rule_ids, CWE/CVEs, location, severity, CVSS (score + vector), EPSS, KEV, risk_score, SLA due, lifecycle status, and fingerprint. Impact, affected_urls (JSON list of URL strings), and references (JSON list of strings) default empty (migration `0021_finding_fields_disclaimer`). API [[attestra/api.py#_finding_dict]] exposes them. [[attestra/library/service.py#apply_to_finding]] fills empty impact and references from a library entry while still composing description/recommendation for older consumers. [[attestra/scoring.py#validate_cvss_vector]] accepts empty or CVSS 3.x vectors (`CVSS:3.…/…`); [[attestra/scoring.py#soft_cvss_vector]] clears garbage on import so a bad vector does not abort the run.

Engagement types, frameworks, asset kinds, test types, and allowed status transitions live as module constants in [[attestra/models.py]] (`ENGAGEMENT_TYPES`, `ENGAGEMENT_TYPE_LABELS`, `FRAMEWORKS`, `ASSET_KINDS`, `TEST_TYPES`, `TRANSITIONS`). The stored type key `vapt` stays; its display label is `VA + PT` via [[attestra/models.py#engagement_type_label]]. Legacy label `vapt (va + pt)` maps to key `vapt` through [[attestra/models.py#normalize_engagement_type]] on create and on display.

## Deduplication

Stable fingerprint so the same issue from two tools or two runs merges.

[[attestra/fingerprint.py#fingerprint]] builds a stable SHA-256 key:

- Prefer CVE + package + normalized location
- Else CWE + location + param
- Else normalized title + location + param
- When `variant` is non-empty, append `v=<variant>` (lowercased). Empty variant keeps the exact pre-variant key.

[[attestra/importers/base.py#NormalizedFinding]] carries optional `variant` (for example ZAP `alertRef` when it differs from `pluginid`). [[attestra/services.py#import_results]] runs [[attestra/fingerprint.py#canonicalize_for_merge]] before hashing so webcheck `dns-caa` and testssl `DNS_CAArecord` (R15) share [[attestra/fingerprint.py#CAA_VARIANT]] (`dns-caa`), CWE-16, bare host, and empty param. If that key misses, import still tries the raw key, a legacy empty-variant key (same normalized title), and [[attestra/fingerprint.py#caa_legacy_fingerprints]] (older testssl `host:port` + `DNS_CAArecord` shapes), then upgrades the stored fingerprint.

Location normalization: [[attestra/fingerprint.py#normalize_location]]. Title: [[attestra/fingerprint.py#normalize_title]].

On re-import of the same fingerprint, [[attestra/services.py#import_results]] merges tools/rule_ids, keeps higher severity, and reopens if status was `fixed`.

## Certificate expiry warning

Warn before a certificate expires using 30 / 14 / 7 day bands, with one finding per cert.

[[attestra/cert_expiry.py#expiry_band]] maps days left: under 30 → Low, under 14 → Medium, under 7 → High, ≤0 → expired (existing high finding). 30+ days → no finding. [[attestra/cert_expiry.py#finding_for_end_date]] builds the NormalizedFinding. [[attestra/importers/testssl.py#parse]] prefers `cert_notAfter` (optional `today=` for tests); webcheck stores peer `certificate.not_after` from [[attestra/runner/http_safe.py#SafeResponse]] and may emit the same variant. [[attestra/fingerprint.py#canonicalize_for_merge]] aligns both tools on bare host, CWE-298, variant `cert_expirationStatus` so they merge. [[attestra/services.py#import_results]] updates title and severity in place on band change, and [[attestra/cert_expiry.py#close_renewed_for_asset]] marks the finding fixed when the saved end date is more than 30 days away. Daily job [[attestra/cert_expiry.py#run_daily_cert_alerts]] (CLI `attestra cert-expiry-check`) reads SAVED end dates only and emits webhook `cert.expiring` once per band via [[attestra/models.py#CertExpiryAlert]]. Target page shows end date and days left with warning colour; library seed has fix text for expires-soon and expired.

## Passed checks

Lists every check that ran as passed, failed, or skipped — not only the failures.

[[attestra/checks.py]] builds check rows (`id`, `name`, `status`, `source`). [[attestra/runner/scanners/webcheck.py#WebcheckAdapter]] embeds them in `webcheck.json` and writes a `checks.json` sidecar. ZAP imports use [[attestra/checks.py#zap_checks_from_report]] (catalog rules with no alert = passed). Rows are stored on [[attestra/models.py#ScanRun]] / [[attestra/models.py#ImportRun]] `checks_json` and merged by [[attestra/services.py#list_passed_checks]] for the engagement page and the technical report.

## Site grade

Overall A–F letter grade per target with an Observatory-style score breakdown.

[[attestra/grade.py#score_from_findings]] starts at 100 and applies [[attestra/grade.py#MODIFIERS]] (penalties and bonuses). Not-tested checks leave the score alone. Bonuses apply only when the score is already 90 or more. Suppressed and false-positive findings do not take points off; accepted-risk findings still count. An expired or invalid certificate sets `cap_f` so [[attestra/grade.py#grade_from_score]] returns F. Modifier `http_no_https_redirect` (−20) applies when findings show HTTP does not upgrade to HTTPS on the same host (including first hop to another host); a temporary 302/307 to https:// on the same host does not take that penalty. [[attestra/services.py#asset_site_grade]] loads the target’s findings for the UI and `GET /api/engagements/{eid}/assets/{aid}/grade`. The target page shows the letter, score, and breakdown table; C11 scan history keeps its per-scan severity letter separately. The sites dashboard ([[interfaces#Web dashboard#Sites dashboard]]) reuses the same grade helpers via [[attestra/services.py#list_tenant_sites]] and sorts with [[attestra/grade.py#grade_rank]].

## CVSS vector

Stored vector string validated as empty or CVSS 3.x before keep.

[[attestra/scoring.py#validate_cvss_vector]] returns `""` for blank input and otherwise requires a string starting with `CVSS:3.` that contains `/` metrics; garbage raises `ValueError`. Import merge uses [[attestra/scoring.py#soft_cvss_vector]] so invalid importer data is cleared and the rest of the import continues.

## Risk score

Prioritization formula used to rank work; does not replace CVSS in reports.

Formula in [[attestra/scoring.py#risk_score]]:

```
risk = CVSS × (1 + EPSS) × w_KEV × w_asset × w_exposure
```

- `w_KEV` = 1.5 if on CISA KEV, else 1.0
- `w_asset` = 0.6…1.4 from criticality ([[attestra/scoring.py#asset_weight]])
- `w_exposure` = 1.3 for internet or CDE ([[attestra/scoring.py#exposure_weight]])
- Info with no CVSS stays base 0 on internal assets; on internet-facing or CDE assets the base is [[attestra/scoring.py#INFO_INTERNET_BASE]] (1.0) so risk is never 0 after exposure weight (about 1.3 at criticality 3).

Applied via [[attestra/services.py#rescore]]. Severity bands from CVSS: [[attestra/scoring.py#severity_from_cvss]]. Findings on internet-facing assets show an "Internet-facing" tag in the engagement list and technical report.

## SLA

Remediation due dates by severity, including PCI 6.3.3 critical window.

[[attestra/scoring.py#sla_due]] uses [[attestra/config.py#SLA_DAYS]] (critical 30 days per PCI 6.3.3). Open findings past `sla_due` are listed by [[attestra/services.py#sla_breaches]]. The daily CLI `attestra sla-alert-check` calls [[attestra/alerts/service.py#run_sla_missed_alerts]] so each overdue finding can email once ([[interfaces#Email alerts]]).

## Lifecycle

Allowed status transitions and how they are applied.

Allowed transitions: [[attestra/models.py#TRANSITIONS]]. Applied by [[attestra/services.py#transition]] with actor + optional note (required for `false_positive`). Moving to `risk_accepted` is refused unless called from [[attestra/services.py#accept_risk]], which creates the [[attestra/models.py#RiskAcceptance]] row (expiry + rationale + owner/approver). Enforced in API (`POST /risk-acceptances`), UI (accept-risk form), and CLI (`attestra accept-risk`). Every transition is audited.

Open statuses for compliance roll-up: [[attestra/models.py#OPEN_STATUSES]].

## Enrichment

Offline KEV and EPSS application from operator-supplied files.

[[attestra/services.py#enrich]] applies CISA KEV JSON and FIRST EPSS CSV. CLI `attestra enrich --refresh` downloads feeds via [[attestra/ops/feeds.py#refresh_feeds]] into `DATA_DIR/feeds/` (catalog dates stored for reports).

## CSV export

Triage CSV download with a formula-injection guard; evidence bodies are omitted.

[[attestra/reports/findings_csv.py#export_findings_csv]] writes the fixed [[attestra/reports/findings_csv.py#CSV_COLUMNS]] set (id, target, title, severity, status, risk score, CVSS, CWE, first/last seen, due date, source tools, fingerprint). [[attestra/reports/findings_csv.py#csv_cell]] prefixes cells that start with `=`, `+`, `-`, `@`, tab or carriage return so Excel does not treat them as formulas. Evidence bodies, notes and comments are never included. Routes: `GET /api/engagements/{eid}/findings/export` and the engagement/target page buttons. Audited as `findings.exported`.

## Evidence

Attaching hashed artifacts to a finding.

[[attestra/services.py#add_evidence]] masks secrets/PANs via [[attestra/evidence/mask.py#mask_bytes]] before hashing and write-once store ([[attestra/models.py#Evidence]] `masking_applied`). Imports mask raw bytes the same way after parse. Storage backends implement [[attestra/storage/__init__.py#Storage]] (`local` or `s3`).

## Findings library fix snippets

Reusable writeups carry optional importance, effort, fix steps and server config snippets.

[[attestra/models.py#LibraryEntry]] stores `importance` (High/Medium/Low), `effort` (Easy/Medium/Hard), `fix_steps`, and `snippet_nginx` / `snippet_apache` / `snippet_iis` / `snippet_cloudflare` (migration `0018_library_fix_snippets`). Empty values stay valid for older rows. Built-in text lives in [[attestra/library/fix_snippets.py#BY_TITLE]] and is merged into [[attestra/library/seed.py#SEED]] for header, TLS, cookie and CSP titles. [[attestra/library/service.py#guidance_for_finding]] prefers a tenant library match, then the seed. The finding page, technical report and `GET /api/engagements/{eid}/findings` show these fields; reports keep only the known server snippet, or nginx plus Apache when the server type is unknown ([[attestra/library/fix_snippets.py#snippets_for_report]]).

## Comments

Plain-text discussion thread on each finding; soft-deleted; never in share links or default reports.

[[attestra/models.py#FindingComment]] stores finding id, tenant id, author user id, body (max 5000), created/edited times, and a `deleted` flag. [[attestra/comments.py]] lists, adds, and soft-deletes with tenant checks through [[attestra/services.py#get_engagement]]. Anyone with `finding.read` who can see the finding may read comments. Add needs `finding.write`, or role `client_viewer`. Authors may delete their own; lead/admin may delete any in the tenant. Audited as `finding.comment.added` / `finding.comment.deleted`. Optional webhook `finding.commented` (no body). API: `GET/POST /api/findings/{fid}/comments`, `DELETE /api/findings/{fid}/comments/{cid}`. UI card on the finding page escapes all output. [[attestra/comments.py#finding_fields_for_share]] never includes comments; [[attestra/reports/render.py#generate_report]] includes them only when `include_comments=True` (default off).

## Comments

Threaded notes on a finding with soft-delete and role checks.

[[attestra/comments.py#list_comments]], [[attestra/comments.py#add_comment]], and [[attestra/comments.py#delete_comment]] keep comments on [[attestra/models.py#FindingComment]]. Writers and client viewers may add; authors or lead/admin may soft-delete. Public share payloads use [[attestra/comments.py#finding_fields_for_share]] and never include comment bodies.

## Assignment

Human and workflow-rule assignee history on a finding, audited on every change.

[[attestra/models.py#FindingAssignment]] stores `assignee` (username string), optional `rule_id`, and `assigned_by`. [[attestra/assignments.py#assign_finding]] resolves the username to an active [[attestra/models.py#User]] in the finding's engagement tenant (home tenant or [[attestra/models.py#TenantMembership]]), or a platform `admin`, then inserts a row and audits `finding.assigned`. [[attestra/assignments.py#unassign_finding]] inserts `assignee=""` and audits `finding.unassigned`. [[attestra/assignments.py#current_assignee]] returns the latest non-empty assignee (or `None` after unassign). [[attestra/assignments.py#findings_assigned_to]] filters an engagement for the "assigned to me" view. Workflow rules in [[attestra/webhooks/service.py]] still insert `FindingAssignment` rows directly.
