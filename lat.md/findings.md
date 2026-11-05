# Findings

One normalized finding schema, keyed for dedup and ranked for work order. Reports still show CVSS as the severity of record.

## Data model

SQLAlchemy finding entity and related engagement constants.

[[attestra/models.py#Finding]] holds title, description, recommendation, impact, affected_urls, references, tools, rule_ids, CWE/CVEs, location, severity, CVSS (score + vector + version), EPSS, KEV, risk_score, business_risk, SLA due, lifecycle status, and fingerprint. Impact, affected_urls (JSON list of URL strings), and references (JSON list of strings) default empty (migration `0021_finding_fields_disclaimer`). API [[attestra/api.py#_finding_dict]] exposes them including `cvss_version`, `business_risk`, and `risk_modifiers`. [[attestra/library/service.py#apply_to_finding]] fills empty impact and references from a library entry while still composing description/recommendation for older consumers. [[attestra/scoring.py#validate_cvss_vector]] accepts empty, CVSS 3.x, or CVSS 4.0 vectors; [[attestra/scoring.py#soft_cvss_vector]] clears garbage on import so a bad vector does not abort the run.

Engagement types, frameworks, asset kinds, test types, and allowed status transitions live as module constants in [[attestra/models.py]] (`ENGAGEMENT_TYPES`, `NEW_ENGAGEMENT_TYPES`, `ENGAGEMENT_TYPE_LABELS`, `FRAMEWORKS`, `ASSET_KINDS`, `TEST_TYPES`, `TRANSITIONS`). New creates accept only [[attestra/models.py#NEW_ENGAGEMENT_TYPES]] (`va`, `pt`, `vapt`) via [[attestra/services.py#create_engagement]], the new-engagement UI ([[attestra/models.py#new_engagement_type_labels]]), and `/api/catalog`. Historical `retest` / `continuous` rows remain readable. The stored type key `vapt` stays; its display label is `VA + PT` via [[attestra/models.py#engagement_type_label]]. Legacy label `vapt (va + pt)` maps to key `vapt` through [[attestra/models.py#normalize_engagement_type]] on create and on display.

### Engagement type workflows

Default planned tests follow the engagement type: VA uses [[attestra/models.py#VA_TEST_TYPES]] (automated scanners), PT uses [[attestra/models.py#PT_TEST_TYPES]] (`manual_pt`), and `vapt` / historical types use the full [[attestra/models.py#DEFAULT_TESTS]] set. [[attestra/models.py#default_tests_for]] and [[attestra/models.py#allowed_test_types_for]] drive [[attestra/services.py#add_asset]] defaults and rejection of cross-workflow test types.

## Deduplication

Stable fingerprint so the same issue from two tools or two runs merges.

[[attestra/fingerprint.py#fingerprint]] builds a stable SHA-256 key:

- Prefer CVE + package + normalized location
- Else CWE + location + param
- Else normalized title + location + param
- When `variant` is non-empty, append `v=<variant>` (lowercased). Empty variant keeps the exact pre-variant key.

[[attestra/importers/base.py#NormalizedFinding]] carries optional `variant` (for example ZAP `alertRef` when it differs from `pluginid`) plus optional observation fields (`tool_version`, `original_id`, `package_version`, …). [[attestra/services.py#import_results]] runs [[attestra/fingerprint.py#canonicalize_for_merge]] before hashing so webcheck `dns-caa` and testssl `DNS_CAArecord` (R15) share [[attestra/fingerprint.py#CAA_VARIANT]] (`dns-caa`), CWE-16, bare host, and empty param. If that key misses, import still tries the raw key, a legacy empty-variant key (same normalized title), and [[attestra/fingerprint.py#caa_legacy_fingerprints]] (older testssl `host:port` + `DNS_CAArecord` shapes), then upgrades the stored fingerprint.

Location normalization: [[attestra/fingerprint.py#normalize_location]]. Title: [[attestra/fingerprint.py#normalize_title]].

On re-import of the same fingerprint, [[attestra/services.py#import_results]] merges tools/rule_ids, keeps higher severity, and reopens if status was `fixed`.

### Cross-tool deduplication

Confidence-based consolidation across scanners within one engagement.

When the exact fingerprint misses, [[attestra/dedup.py#find_best_soft_match]] scores candidates (asset, location, CVE/package, CWE+param, cross-tool). Scores at or above [[attestra/dedup.py#MERGE_THRESHOLD]] merge into the canonical finding; mid-band scores stay separate and set `possible_duplicate_of` on the new [[attestra/models.py#FindingObservation]]; low scores create a new finding. Title, CVE, CWE, severity, or hostname alone never merge. Every import stores a [[attestra/models.py#FindingObservation]] (migration `0025_finding_observations`). UI/API show **Detected by** via [[attestra/dedup.py#detected_by_label]]. Historical review uses [[attestra/dedup.py#suggest_historical_duplicates]] / `GET /api/engagements/{eid}/dedup-suggestions` without automatic destructive merges.

### Cross-tool merge

Present the same issue from different tools as one finding while preserving observation history.

[[attestra/crossmerge.py]] links related finding rows to a primary after import (migration `0029_cross_tool_merge`). [[attestra/crossmerge.py#recompute_safely]] runs inside a savepoint so a merge failure cannot abort the parent import transaction. Report consolidation still reads the merged view; original tool observations remain on [[attestra/models.py#FindingObservation]]. Related rows keep their own severity/status/evidence; [[attestra/crossmerge.py#collapse]] / [[attestra/crossmerge.py#build_sources]] surface per-tool Sources (including `merge_rationale`) for UI and Markdown. Phase 6 honesty overview: [[architecture#World-class finding normalization (Phase 6)]].

World-Class Phase 6 context guards: [[attestra/finding_normalize.py#security_context_key]] buckets path context (`app` / `cdn-cgi` / `challenge` / `static`). Concept and CWE+path matches in [[attestra/crossmerge.py#match_reason]] require the same context key; CVE stays host-level. `merge_rationale` records `map:{concept}@{bucket}`, `cve:{id}`, or `cwe:CWE-N+path@{bucket}`. [[attestra/crossmerge.py#explain_near_misses]] lists same-host+concept pairs that differ in context (related-not-merged). [[attestra/crossmerge.py#CONCEPT_RULES]] covers missing headers (HSTS/CSP/XFO/XCTO/COEP/COOP/CORP/Permissions-Policy/Referrer-Policy), deprecated X-XSS-Protection (not CWE-79 XSS), CORS, SameSite cookies, weak ciphers, and TLS cert concepts; COEP/COOP/CORP and CSP-missing vs CSP-weak stay distinct. [[attestra/crossmerge.py#list_concept_keys]] lists registry keys for docs/tests. Sibling expansions may add [[attestra/finding_normalize.py#EXTRA_CONCEPT_RULES]]. Doc: `docs/WORLDCLASS_VAPT_PHASE6_NORMALIZE_DEDUP.md`.

## Certificate expiry warning

Warn before a certificate expires using 30 / 14 / 7 day bands, with one finding per cert.

[[attestra/cert_expiry.py#expiry_band]] maps days left: under 30 → Low, under 14 → Medium, under 7 → High, ≤0 → expired (existing high finding). 30+ days → no finding. [[attestra/cert_expiry.py#finding_for_end_date]] builds the NormalizedFinding. [[attestra/importers/testssl.py#parse]] prefers `cert_notAfter` (optional `today=` for tests); webcheck stores peer `certificate.not_after` from [[attestra/runner/http_safe.py#SafeResponse]] and may emit the same variant. [[attestra/fingerprint.py#canonicalize_for_merge]] aligns both tools on bare host, CWE-298, variant `cert_expirationStatus` so they merge. [[attestra/services.py#import_results]] updates title and severity in place on band change, and [[attestra/cert_expiry.py#close_renewed_for_asset]] marks the finding fixed when the saved end date is more than 30 days away. Daily job [[attestra/cert_expiry.py#run_daily_cert_alerts]] (CLI `attestra cert-expiry-check`) reads SAVED end dates only and emits webhook `cert.expiring` once per band via [[attestra/models.py#CertExpiryAlert]]. Target page shows end date and days left with warning colour; library seed has fix text for expires-soon and expired.

## Passed checks

Lists every check that ran as passed, failed, or skipped — not only the failures.

[[attestra/checks.py]] builds check rows (`id`, `name`, `status`, `source`). [[attestra/runner/scanners/webcheck.py#WebcheckAdapter]] embeds them in `webcheck.json` and writes a `checks.json` sidecar. ZAP imports use [[attestra/checks.py#zap_checks_from_report]] (catalog rules with no alert = passed). Rows are stored on [[attestra/models.py#ScanRun]] / [[attestra/models.py#ImportRun]] `checks_json` and merged by [[attestra/services.py#list_passed_checks]] for the engagement page and the technical report.

## Site grade

Overall A–F letter grade per target with an Observatory-style score breakdown.

[[attestra/grade.py#score_from_findings]] starts at 100 and applies [[attestra/grade.py#MODIFIERS]] (penalties and bonuses). Not-tested checks leave the score alone. Bonuses apply only when the score is already 90 or more. Suppressed and false-positive findings do not take points off; accepted-risk findings still count. An expired or invalid certificate sets `cap_f` so [[attestra/grade.py#grade_from_score]] returns F. Modifier `http_no_https_redirect` (−20) applies when findings show HTTP does not upgrade to HTTPS on the same host (including first hop to another host); a temporary 302/307 to https:// on the same host does not take that penalty. HSTS-missing (−20) is skipped when the claiming finding’s `validation_status` is not_reproducible / informational / validation FP, or when any in-scope finding’s description/evidence text shows HSTS with max-age ([[attestra/finding_validation/headers.py#hsts_present_in_evidence]]); the check still counts as tested so the row is pass, not not_tested. [[attestra/services.py#asset_site_grade]] loads the target’s findings for the UI and `GET /api/engagements/{eid}/assets/{aid}/grade`. The target page shows the letter, score, and breakdown table; C11 scan history keeps its per-scan severity letter separately. The sites dashboard ([[interfaces#Web dashboard#Sites dashboard]]) reuses the same grade helpers via [[attestra/services.py#list_tenant_sites]] and sorts with [[attestra/grade.py#grade_rank]]. Phase 5 honesty: [[architecture#World-class risk scoring (Phase 5)]].

## CVSS vector

Stored vector string validated as empty, CVSS 3.x, or CVSS 4.0 before keep; version stored for reports.

[[attestra/scoring.py#validate_cvss_vector]] returns `""` for blank input and otherwise requires `CVSS:3.x/…` or `CVSS:4.0/…` with metrics; garbage (including CVSS 2.x) raises `ValueError`. [[attestra/scoring.py#soft_cvss_vector]] clears invalid importer data so the rest of the import continues. [[attestra/scoring.py#cvss_version_from_vector]] parses the prefix into `Finding.cvss_version` (`""` | `3.0` | `3.1` | `4.0`). CVSS 4.0 is soft-accepted for storage/display only — scores are never invented from a v4 vector without an official calculator; missing score stays `None` and severity comes from the scanner or info. Import sets version from the vector and never clears an existing `cvss_score` when merging an observation that lacks one. When a score is present, [[attestra/scoring.py#align_severity_with_cvss]] syncs severity to CVSS bands unless explicitly overridden. UI, API, and technical reports show score, full vector, and version.

## Risk score

Prioritization formula used to rank work; does not replace CVSS in reports.

Formula in [[attestra/scoring.py#risk_score]]:

```
risk = base × (1 + EPSS) × kev_factor × asset_weight × exposure_weight
```

- `base` = real `cvss_score` when present; otherwise a documented severity default ([[attestra/scoring.py#DEFAULT_CVSS]]) used only for ranking — never written into `cvss_score`
- `kev_factor` = 1.5 if on CISA KEV, else 1.0 ([[attestra/scoring.py#KEV_FACTOR]])
- `asset_weight` = 0.6…1.4 from criticality ([[attestra/scoring.py#asset_weight]])
- `exposure_weight` = 1.3 for internet or CDE ([[attestra/scoring.py#exposure_weight]])
- Info with no CVSS stays base 0 on internal assets; on internet-facing or CDE assets the base is [[attestra/scoring.py#INFO_INTERNET_BASE]] (1.0) so risk is never 0 after exposure weight (about 1.3 at criticality 3).

[[attestra/scoring.py#explain_risk_modifiers]] returns documented modifiers (`base`, `base_source`, `epss`, `kev_factor`, `asset_weight`, `exposure_weight`, `formula`, `risk_score`, plus `business_risk` band) so scoring stays reproducible; informational validation caps priority to the info base. [[attestra/scoring.py#business_risk_band]] labels priority separately from technical CVSS severity; [[attestra/services.py#rescore]] stores `Finding.business_risk` and never rewrites `cvss_score`. Report open-vuln KPIs exclude informational / not-reproducible validation classes ([[architecture#World-class risk scoring (Phase 5)]]). Severity bands from CVSS: [[attestra/scoring.py#severity_from_cvss]]. Findings on internet-facing assets show an "Internet-facing" tag in the engagement list and technical report.

## SLA

Remediation due dates by severity, including PCI 6.3.3 critical window.

[[attestra/scoring.py#sla_due]] uses [[attestra/config.py#SLA_DAYS]] (critical 30 days per PCI 6.3.3). Open findings past `sla_due` are listed by [[attestra/services.py#sla_breaches]]. The daily CLI `attestra sla-alert-check` calls [[attestra/alerts/service.py#run_sla_missed_alerts]] so each overdue finding can email once ([[interfaces#Email alerts]]).

## Lifecycle

Allowed status transitions and how they are applied.

Allowed transitions: [[attestra/models.py#TRANSITIONS]]. Applied by [[attestra/services.py#transition]] with actor + optional note (required for `false_positive`). Moving to `risk_accepted` is refused unless called from [[attestra/services.py#accept_risk]], which creates the [[attestra/models.py#RiskAcceptance]] row (expiry + rationale + owner/approver). Enforced in API (`POST /risk-acceptances`), UI (accept-risk form), and CLI (`attestra accept-risk`). Every transition is audited.

Open statuses for compliance roll-up: [[attestra/models.py#OPEN_STATUSES]].

### Validation class vs workflow status

Workflow `status` and finding `validation_status` are separate; scanners stay unvalidated until evidence-backed.

[[attestra/models.py#TRANSITIONS]] covers triage/fix/FP/risk acceptance workflow. [[attestra/finding_validation/statuses.py]] defines validation classes (`unvalidated`, `confirmed`, `needs_manual_validation`, `potential`, `false_positive`, `informational`, `not_reproducible`, `accepted_risk`). [[attestra/finding_validation/classify.py#classify_observation]] applies general CDN/CF cookie, CORS-on-cdn-cgi, XSS-Protection remapping, header-evidence contradiction, and weak-cipher evidence rules without hardcoding engagement finding IDs. [[attestra/finding_validation/classify.py#apply_classification_to_finding]] sets validation fields only (never workflow status). Elite [[attestra/automated_vapt/validation/vulnerability_validator.py#validate_result]] statuses map via [[attestra/finding_validation/classify.py#elite_status_to_validation]]; create is gated by [[attestra/finding_validation/classify.py#should_create_elite_finding]] (CONFIRMED/POTENTIAL and not likely FP). Gap analysis: `docs/WORLDCLASS_VAPT_PHASE1_AUDIT.md` and [[architecture#World-class security testing audit (Phase 1)]].

## Enrichment

Offline KEV and EPSS application from operator-supplied files.

[[attestra/services.py#enrich]] applies CISA KEV JSON and FIRST EPSS CSV. CLI `attestra enrich --refresh` downloads feeds via [[attestra/ops/feeds.py#refresh_feeds]] into `DATA_DIR/feeds/` (catalog dates stored for reports).

## CSV export

Triage CSV download with a formula-injection guard; evidence bodies are omitted.

[[attestra/reports/findings_csv.py#export_findings_csv]] writes the fixed [[attestra/reports/findings_csv.py#CSV_COLUMNS]] set (id, target, title, severity, status, risk score, CVSS, CWE, first/last seen, due date, source tools, fingerprint). [[attestra/reports/findings_csv.py#csv_cell]] prefixes cells that start with `=`, `+`, `-`, `@`, tab or carriage return so Excel does not treat them as formulas. Evidence bodies, notes and comments are never included. Routes: `GET /api/engagements/{eid}/findings/export` and the engagement/target page buttons. Audited as `findings.exported`.

## Evidence

Attaching hashed artifacts to a finding, with provenance and original-vs-annotated roles.

[[attestra/services.py#add_evidence]] masks secrets/PANs via [[attestra/evidence/mask.py#mask_bytes]] before hashing and write-once store ([[attestra/models.py#Evidence]] `masking_applied`). Image screenshots keep bytes intact aside from prior redaction. Imports mask raw bytes the same way after parse. Storage backends implement [[attestra/storage/__init__.py#Storage]] (`local` or `s3`). Allowed kinds are [[attestra/services.py#EVIDENCE_KINDS]] (`screenshot`, `http_pair`, `log`, `code`, `package`, `note`, `file`, `capture_failure`, `client_upload`). Upload size is capped by [[attestra/config.py#EVIDENCE_MAX_BYTES]] (portal uses a stricter 5 MB). Provenance and gallery behaviour: [[authorization#Evidence gallery]]. Download and path rules: [[authorization#Evidence file security]].

## Findings library fix snippets

Reusable writeups carry optional importance, effort, fix steps and server config snippets.

[[attestra/models.py#LibraryEntry]] stores `importance` (High/Medium/Low), `effort` (Easy/Medium/Hard), `fix_steps`, and `snippet_nginx` / `snippet_apache` / `snippet_iis` / `snippet_cloudflare` (migration `0018_library_fix_snippets`). Empty values stay valid for older rows. Built-in text lives in [[attestra/library/fix_snippets.py#BY_TITLE]] and is merged into [[attestra/library/seed.py#SEED]] for header, TLS, cookie and CSP titles. [[attestra/library/service.py#guidance_for_finding]] prefers a tenant library match, then the seed. The finding page, technical report and `GET /api/engagements/{eid}/findings` show these fields; reports keep only the known server snippet, or nginx plus Apache when the server type is unknown ([[attestra/library/fix_snippets.py#snippets_for_report]]). Onboarding uses [[attestra/library/service.py#seed_defaults]] (UI/API) or [[attestra/library/import_convert.py#convert_library_template]] via `POST /api/library/import`.

## Comments

Plain-text discussion thread on each finding; soft-deleted; never in share links or default reports.

[[attestra/models.py#FindingComment]] stores finding id, tenant id, author user id, body (max 5000), created/edited times, and a `deleted` flag. [[attestra/comments.py]] lists, adds, and soft-deletes with tenant checks through [[attestra/services.py#get_engagement]]. Anyone with `finding.read` who can see the finding may read comments. Add needs `finding.write`, or role `client_viewer`. Authors may delete their own; lead/admin may delete any in the tenant. Audited as `finding.comment.added` / `finding.comment.deleted`. Optional webhook `finding.commented` (no body). API: `GET/POST /api/findings/{fid}/comments`, `DELETE /api/findings/{fid}/comments/{cid}`. UI card on the finding page escapes all output. Client portal posts via [[attestra/web/portal.py#portal_add_comment]] (same add gate; auditors cannot write). [[attestra/comments.py#finding_fields_for_share]] never includes comments; [[attestra/reports/render.py#generate_report]] includes them only when `include_comments=True` (default off).

## Comments

Threaded notes on a finding with soft-delete and role checks.

[[attestra/comments.py#list_comments]], [[attestra/comments.py#add_comment]], and [[attestra/comments.py#delete_comment]] keep comments on [[attestra/models.py#FindingComment]]. Writers and client viewers may add; authors or lead/admin may soft-delete. Public share payloads use [[attestra/comments.py#finding_fields_for_share]] and never include comment bodies.

## Assignment

Human and workflow-rule assignee history on a finding, audited on every change.

[[attestra/models.py#FindingAssignment]] stores `assignee` (username string), optional `rule_id`, and `assigned_by`. [[attestra/assignments.py#assign_finding]] resolves the username to an active [[attestra/models.py#User]] in the finding's engagement tenant (home tenant or [[attestra/models.py#TenantMembership]]), or a platform `admin`, then inserts a row and audits `finding.assigned`. [[attestra/assignments.py#unassign_finding]] inserts `assignee=""` and audits `finding.unassigned`. [[attestra/assignments.py#current_assignee]] returns the latest non-empty assignee (or `None` after unassign). [[attestra/assignments.py#findings_assigned_to]] filters an engagement for the "assigned to me" view. Workflow rules in [[attestra/webhooks/service.py]] still insert `FindingAssignment` rows directly.
