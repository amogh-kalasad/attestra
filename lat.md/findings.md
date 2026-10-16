# Findings

One normalized finding schema, keyed for dedup and ranked for work order. Reports still show CVSS as the severity of record.

## Data model

SQLAlchemy finding entity and related engagement constants.

[[attestra/models.py#Finding]] holds title, description, recommendation, tools, rule_ids, CWE/CVEs, location, severity, CVSS, EPSS, KEV, risk_score, SLA due, lifecycle status, and fingerprint.

Engagement types, frameworks, asset kinds, test types, and allowed status transitions live as module constants in [[attestra/models.py]] (`ENGAGEMENT_TYPES`, `FRAMEWORKS`, `ASSET_KINDS`, `TEST_TYPES`, `TRANSITIONS`).

## Deduplication

Stable fingerprint so the same issue from two tools or two runs merges.

[[attestra/fingerprint.py#fingerprint]] builds a stable SHA-256 key:

- Prefer CVE + package + normalized location
- Else CWE + location + param
- Else normalized title + location + param
- When `variant` is non-empty, append `v=<variant>` (lowercased). Empty variant keeps the exact pre-variant key.

[[attestra/importers/base.py#NormalizedFinding]] carries optional `variant` (for example ZAP `alertRef` when it differs from `pluginid`). [[attestra/services.py#import_results]] passes it into the fingerprint. If a variant key misses but a legacy no-variant fingerprint matches the same normalized title, the row is merged and its fingerprint is updated to the variant key.

Location normalization: [[attestra/fingerprint.py#normalize_location]]. Title: [[attestra/fingerprint.py#normalize_title]].

On re-import of the same fingerprint, [[attestra/services.py#import_results]] merges tools/rule_ids, keeps higher severity, and reopens if status was `fixed`.

## Passed checks

Lists every check that ran as passed, failed, or skipped — not only the failures.

[[attestra/checks.py]] builds check rows (`id`, `name`, `status`, `source`). [[attestra/runner/scanners/webcheck.py#WebcheckAdapter]] embeds them in `webcheck.json` and writes a `checks.json` sidecar. ZAP imports use [[attestra/checks.py#zap_checks_from_report]] (catalog rules with no alert = passed). Rows are stored on [[attestra/models.py#ScanRun]] / [[attestra/models.py#ImportRun]] `checks_json` and merged by [[attestra/services.py#list_passed_checks]] for the engagement page and the technical report.

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

[[attestra/scoring.py#sla_due]] uses [[attestra/config.py#SLA_DAYS]] (critical 30 days per PCI 6.3.3).

## Lifecycle

Allowed status transitions and how they are applied.

Allowed transitions: [[attestra/models.py#TRANSITIONS]]. Applied by [[attestra/services.py#transition]] with actor + optional note (required for false_positive / risk_accepted). Every transition is audited.

Open statuses for compliance roll-up: [[attestra/models.py#OPEN_STATUSES]].

## Enrichment

Offline KEV and EPSS application from operator-supplied files.

[[attestra/services.py#enrich]] applies CISA KEV JSON and FIRST EPSS CSV. CLI `attestra enrich --refresh` downloads feeds via [[attestra/ops/feeds.py#refresh_feeds]] into `DATA_DIR/feeds/` (catalog dates stored for reports).

## Evidence

Attaching hashed artifacts to a finding.

[[attestra/services.py#add_evidence]] masks secrets/PANs via [[attestra/evidence/mask.py#mask_bytes]] before hashing and write-once store ([[attestra/models.py#Evidence]] `masking_applied`). Imports mask raw bytes the same way after parse. Storage backends implement [[attestra/storage/__init__.py#Storage]] (`local` or `s3`).
