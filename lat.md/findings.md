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

Location normalization: [[attestra/fingerprint.py#normalize_location]]. Title: [[attestra/fingerprint.py#normalize_title]].

On re-import of the same fingerprint, [[attestra/services.py#import_results]] merges tools/rule_ids, keeps higher severity, and reopens if status was `fixed`.

## Risk score

Prioritization formula used to rank work; does not replace CVSS in reports.

Formula in [[attestra/scoring.py#risk_score]]:

```
risk = CVSS × (1 + EPSS) × w_KEV × w_asset × w_exposure
```

- `w_KEV` = 1.5 if on CISA KEV, else 1.0
- `w_asset` = 0.6…1.4 from criticality ([[attestra/scoring.py#asset_weight]])
- `w_exposure` = 1.3 for internet or CDE ([[attestra/scoring.py#exposure_weight]])

Applied via [[attestra/services.py#rescore]]. Severity bands from CVSS: [[attestra/scoring.py#severity_from_cvss]].

## SLA

Remediation due dates by severity, including PCI 6.3.3 critical window.

[[attestra/scoring.py#sla_due]] uses [[attestra/config.py#SLA_DAYS]] (critical 30 days per PCI 6.3.3).

## Lifecycle

Allowed status transitions and how they are applied.

Allowed transitions: [[attestra/models.py#TRANSITIONS]]. Applied by [[attestra/services.py#transition]] with actor + optional note (required for false_positive / risk_accepted). Every transition is audited.

Open statuses for compliance roll-up: [[attestra/models.py#OPEN_STATUSES]].

## Enrichment

Offline KEV and EPSS application from operator-supplied files.

[[attestra/services.py#enrich]] applies operator-supplied CISA KEV JSON and FIRST EPSS CSV (no auto-fetch in v0.1).

## Evidence

Attaching hashed artifacts to a finding.

[[attestra/services.py#add_evidence]] attaches hashed write-once files to a finding ([[attestra/models.py#Evidence]]).
