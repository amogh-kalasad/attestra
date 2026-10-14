# Compliance engine

Maps findings to PCI DSS 4.0.1, ISO/IEC 27001:2022, and SOC 2 through a hub-and-spoke objective graph. The engine **proposes**; a person **confirms**.

## Library load

How framework and CWE YAML become the in-memory Library.

[[attestra/compliance/engine.py#load_library]] reads:

- [[attestra/compliance/data/controls.yaml]] — frameworks, objectives, evidence expectations, control titles
- [[attestra/compliance/data/cwe_map.yaml]] — CWE → objectives with `strength`/`rationale` (+ defaults)
- [[attestra/compliance/data/owasp.yaml]] — CWE → OWASP Top 10 / ASVS / WSTG (via [[attestra/compliance/owasp.py#map_finding_to_owasp]])

Cached as [[attestra/compliance/engine.py#Library]] with [[attestra/compliance/engine.py#CweMapping]] entries.

## Finding to objectives

Resolve which control objectives a finding touches.

[[attestra/compliance/engine.py#objectives_for]] unions default objectives with CWE map hits and adds patching objectives when CVEs are present.

## Framework scope

Which findings count for a given framework evaluation.

[[attestra/compliance/engine.py#in_framework_scope]] — for `pci_dss_4`, only findings on `in_cde` assets (or unmatched assets) count.

## Status proposal

How [[attestra/compliance/engine.py#evaluate]] builds proposed control statuses.

Builds [[attestra/compliance/engine.py#ControlResult]] per control ref:

- **Finding objectives** — open findings drive `not_met` / `partial` / `no_exceptions` via [[attestra/compliance/engine.py#_finding_status]]
- **Process objectives** — engagement evidence via [[attestra/compliance/engine.py#_process_status]] (`has_imports`, `has_valid_authorization`, `has_validated_pt`, `no_open_high_after_retest`, `asv_passing_scan`, `segmentation_tested`, `internal_scan_quarterly`, `has_risk_assessment`)

Weakest claim wins when several objectives feed one control ref.

## PCI / ISO records

ASV attestations, segmentation tests, risk acceptances, scan schedules, and nonconformities feed process rules and reports.

- ASV: [[attestra/services.py#add_asv_scan]] → [[attestra/models.py#AsvScan]] (PCI 11.3.2)
- Segmentation: [[attestra/services.py#add_segmentation_test]]
- Risk acceptance + expiry: [[attestra/services.py#accept_risk]], [[attestra/services.py#expire_risk_acceptances]] (CLI `attestra expire-risk`)
- Quarterly calendar: [[attestra/services.py#enqueue_due_schedules]] (worker loop)
- SLA breaches: [[attestra/services.py#sla_breaches]]; reports `iso_soa` / `ageing`
- External review log: [[attestra/compliance/data/REVIEW.md]]; export via [[attestra/services.py#export_compliance_library_csv]]

## Assessor confirmation

Named assessor override of the engine proposal.

[[attestra/services.py#confirm_control]] persists [[attestra/models.py#ControlAssessment]]. Confirmed status overrides the proposal ([[attestra/compliance/engine.py#ControlResult#status]]).

Service entry: [[attestra/services.py#compliance]].

## Control statuses

Meaning of each status string used in proposals and confirmations.

| Status | Meaning |
| --- | --- |
| `met` | Process evidenced, or assessor confirmed |
| `no_exceptions` | Testing found nothing against the control — not proof the control exists |
| `partial` | Medium findings or incomplete process evidence |
| `not_met` | Critical/high open, or required evidence missing |
| `not_assessed` | Outside what this engagement tested |

## OWASP references

CWE-driven OWASP Top 10, ASVS, and WSTG labels on findings.

[[attestra/compliance/owasp.py#map_finding_to_owasp]] reads [[attestra/compliance/data/owasp.yaml]] and populates finding OWASP columns at import/enrich time.

## Caveat

Mapping texts are paraphrased and need standards review before production.

Control texts in YAML are paraphrased. Verify against licensed PCI SSC / ISO / AICPA sources before production use.
