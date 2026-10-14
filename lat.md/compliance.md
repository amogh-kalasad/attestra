# Compliance engine

Maps findings to PCI DSS 4.0.1, ISO/IEC 27001:2022, and SOC 2 through a hub-and-spoke objective graph. The engine **proposes**; a person **confirms**.

## Library load

How framework and CWE YAML become the in-memory Library.

[[attestra/compliance/engine.py#load_library]] reads:

- [[attestra/compliance/data/controls.yaml]] — frameworks, objectives, control titles
- [[attestra/compliance/data/cwe_map.yaml]] — CWE → objectives (+ defaults)

Cached as [[attestra/compliance/engine.py#Library]].

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
- **Process objectives** — engagement evidence via [[attestra/compliance/engine.py#_process_status]] (`has_imports`, `has_valid_authorization`, `has_validated_pt`, `no_open_high_after_retest`)

Weakest claim wins when several objectives feed one control ref.

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

## Caveat

Mapping texts are paraphrased and need standards review before production.

Control texts in YAML are paraphrased. Verify against licensed PCI SSC / ISO / AICPA sources before production use.
