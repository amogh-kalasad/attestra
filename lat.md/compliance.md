# Compliance engine

Maps findings to PCI DSS 4.0.1, ISO/IEC 27001:2022, and SOC 2 through a hub-and-spoke objective graph. The engine **proposes**; a person **confirms**.

## Library load

How framework and CWE YAML become the in-memory Library.

[[attestra/compliance/engine.py#load_library]] reads:

- `attestra/compliance/data/controls.yaml` — frameworks, objectives, evidence expectations, control titles
- `attestra/compliance/data/cwe_map.yaml` — CWE → objectives with `strength`/`rationale` (+ defaults)
- `attestra/compliance/data/owasp.yaml` — CWE → OWASP Top 10 / ASVS / WSTG (via [[attestra/compliance/owasp.py#map_finding_to_owasp]])
- `attestra/compliance/data/packs/*.yaml` — optional framework packs merged by [[attestra/compliance/engine.py#_merge_pack]] (ISO 42001, CERT-In, NIST CSF 2, RBI, SEBI, DORA, ASVS 4.0)

Cached as [[attestra/compliance/engine.py#Library]] with [[attestra/compliance/engine.py#CweMapping]] entries.

## Framework recommendations

Advisory profile matching that recommends only frameworks already in the configured catalogue.

[[attestra/compliance/recommend.py#recommend_frameworks]] requires catalogue Industry and Country keys from `attestra/compliance/data/industries.yaml` and `countries.yaml`. Optional regulatory status and technical scope refine rules in `recommend_rules.yaml`. API: `POST /api/frameworks/recommend` and catalogues via `GET /api/profile/catalogues` / `/api/catalog`. New-engagement UI heading is **Compliance Frameworks to Report Against**. Tenant profile fields `country`, `regulatory_status`, `technical_scope` (migration `0024_tenant_profile_recommend`) store the inputs. One primary country is stored; multi-country operation is not modeled yet. Confirmed user selections are preserved as `user_added` / `user_excluded` on refresh. Recommendations never invent framework IDs outside [[attestra/compliance/engine.py#load_library]].

## ASVS 4.0 pack

Chapter-level OWASP ASVS 4.0 register loaded as framework key `asvs_4_0`.

`attestra/compliance/data/packs/asvs_4_0.yaml` maps hub objectives to V1–V14 chapter refs with short titles. It loads like other packs via [[attestra/compliance/engine.py#load_library]] and supports [[attestra/services.py#compliance]] / compliance report generation.

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

Weakest claim wins when several objectives feed one control ref. `has_risk_assessment` treats risk-acceptance rows as at most `partial` evidence (not `met`); full credit needs assessor confirmation.

## PCI / ISO records

ASV attestations, segmentation tests, risk acceptances, scan schedules, and nonconformities feed process rules and reports.

- ASV: [[attestra/services.py#add_asv_scan]] → [[attestra/models.py#AsvScan]] (PCI 11.3.2)
- Segmentation: [[attestra/services.py#add_segmentation_test]]
- Risk acceptance + expiry: [[attestra/services.py#accept_risk]], [[attestra/services.py#expire_risk_acceptances]] (CLI `attestra accept-risk` / `attestra expire-risk`)
- Quarterly calendar: [[attestra/services.py#enqueue_due_schedules]] (worker loop)
- SLA breaches: [[attestra/services.py#sla_breaches]]; reports `iso_soa` / `ageing`
- External review log: `attestra/compliance/data/REVIEW.md`; export via [[attestra/services.py#export_compliance_library_csv]]

## Assessor confirmation

Named assessor override of the engine proposal.

[[attestra/services.py#confirm_control]] persists [[attestra/models.py#ControlAssessment]]. Confirmed status overrides the proposal ([[attestra/compliance/engine.py#ControlResult#status]]). Only `auditor` and `admin` may confirm (`compliance.confirm`); refused attempts (including lead overwrite) are audited as `control.confirm_refused` and the API returns 403. Confirming `met` while open mapped critical/high/medium findings remain is refused with those findings named in the error, unless `allow_open_findings_override` is set with rationale. Low/info open findings alone do not block `met`. The engagement UI shows the confirming assessor next to each confirmed control.

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

[[attestra/compliance/owasp.py#map_finding_to_owasp]] reads `attestra/compliance/data/owasp.yaml` and populates finding OWASP columns at import/enrich time. [[attestra/compliance/owasp.py#get_top10]] returns Top 10 2021 ids; [[attestra/compliance/owasp.py#group_findings_by_top10]] and [[attestra/compliance/owasp.py#should_show_llm_top10]] feed the `owasp_top10` report view (web categories always; optional LLM Top 10 2025 when ISO 42001 / AI evidence is present).

## SEBI security testing timeline

Engagement milestones mapped to SEBI CSCRF periodic security-testing expectations.

[[attestra/compliance/sebi_timeline.py#build_timeline]] derives planning, authorization recorded, testing window, scans completed, report signed, and retest from window dates, authorizations, scan/import runs, signed reports, and retests. Statuses are `pending`, `in_progress`, `done`, `overdue`, or `n/a`. Optional notes/status overrides persist under `DATA_DIR/tenants/{tid}/sebi_timeline/{eid}.json` ([[attestra/compliance/sebi_timeline.py#save_overrides]]) with no Alembic migration. Staff UI: `GET /engagements/{eid}/sebi-timeline` ([[attestra/web/sebi_routes.py#ui_sebi_timeline]]). Report context may include the timeline via [[attestra/reports/render.py#_sebi_timeline_report_context]].

## Shared audit sampling

ISO 9.2 and SOC 2 Type II use one sample-size table and the same seed-to-int rules.

[[attestra/compliance/sampling.py]] holds [[attestra/compliance/sampling.py#SAMPLE_SIZE_TABLE]], [[attestra/compliance/sampling.py#sample_size_for]], and seed helpers ([[attestra/compliance/sampling.py#seed_to_int]], [[attestra/compliance/sampling.py#resolve_seed]], [[attestra/compliance/sampling.py#seed_from_context]]). [[attestra/services.py#default_sample_size]] delegates to `sample_size_for`. [[attestra/services.py#draw_audit_sample]] keeps a string seed on [[attestra/models.py#AuditSample]] (auto `token_hex` when blank) and feeds `random.Random(seed_to_int(seed))`. [[attestra/reports/soc2_sampling.py#build_sample]] uses the same table and `resolve_seed` (context hash when seed is omitted). Populations stay framework-specific (ISO: soa_applicable/findings/nonconformities; SOC 2: findings/remediations).

## Caveat

Mapping texts are paraphrased and need standards review before production.

Control texts in YAML are paraphrased. Verify against licensed PCI SSC / ISO / AICPA sources before production use.
