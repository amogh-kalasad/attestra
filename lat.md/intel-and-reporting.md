# Intelligence and reporting validity

Phase 2 WP3: validated threat-intel feeds, CVSS 4.0, explainable versioned risk, retest outcomes, merge history, mapping provenance, and run validity in reports.

## CVSS 4.0 calculator

Pure-Python port of the FIRST CVSS v4.0 reference calculator (BSD-2), versioned so scores are reproducible.

[[attestra/intel/cvss4.py#score]] parses a `CVSS:4.0/...` vector ([[attestra/intel/cvss4.py#parse_vector]]), derives the macro vector ([[attestra/intel/cvss4.py#macro_vector]]) and interpolates within the 270-entry lookup table. [[attestra/intel/cvss4.py#try_score]] returns `None` instead of raising [[attestra/intel/cvss4.py#Cvss4Error]]. Version string: [[attestra/intel/cvss4.py#CALCULATOR_VERSION]]. Fixture vectors live in `tests/fixtures/cvss4/first_vectors.json`.

## Feed store and freshness

KEV and EPSS feeds are validated before they replace the last good copy; a bad download never wipes intel.

[[attestra/intel/feed_store.py#store_feed]] runs [[attestra/intel/feed_store.py#validate]] ([[attestra/intel/feed_store.py#parse_kev]] / [[attestra/intel/feed_store.py#parse_epss]]), keeps the previous file as `.prev`, writes atomically and is idempotent on identical content. Failures go to [[attestra/intel/feed_store.py#record_failure]]. [[attestra/intel/feed_store.py#load_validated]] returns an [[attestra/intel/feed_store.py#IntelSnapshot]] (falls back to `.prev`) with [[attestra/intel/feed_store.py#intel_source_version]]. Staleness comes from [[attestra/intel/freshness.py#freshness_report]] (per-feed `ATTESTRA_INTEL_MAX_AGE_HOURS_<FEED>`). [[attestra/ops/feeds.py#refresh_feeds]] now delegates to the store; [[attestra/ops/feeds.py#load_cached_feeds]] returns only validated bytes.

## Explainable versioned risk

Risk explanations say which formula produced them, which inputs were unknown or stale, and how CVSS was obtained.

[[attestra/scoring.py#explain_risk_modifiers]] adds `scoring_version` ([[attestra/scoring.py#SCORING_VERSION]]), `formula_version` ([[attestra/scoring.py#SCORING_FORMULA_VERSION]]), `epss_known`, `kev_known`, `stale_inputs`, `intel_source_version` and `cvss_calculation` from [[attestra/scoring.py#cvss_score_for_vector]]. Unknown EPSS is reported as `None`, never as 0. The numeric risk score is unchanged.

## NVD and OSV

Offline-first NVD 2.0 parsing and OSV package correlation with explicit confidence.

[[attestra/intel/nvd.py#parse_response]] and [[attestra/intel/nvd.py#refresh]] (injectable fetch, no network in tests) produce [[attestra/intel/nvd.py#NvdRecord]] rows. [[attestra/intel/osv.py#correlate]] matches [[attestra/intel/osv.py#Component]] values (from [[attestra/intel/osv.py#parse_purl]] or [[attestra/intel/osv.py#components_from_cyclonedx]]) against OSV records, tagging each match high, medium or low confidence.

## Evidence provenance

Every piece of evidence can carry a provenance record explaining where it came from and how much to trust it.

[[attestra/finding_validation/provenance.py#build]] returns a `prov1` dict (tool, run, validity, confidence capped at [[attestra/finding_validation/provenance.py#MAX_CONFIDENCE]], secret-like identity labels redacted). Serialised with [[attestra/finding_validation/provenance.py#dumps]] / [[attestra/finding_validation/provenance.py#loads]] for `Evidence.provenance_json` (wiring in INT).

## Retest outcomes

Retests use eight explicit outcomes; only a confirmed fix closes a finding.

[[attestra/retest.py#decide_outcome]] maps the requested result plus run validity to an outcome; [[attestra/retest.py#can_close]] is true only for `confirmed_fixed`. Legacy `fixed` / `still_open` map through [[attestra/retest.py#normalize_outcome]]; `Retest.result` keeps the legacy value for compatibility. [[attestra/retest.py#finalize_retest]] accepts `run_validity`; a still-present result reopens with [[attestra/retest.py#regression_link]]. [[attestra/retest.py#retest_public_dict]] exposes outcome detail.

## Merge and split history

Cross-tool merge decisions are recorded as history events so a merge can be explained or reversed.

[[attestra/crossmerge.py#history_event]] (version [[attestra/crossmerge.py#MERGE_HISTORY_VERSION]]) describes merge, split or relink without changing fingerprints; [[attestra/crossmerge.py#merge_history]] reads them back from the audit log.

## Structured remediation

Remediation packs expose machine-readable metadata and link to the retest that verified the fix.

[[attestra/remediation/packs.py#structured_metadata]] returns `rp1` metadata. [[attestra/remediation/packs.py#link_verified_fix]] marks a fix verified only for a confirmed fix on a VALID (or not computed) run.

## Compliance mapping provenance

Mapping data declares its source and version, and assessor-only controls are never auto-passed.

`compliance/data/owasp.yaml` and `cwe_map.yaml` carry a `metadata` block; CWE-918 (SSRF) maps to WSTG-INPV-19. [[attestra/compliance/engine.py#mapping_metadata]] and [[attestra/compliance/engine.py#validate_library]] expose and check it. [[attestra/compliance/engine.py#is_assessor_only]] ([[attestra/compliance/engine.py#ASSESSOR_ONLY_RULES]]) downgrades automatic met to not assessed unless an assessor confirms.

## Run validity in reports

Reports disclose whether automated testing actually ran, so a blocked run is never presented as clean.

[[attestra/reports/run_validity.py#build_section]] summarises `result_json.run_validity` per execution (worst state wins); [[attestra/reports/render.py#_run_validity_context]] adds it to the report context and `_run_validity.html.j2` renders it in technical (full) and executive (compact) reports. Markdown uses [[attestra/reports/run_validity.py#markdown_lines]]; XLSX adds a "Run validity" sheet from [[attestra/reports/run_validity.py#xlsx_rows]] only when automated runs exist.

## QA validity gate

Report QA blocks reports that hide incomplete testing.

[[attestra/reports/qa/checks.py#check_run_validity_disclosed]] (critical when the section is missing), [[attestra/reports/qa/checks.py#check_blocked_not_clean]] (critical when a blocked run is shown as zero findings) and [[attestra/reports/qa/checks.py#check_checklist_version]] (mixed checklist versions).

## Semgrep GitHub Actions rules

Bundled Semgrep rules for GitHub Actions workflow risks.

Rules live in `attestra/runner/scanners/semgrep_rules/` (not `policy/`, which OPA loads as data): script injection, `pull_request_target` checkout, unpinned actions, write-all permissions. [[attestra/runner/scanners/semgrep.py#stage_rules]] copies them into the scan output dir; disable with `ATTESTRA_SEMGREP_GHA_RULES=0` ([[attestra/runner/scanners/semgrep.py#gha_rules_enabled]]).

## Licence policy

Opt-in SBOM licence policy findings.

[[attestra/supply_chain/license_policy.py#evaluate_bom]] applies deny / review / allow lists ([[attestra/supply_chain/license_policy.py#load_policy]]); [[attestra/importers/cyclonedx.py#license_findings]] emits findings only when `ATTESTRA_LICENSE_POLICY` is set ([[attestra/supply_chain/license_policy.py#enabled]]).
