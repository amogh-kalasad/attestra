# World-Class VA + PT — Phase 10 ENG1 V21 Regression

**Source:** `Downloads/# MASTER PROMPT WORLD-CLASS VAPT PL.txt` (§13 Phase 10)  
**Prior:** `docs/WORLDCLASS_VAPT_PHASE9_REPORT_QA.md`  
**ENG1 case:** `Downloads/eng1-technical-v21.pdf` (HarmonyPM / Coworked demo, engagement #1, report v21, DRAFT)  
**Phase 1 register:** `docs/WORLDCLASS_VAPT_PHASE1_AUDIT.md` §3  
**Date:** 2026-11-05

Product wording: **security testing** / **VA + PT**. Do not put the historical internal “elite” label in customer-facing reports or docs. Do **not** “fix” ENG1 by editing the PDF — assert detection, validation, grading, remediation, coverage honesty, and report QA, then regenerate if needed.

---

## Goals

- Treat ENG1 technical report **v21** as the world-class regression case for Phases 2–9 behaviour.
- Assert all **15** master-prompt anchors with existing behaviour, expected behaviour, root cause, required change, regression test, and validation result.
- Reuse classifiers, coverage honesty, risk scoring, normalization, remediation packs, report narrative, and report QA — no second platform.
- Document remaining limitations; this is the **final** world-class phase in the prompt (no Phase 11).

---

## Full 15-anchor register

Master prompt §13 verify list, seeded from Phase 1 ENG1 register + Phases 2–9 deliverables. Siblings fill **Existing / Expected / Root cause / Code change / Regression test**; coordinator marks **Validation result** from `tests/test_eng1_v21_regression.py`.

| ID | Anchor | Phase 1 / prior map | Primary package(s) | Validation result |
| --- | --- | --- | --- | --- |
| **1** | HSTS contradiction | F-8; Phase 2 classify + Phase 5 grade | `finding_validation`, `grade.py` | **pass** (`test_eng1_hsts_*`) |
| **2** | Permissions-Policy contradiction | F-7; Phase 2 cdn-cgi + Phase 7 pack match | `finding_validation`, `remediation` | **pass** (`test_eng1_pp_*`) |
| **3** | CORS challenge-resource detection | F-2; Phase 2 CDN/CORS | `finding_validation` | **pass** (`test_eng1_cors_*`) |
| **4** | Cloudflare cookie classification | F-3 / CDN noise; Phase 2 CF cookies | `finding_validation` | **pass** (`test_eng1_cf_*`) |
| **5** | Weak cipher evidence | F-10; Phase 2 needs_manual | `finding_validation`, nuclei importer, `grade.py` | **pass** (`test_eng1_cipher_*`) |
| **6** | Incorrect site-grade calculations | Site grade; Phase 5 | `grade.py`, `scoring.py` | **pass** (`test_eng1_grade_*`) |
| **7** | Generic remediation templates | Remediation quality; Phase 7 | `remediation/`, `finding_validation` | **pass** (`test_eng1_remediation_*`, `test_eng1_xssprot_*`) |
| **8** | Informational findings as vulnerabilities | F-18 XSS-Protection; Phase 2 + 6 | `finding_validation`, `reports/render` | **pass** (`test_eng1_info_*`) |
| **9** | Incomplete authenticated testing | Coverage; Phase 3 + 4 | `auth_web`, `automated_vapt/coverage` | **pass** (`test_eng1_auth_*`) |
| **10** | Blocked IDOR/BOLA coverage | PT / authz; Phase 3 | `automated_vapt/testing`, `auth_web` | **pass** (`test_eng1_idor_*`) |
| **11** | Limited XSS and SQL injection testing | Checklist honesty; Phase 3 + 4 + 9 QA | `checklists`, `reports/qa` | **pass** (`test_eng1_xsssql_*`) |
| **12** | HTTP 403 and HTTP 200 evidence inconsistencies | Validation / evidence; Phase 2 | `finding_validation`, Elite validate, coverage | **pass** (`test_eng1_http_*`) |
| **13** | Scan timestamp reconciliation | Report / QA honesty; Phase 8–9 | `reports/render`, `reports/labels` | **pass** (`test_eng1_timestamp_*`) |
| **14** | Evidence traceability | Evidence integrity; Phase 8–9 | evidence embeds/limitations, `reports/qa` | **pass** (`test_eng1_evidence_*`) |
| **15** | Draft and approval metadata | QA metadata; Phase 8–9 | report workflow, `reports/qa` | **pass** (`test_eng1_draft_*`) |

---

## Anchor details

### 1. HSTS contradiction

HSTS-missing finding or site-grade fail while HTTP evidence shows `Strict-Transport-Security` with max-age (ENG1 F-8).

- **Existing behaviour:** Phase 2 `classify_observation` / `hsts_present_in_evidence` already mark HSTS-not-set claims as `not_reproducible` when evidence shows `Strict-Transport-Security` with `max-age`. HTTP-pair reconcile and Phase 5 grade skip the HSTS-missing penalty when contradicting evidence exists.
- **Expected behaviour:** Finding and grade must match response evidence; contradicting Pass/Fail reconciled without analyst override to keep an open “HSTS not set” vuln.
- **Root cause:** Scanner alert imported as open while another observation’s HTTP evidence already proved HSTS present; evidence was not used to invalidate the claim.
- **Required code change:** Already fixed in Phase 2 (classify + reconcile) and Phase 5 (grade). No further product logic change for the classify path.
- **Regression test:** `test_eng1_hsts_evidence_contradicts_missing_claim`, `test_eng1_hsts_missing_without_evidence_stays_unvalidated`
- **Validation result:** **pass**

### 2. Permissions-Policy contradiction

Permissions-Policy “not set” on cdn-cgi / challenge URLs, or CSP-only remediation for a Permissions-Policy finding (ENG1 F-7).

- **Existing behaviour:** Phase 2 marks Permissions-Policy-missing on `cdn-cgi` / `challenge-platform` as `informational`; evidence showing `Permissions-Policy:` on an app URL yields `not_reproducible`. Phase 7 pack `header:permissions-policy-missing` excludes CSP nginx/apache text; Phase 9 QA flags `remediation_csp_mismatch`.
- **Expected behaviour:** Validate against application responses; remediation must match Permissions-Policy (never CSP-only snippets).
- **Root cause:** Wrong affected resource (CDN challenge URL) plus library/guidance mismatch that attached CSP remediations.
- **Required code change:** Already fixed in Phase 2 (cdn-cgi / evidence) and Phase 7 (pack + library guard). No further change for this anchor.
- **Regression test:** `test_eng1_pp_missing_on_cdn_cgi_informational`, `test_eng1_pp_evidence_contradicts_missing_on_app_url`, `test_eng1_pp_remediation_pack_is_not_csp`
- **Validation result:** **pass**

### 3. CORS challenge-resource detection

Wildcard CORS on Cloudflare challenge / `/cdn-cgi/...` treated as app Medium (ENG1 F-2).

- **Existing behaviour:** Phase 2 `is_cdn_cors_finding` + `classify_observation` mark CORS / cross-domain alerts on challenge URLs as `informational` with a CDN/challenge reason. App-owned CORS stays `unvalidated`.
- **Expected behaviour:** Classify CDN/challenge resources separately; require app-owned CORS + credentialed read proof before Confirmed.
- **Root cause:** No CDN/challenge ownership validator; ZAP 10098 imported as open Medium. Phase 10 also found a gap: any non-empty evidence on a cdn-cgi URL was treated as an infrastructure-cookie finding, shadowing the CORS reason (status was still informational, but the wrong rule fired).
- **Required code change:** Phase 2 already delivered CDN CORS classification. Phase 10 tightened `is_infrastructure_cookie_finding` so cookie-titled / CF-named cookies only qualify — CORS ACAO evidence on challenge URLs no longer routes through the CF-cookie branch (`attestra/finding_validation/infrastructure.py`).
- **Regression test:** `test_eng1_cors_challenge_platform_acao_wildcard_informational`, `test_eng1_cors_app_owned_stays_unvalidated`
- **Validation result:** **pass**

### 4. Cloudflare cookie classification

SameSite / cookie findings on `cf_clearance` / `__cf_bm` (ENG1 F-3).

- **Existing behaviour:** Phase 2 `is_cloudflare_infrastructure_cookie` / `is_infrastructure_cookie_finding` mark `cf_clearance`, `__cf_bm`, `__cfruid`, `_cfuvid`, and `cf_` / `__cf` / `cf_chl_` prefixes as informational infrastructure noise. App session cookies (e.g. `sessionid`) stay `unvalidated`.
- **Expected behaviour:** Distinguish Cloudflare cookies from app session cookies; impact only if auth/session cookie.
- **Root cause:** Cookie checks treated all Set-Cookie alerts equally, including CF bot-management cookies.
- **Required code change:** Already fixed in Phase 2. Phase 10 cookie-classifier tighten (anchor 3) preserves CF cookie behaviour for cookie-titled / named CF cookies.
- **Regression test:** `test_eng1_cf_clearance_samesite_none_informational`, `test_eng1_cf_cookie_family_and_prefixes`, `test_eng1_cf_app_session_samesite_stays_unvalidated`
- **Validation result:** **pass**

### 5. Weak cipher evidence

Weak-cipher alerts without suite names / TLS versions / handshake (ENG1 F-10).

- **Existing behaviour (pre-fix):** Nuclei `weak-cipher-suites` imported as Low/open with empty evidence; Phase 2 classifier already sent suite-less alerts to `needs_manual_validation`, but suite names in the description (or Nuclei `extracted-results`) were ignored, so even named suites stayed needs_manual. Nuclei importer did not populate `evidence_refs`.
- **Expected behaviour:** Without suite/handshake tokens → `needs_manual_validation` (never Confirmed). With IANA/algorithm suite tokens in evidence_refs, evidence_texts, or description → leave unvalidated (still not Confirmed). Nuclei extractors/matchers surface into `evidence_refs`. Remediation resolves to `tls:weak-cipher` (AEAD / TLS 1.2+), not a generic XSS pack.
- **Root cause:** Importer omitted extractor output; classifier only scanned evidence blobs, not description; ENG1 template produced no suite names at all.
- **Required code change:** [[attestra/finding_validation/classify.py#classify_observation]] counts description suite tokens; [[attestra/importers/nuclei.py#_evidence_refs]] adds `extracted-results` / matcher / truncated curl. Phase 7 pack `tls:weak-cipher` reused.
- **Regression test:** `test_eng1_cipher_needs_manual_without_suite_names`, `test_eng1_cipher_with_suite_evidence_not_needs_manual`, `test_eng1_cipher_suite_names_in_description_count_as_evidence`, `test_eng1_cipher_nuclei_importer_surfaces_extracted_suites`, `test_eng1_cipher_remediation_pack_is_tls_weak_cipher`.
- **Validation result:** **pass** (pytest prefix `test_eng1_cipher_`)

#### 5b. Complementary TLS evidence depth / grade / summary honesty

Fills OpenSSL suite recognition, protocol-alone honesty, site-grade weak-cipher penalty honesty, and TLS summary non-invention (still ENG1 F-10).

- **Existing behaviour (pre-fix):** IANA `TLS_*` suite tokens worked; OpenSSL hyphenated names (`ECDHE-RSA-AES128-SHA`) and handshake/ServerHello cipher proof did not. Protocol version strings alone could be confused with suite depth. `grade.py` applied `tls_weak_cipher` −15 on needs_manual / informational rows. testssl `_cipher_name` fell back to `finding[:80]`, so TLS summary could show free-text as a “suite”.
- **Expected behaviour:** OpenSSL suites + handshake cipher proof progress past needs_manual (stay unvalidated; Confirmed only via Elite evidence). Protocol versions alone stay needs_manual. Grade skips `tls_weak_cipher` for informational / FP / not_reproducible / accepted_risk and for needs_manual without suite names; unvalidated with suite proof still −15. TLS summary best/weakest uses real suite/family tokens or em-dash — never invents names.
- **Root cause:** `_CIPHER_EVIDENCE_RE` boundary failed on OpenSSL `AES128` tokens; grade lacked validation honesty for weak cipher; `_cipher_name` invented from free text.
- **Required code change:** [[attestra/finding_validation/classify.py#_has_cipher_suite_evidence]] (OpenSSL + handshake patterns); [[attestra/grade.py]] tls_weak_cipher skip; [[attestra/importers/testssl.py#_cipher_name]] suite-token-only.
- **Regression test:** `test_eng1_tls_openssl_suite_evidence_not_needs_manual`, `test_eng1_tls_protocol_versions_alone_stay_needs_manual`, `test_eng1_tls_grade_needs_manual_skips_weak_cipher_penalty`, `test_eng1_tls_grade_informational_skips_weak_cipher_penalty`, `test_eng1_tls_grade_suite_evidence_still_penalizes`, `test_eng1_tls_summary_never_invents_suite_names`, `test_eng1_cipher_evidence_handshake_proof_progresses`.
- **Validation result:** **pass** (pytest prefixes `test_eng1_tls_`, `test_eng1_cipher_evidence_`)

### 6. Incorrect site-grade calculations

Grade C / HSTS missing Failed while evidence or validation shows HSTS present; inconsistent modifiers (ENG1 site grade).

- **Existing behaviour (pre-fix):** `score_from_findings` applied HSTS-missing −20 from scanner titles even when other findings’ HTTP blobs showed `Strict-Transport-Security: max-age=…`, and skipped rows still labelled the pass as “Has Strict-Transport-Security” when only `validation_status` cleared the claim.
- **Expected behaviour:** Modifiers respect `validation_status` ∈ {not_reproducible, informational, validation FP, accepted_risk} and cross-finding HSTS evidence via `hsts_present_in_evidence`. Breakdown reasons stay honest: evidence cite vs validation skip (never claim “Has STS” on validation-only skip). Unvalidated claims without evidence still take −20.
- **Root cause:** Grade keyword matching ignored HTTP evidence / validation class; pass-reason templating always rewrote “Missing …” → “Has …”.
- **Required code change:** Phase 5 `attestra/grade.py` (`_IGNORE_VALIDATION`, evidence override) plus Phase 10 honesty: `_hsts_missing_pass_reason` distinguishes evidence vs validation skips.
- **Regression test:** `test_eng1_grade_hsts_evidence_skips_missing_penalty`, `test_eng1_grade_hsts_informational_skips_missing_penalty`, `test_eng1_grade_hsts_not_reproducible_skips_missing_penalty`, `test_eng1_grade_hsts_unvalidated_still_penalizes` in `tests/test_eng1_v21_regression.py` (also Phase 5 `tests/test_risk_scoring_phase5_grade.py`).
- **Validation result:** **pass** (pytest prefixes `test_eng1_grade_`).

### 7. Generic remediation templates

Wrong header remediations (e.g. CSP snippets for Permissions-Policy) (ENG1 remediation quality / F-7) plus deprecated-header / weak-cipher pack depth (F-18 / F-10).

- **Existing behaviour (pre-fix):** Library/CWE matching could attach CSP Nginx/Apache snippets to ZAP 10063 Permissions-Policy findings (shared CWE-693). Separately, Nuclei XSS-Protection titles mapped to CWE-79 / Injection / V5.2.1 / WSTG-INPV-01 while still titled like XSS; ASVS stayed on the Injection row after Phase 2 severity/CWE remap.
- **Expected behaviour:** Concept-matched pack `header:permissions-policy-missing` only; nginx/apache examples set `Permissions-Policy`; `rejects_csp_guidance_for_finding` blocks CSP-only seed/library text; Phase 9 QA flags `remediation_csp_mismatch` when wrong text remains. XSS-Protection → concept `header:xss-protection-deprecated`, informational, CWE-693, A05, ASVS `V14.4.3`, WSTG `WSTG-CONF-12`, remediation “remove or set 0” (not an XSS vuln fix). Weak-cipher → `tls:weak-cipher` AEAD guidance.
- **Root cause:** Generic CWE/title library match without header-concept guards; Nuclei template CWE-79 + `_apply_owasp` before classify left Injection ASVS/WSTG when `asvs_ref` was not overwritten.
- **Required code change:** Phase 7 packs + match + library guards (PP↔CSP — remediation/grade sibling). XSS-Protection remap depth in [[attestra/finding_validation/classify.py#classify_observation]] / [[attestra/finding_validation/classify.py#apply_classification_to_finding]] (set ASVS/WSTG for CWE-693; clear Injection ASVS). Phase 6 CONCEPT_RULES `header:xss-protection-deprecated` reused.
- **Regression test:** `test_eng1_remediation_*` (PP↔CSP sibling); `test_eng1_xssprot_remapped_not_injection`, `test_eng1_xssprot_apply_clears_injection_asvs_wstg`, `test_eng1_xssprot_concept_is_deprecated_header_not_xss`; `test_eng1_cipher_remediation_pack_is_tls_weak_cipher`.
- **Validation result:** **pass** (pytest prefixes `test_eng1_remediation_`, `test_eng1_xssprot_`, `test_eng1_cipher_`).

### 8. Informational findings classified as vulnerabilities

Deprecated XSS-Protection (and similar hardening) mapped as CWE-79 / Injection / open vuln (ENG1 F-18); open-vuln KPIs must exclude informational / not_reproducible.

- **Existing behaviour (pre-fix):** ENG1 F-18 showed CWE-79, A03 Injection, ASVS V5.2.1, WSTG-INPV-01 and counted among open Info findings. Phase 5 already introduced `_counts_as_open_vuln` / `_NON_VULN_VALIDATION`, but ENG1 regression did not assert XSS-Protection remap + KPI exclusion together; ASVS Injection mapping survived classify apply.
- **Expected behaviour:** XSS-Protection → informational hardening (not open Injection KPI). Summary open-vuln counts via [[attestra/reports/render.py#_counts_as_open_vuln]] exclude `informational`, `not_reproducible`, `false_positive`, `accepted_risk`. `needs_manual_validation` / `unvalidated` still count as open vulns (weak-cipher without suites stays visible).
- **Root cause:** Aggressive Nuclei CWE/OWASP mapping treated deprecated-header noise as XSS; report KPIs historically tallied all open workflow statuses without validation class.
- **Required code change:** Phase 2 classify + apply ASVS/WSTG remap (anchor 7); Phase 5 `_counts_as_open_vuln` reused; Phase 10 ENG1 asserts both paths.
- **Regression test:** `test_eng1_info_informational_excluded_from_open_vuln`, `test_eng1_info_not_reproducible_excluded_from_open_vuln`, `test_eng1_info_needs_manual_still_counts_as_open_vuln`, `test_eng1_info_xssprot_informational_not_open_vuln_kpi`.
- **Validation result:** **pass** (pytest prefix `test_eng1_info_`)

### 9. Incomplete authenticated testing

Authenticated crawl / role coverage incomplete while report implies full auth testing.

- **Existing behaviour:** T19 `SKIPPED` / `DEFERRED` auto-map to checklist `blocked` on `WSTG-ATHN-04` with reason notes; `update_checklist_item` refuses `passed` when notes contain incomplete markers (`not covered`, `not tested`, `not executed`, `skipped`, `limited`, `blind`, `deferred`, `blocked:`). Coverage snapshot always sets `scan_completion_is_not_security_coverage=True` and `incomplete` when blocked/untested work remains.
- **Expected behaviour:** Coverage snapshot separates tested vs skipped/blocked; scan completion ≠ security coverage; incomplete auth notes never become checklist Passed.
- **Root cause:** Pre–Phase 3 checklist language allowed Passed with “not covered” notes; DEFERRED automated cases were ignored by checklist auto-apply (no blocked verdict).
- **Required code change:** Markers extended in `attestra/auth_web/checklists.py`; `verdicts_for_automated` treats `DEFERRED` like `SKIPPED`/`FAILED` for real probes (T19/T20/T21/SESSION/INJ/XSS/FILE). Reuse Phase 3–4 snapshot honesty.
- **Regression test:** `test_eng1_auth_incomplete_never_passed`
- **Validation result:** **pass**

### 10. Blocked IDOR/BOLA coverage

IDOR/BOLA / authz probes blocked or not executed recorded as Passed.

- **Existing behaviour:** T20 with `secondary_auth.status != ready` records `WSTG-ATHZ-04` as `blocked` (“single admin profile… cannot prove object-level authorization”). Notes containing `blocked:`, `deferred`, `not executed`, or `skipped` cannot be flipped to Passed via `update_checklist_item`. A later clean T20 with secondary ready and prior auto evidence may honestly pass.
- **Expected behaviour:** blocked / deferred / not executed never become checklist Passed without real two-account proof + evidence.
- **Root cause:** Single-profile IDOR was previously treatable as a clean pass; incomplete-note markers omitted `deferred` / `not executed` / `blocked:`.
- **Required code change:** Phase 3 T20 secondary-profile gate (already) + Phase 10 marker/DEFERRED honesty; Phase 9 `checklist_passed_incomplete` catches DB bypasses.
- **Regression test:** `test_eng1_idor_blocked_without_secondary_never_passed`
- **Validation result:** **pass**

### 11. Limited XSS and SQL injection testing

XSS/SQLi checklist Passed while notes admit forms/DOM / blind SQLi not covered (ENG1 coverage).

- **Existing behaviour:** Clean T21 still marks `WSTG-INPV-05` / `WSTG-INPV-01` **blocked** with honesty notes (blind/time-based SQLi not covered; HTML forms/DOM not covered). Limited INJ/XSS canaries likewise stay blocked (“full coverage not tested”). Manual/API Passed with those notes raises `ServiceError`. Report QA `check_skipped_blocked` emits critical `checklist_passed_incomplete` if a row is Passed with incomplete notes (ENG1 bad-state simulation).
- **Expected behaviour:** Limited probes → blocked with honesty notes; QA flags Passed+incomplete notes; never equate limited canaries with full XSS/SQLi coverage.
- **Root cause:** ENG1 V21 marked XSS/SQLi checklist Passed despite admitting forms/DOM and blind SQLi gaps.
- **Required code change:** Phase 3 `_t21_verdicts` / INJ/XSS blocked-on-clean (already) + Phase 10 marker expansion + Phase 9 QA check.
- **Regression test:** `test_eng1_xsssql_limited_probes_stay_blocked`
- **Validation result:** **pass**

### 12. HTTP 403 and HTTP 200 evidence inconsistencies

Claims that treat HTTP 200 alone as Confirmed, or ignore 403 / challenge bodies that contradict exploitability.

- **Existing behaviour:** `validate_result` returns `NOT_VULNERABLE` when status is 200 (or 403) without exposure/bypass; `should_create_elite_finding` only allows `CONFIRMED`/`POTENTIAL` and not likely-FP; `classify_observation` defaults scanner alerts to `unvalidated`; FP checker marks 401/403/404 without exposure as likely FP; coverage `_ledger_status_tested` excludes `DEFERRED`/`SKIPPED`.
- **Expected behaviour:** Never Confirmed on HTTP 200 alone; 403 blocked paths stay non-Confirmed / likely FP; deferred coverage rows stay blocked (not tested/passed).
- **Root cause:** Historical scanners and authz modules can emit 200 without proof, or treat deny responses as findings; coverage must not count deferred cases as tested.
- **Required code change:** None beyond Phases 2–4 — regression locks Elite validator, create gate, classify default, FP 403 heuristic, and ledger tested-status filter.
- **Regression test:** `test_eng1_http_200_alone_never_confirmed`, `test_eng1_http_403_blocked_path_not_confirmed`, `test_eng1_http_classify_default_unvalidated_not_confirmed`, `test_eng1_http_deferred_coverage_stays_blocked`
- **Validation result:** **pass** (12 local pytest; worker ENG1 12–15)

### 13. Scan timestamp reconciliation

Report / control timestamps disagree with scan run or import times, or DRAFT control shows empty QA dates inconsistently.

- **Existing behaviour:** `_tools_and_versions` uses recorded `tool_version` only (else `version not recorded`); methodology / appendix scan tables bind `ScanRun.started_at` / `ended_at` through `format_datetime` (missing → `—`); `format_date` / `format_datetime` return empty for null/blank and never invent clocks or “India Standard Time”.
- **Expected behaviour:** Document-control and methodology times derive from recorded runs/imports; no invented tool versions or timestamps.
- **Root cause:** Earlier drafts risked placeholder clocks or hard-coded scanner versions in sealed HTML.
- **Required code change:** None beyond Phase 8 helpers — regression asserts recorded-only versions, empty helpers, and methodology scan history from `ScanRun`.
- **Regression test:** `test_eng1_timestamp_tools_versions_recorded_only`, `test_eng1_timestamp_format_date_helpers_recorded_only`, `test_eng1_timestamp_scan_history_methodology_recorded`
- **Validation result:** **pass** (local pytest; worker ENG1 12–15)

### 14. Evidence traceability

Finding cards / QA without hash-backed evidence links; Confirmed high with zero evidence.

- **Existing behaviour:** `_evidence_embeds` embeds screenshots only when on-disk bytes match stored `sha256` (mismatch skipped); `_evidence_limitations` lists `capture_failure` / failed `capture_status` notes; Phase 9 `check_evidence_integrity` raises critical `evidence_hash_mismatch`.
- **Expected behaviour:** Finding-card embeds are hash-verified; capture failures appear as limitations; QA blocks approval on hash mismatch.
- **Root cause:** Sealed reports historically could show screenshots without verifying storage integrity, or omit failed-capture honesty.
- **Required code change:** None beyond Phases 8–9 — regression covers limitations helper, embed hash gate, and QA critical path.
- **Regression test:** `test_eng1_evidence_limitations_list_capture_failures`, `test_eng1_evidence_embeds_require_hash_match`, `test_eng1_evidence_qa_hash_mismatch_critical`
- **Validation result:** **pass** (local pytest; worker ENG1 12–15)

### 15. Draft and approval metadata

Document control QA/Approved `—`; DRAFT watermark; approval without automated QA (ENG1 QA metadata).

- **Existing behaviour:** Technical template `#document-control` / `#sign-off` use explicit `Pending QA (DRAFT)` / `Pending approval (DRAFT)` while status is draft/submitted; `_base` emits `.draft-mark` when `is_draft`; Phase 9 `check_approval_status` emits informational `approval_status` with current status; `qa_approve` / `sign_report` call `assert_qa_allows_approval`.
- **Expected behaviour:** DRAFT generations show Pending QA placeholders and watermark chrome; QA surfaces approval_status; critical QA still blocks final approval (Phase 9).
- **Root cause:** ENG1 v21 document control showed bare `—` for QA/Approved without stating DRAFT pending state.
- **Required code change:** None beyond Phases 8–9 — regression asserts placeholders + `approval_status` info issue on draft reports.
- **Regression test:** `test_eng1_draft_pending_qa_placeholders`, `test_eng1_draft_approval_status_qa_check`
- **Validation result:** **pass** (local pytest; worker ENG1 12–15)

---

## Primary files / packages (Phases 2–9 reuse)

Phase 10 regression reuses these surfaces; prefer extending tests over forking logic.

| Phase | Packages / files |
| --- | --- |
| 2 Validation | `attestra/finding_validation/` (`classify_observation`, infrastructure, reconcile), `services.py` import wiring |
| 3 PT coverage | `attestra/automated_vapt/testing/`, `attestra/auth_web/checklists.py`, `coverage_matrix.py` |
| 4 Coverage engine | `attestra/automated_vapt/coverage/` (snapshot, ledger), `services.engagement_coverage_snapshot`, report `#security-testing-coverage` |
| 5 Risk scoring | `attestra/scoring.py`, `attestra/grade.py`, `Finding.business_risk` / `cvss_version` |
| 6 Normalize / dedup | `attestra/finding_normalize.py`, `attestra/crossmerge.py` CONCEPT_RULES |
| 7 Remediation | `attestra/remediation/` packs + match |
| 8 Report engine | `attestra/reports/render.py`, `technical.html.j2` narrative / limitations / DRAFT placeholders |
| 9 Report QA | `attestra/reports/qa/` (`run_report_qa`, gates on approve/sign) |
| Docs / lat | `docs/WORLDCLASS_VAPT_PHASE1_AUDIT.md` … `PHASE9_REPORT_QA.md`; `lat.md/architecture.md`, `lat.md/tests.md` |
| This phase | `docs/WORLDCLASS_VAPT_PHASE10_ENG1_V21.md`, `tests/test_eng1_v21_regression.py` |

---

## Import/normalize path

ENG1 F-18 / CONCEPT_RULES honesty for scanner import (exclusive ownership: import → classify wiring, `finding_normalize`, CONCEPT_RULES).

### Wiring (import applies classification)

`services.import_results` already calls `_apply_import_validation` on create and on merge (`only_if_stronger=True`). That runs `classify_observation` then `apply_classification_to_finding` (validation fields only; workflow `status` unchanged). No gap hook required.

Before fingerprint / soft-match, import remaps deprecated XSS-Protection observations via `finding_normalize.normalize_cwe_for_import` (template CWE-79 → **693**) so Nuclei/ZAP hardening alerts do not share a CWE-79 fingerprint with reflected XSS at the same location. `_apply_owasp` then maps A05 misconfiguration; classify reinforces informational + clears Injection/WSTG XSS labels.

### CONCEPT_RULES / normalize

| Concept | Distinct from |
| --- | --- |
| `header:xss-protection-deprecated` | Reflected XSS (ZAP 40012 / nuclei `reflected-xss` → empty concept set) |
| `header:permissions-policy-missing` | `header:csp-missing` and `csp:*` weak directives |

Security-context buckets (`app` / `cdn-cgi` / `challenge` / `static`) remain in `finding_normalize.security_context_key`.

### Regression tests

Prefixes in `tests/test_eng1_v21_regression.py`:

- `test_eng1_import_*` — Nuclei/ZAP XSS-Protection leaves CWE-693 + informational (not Injection); CORS / Permissions-Policy on cdn-cgi → informational through the real import pipeline.
- `test_eng1_normalize_*` — CONCEPT_RULES distinctness + CWE remap fingerprint separation.

---

## Remaining limitations

- Visual PDF blank-page / layout / page-number automation remains deferred (Phase 9 note).
- ZAP traditional-json often omits message bodies; some contradiction paths still need captured HTTP pairs.
- ENG1 PDF itself is a historical DRAFT artifact — regression targets **product behaviour**, not rewriting that file.
- Full live ENG1 re-scan / regenerate against HarmonyPM may stay environment-blocked; unit/integration anchors are the exit bar here.

---

## Stop

Phase 10 is the **final** world-class VA + PT phase in the master prompt (ENG1 V21 validation). There is **no Phase 11** in that prompt. Stop for owner review after the 15-anchor regression suite and this document are complete.
