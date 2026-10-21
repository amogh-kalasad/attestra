# Attestra Requirements Register

Evidence-backed register extracted from `Attestra_Consolidated_Good_To_Have_Features.docx` (46 features, 21 Oct 2026) plus the coverage baseline in the CLI agent master prompt (5 assessment types × 9 frameworks).

## How to read

| Column | Meaning |
| --- | --- |
| ID | Stable requirement id (`DOCX-NN` from master table; `BASE-*` for coverage baseline) |
| Source | DOCX section / master table row |
| Priority | Must / Should / Nice (from DOCX) |
| Status | VERIFIED COMPLETE / PARTIALLY COMPLETE / NOT IMPLEMENTED / STORED-NOT-RENDERED (pre-fix) / NOT VERIFIED / BLOCKED / NOT APPLICABLE |
| Evidence | Code, tests, or report output proving disposition |

## Assessment and framework baseline

| ID | Description | Related types | Frameworks | Status | Evidence |
| --- | --- | --- | --- | --- | --- |
| BASE-AT-01 | Five engagement types: va, pt, vapt, retest, continuous | all | — | VERIFIED COMPLETE | `attestra/models.py` `ENGAGEMENT_TYPES`; API `EngagementIn.type`; tests `test_report_coverage_enhancements.py` |
| BASE-FW-01 | Nine frameworks selectable and loadable | all | all nine | VERIFIED COMPLETE | `controls.yaml` + `compliance/data/packs/*.yaml` (6 packs) → 9 total via `load_library()` |
| BASE-MX-01 | Documented 5×9 coverage matrix | all | all nine | VERIFIED COMPLETE | `docs/vapt/ATTestra_ASSESSMENT_FRAMEWORK_COVERAGE_MATRIX.md` |

## DOCX master table (46 features)

| ID | Feature | Category | Priority | Phase | Status after this work | Evidence / notes |
| --- | --- | --- | --- | --- | --- | --- |
| DOCX-01 | Built-in cover page | Front matter | Must | 2 | VERIFIED COMPLETE | `_base.html.j2` cover for non-letter kinds |
| DOCX-02 | Table of contents | Front matter | Must | 2 | VERIFIED COMPLETE | `technical.html.j2` `#toc` |
| DOCX-03 | List of figures | Front matter | Should | 2 | PARTIALLY COMPLETE | Figure captions on embedded screenshots; no separate LoF index |
| DOCX-04 | Document version control table | Front matter | Must | 1 | VERIFIED COMPLETE | `report_history` + document-control table |
| DOCX-05 | Distribution / tester contact | Front matter | Should | 2 | PARTIALLY COMPLETE | Tenant contact on cover; no separate distribution list field |
| DOCX-06 | Testing type render (+ box type) | Front matter | Must | 1/2 | PARTIALLY COMPLETE | Test types + standards rendered; black/grey/white box field not added |
| DOCX-07 | Disclaimer / limitations / confidentiality | Front matter | Must | 2 | VERIFIED COMPLETE | Template config `disclaimer` + section 12 |
| DOCX-08 | Scope table with environment | Front matter | Must | 1 | VERIFIED COMPLETE | Environment column on scope table |
| DOCX-09 | Methodology phases block | Front matter | Should | 2 | VERIFIED COMPLETE | `methodology_phases` from template config |
| DOCX-10 | Standards list from TEST_TYPES | Front matter | Should | 1 | VERIFIED COMPLETE | Standards section |
| DOCX-11 | Severity chart in technical | Front matter | Should | 2 | VERIFIED COMPLETE | Reuses `trend_svg` in technical summary |
| DOCX-12 | Risk rating legend with CVSS | Front matter | Must | 2 | VERIFIED COMPLETE | CVSS legend section |
| DOCX-13 | Findings overview + retest column | Front matter | Must | 1 | VERIFIED COMPLETE | Overview table with retest result |
| DOCX-14 | Retest report kind | Front matter | Must | 1 | VERIFIED COMPLETE | `KINDS` includes `retest`; `retest.html.j2` |
| DOCX-15 | Conclusion section | Front matter | Should | 2 | VERIFIED COMPLETE | Section 13 |
| DOCX-16 | Appendix / tool output | Front matter | Nice | 2 | PARTIALLY COMPLETE | Imports + scan history; no separate appendix block |
| DOCX-17 | QA / signer block inside report | Front matter | Should | 2 | PARTIALLY COMPLETE | History shows QA/approver columns; live sign-off remains external banner |
| DOCX-18 | Date sanity checks before sign-off | Front matter | Should | 2 | NOT IMPLEMENTED | Deferred; no blocking validation yet |
| DOCX-19 | CVSS vector per finding | Finding fields | Must | 1 | VERIFIED COMPLETE | Rendered when `cvss_vector` set |
| DOCX-20 | OWASP Top 10 / ASVS / WSTG in report | Finding fields | Must | 1 | VERIFIED COMPLETE | Fields printed when present |
| DOCX-21 | Separate Impact field | Finding fields | Must | 2 | NOT IMPLEMENTED | Needs migration; description still used |
| DOCX-22 | Affected URLs / method / parameter | Finding fields | Must | 2 | PARTIALLY COMPLETE | `location` only; structured fields not added |
| DOCX-23 | Separate References field | Finding fields | Should | 2 | NOT IMPLEMENTED | Needs migration |
| DOCX-24 | Embed PoC screenshots with captions | Evidence | Must | 1 | VERIFIED COMPLETE | `evidence_embeds` data URIs + figcaptions |
| DOCX-25 | HTTP request/response as evidence | Evidence | Should | 2 | PARTIALLY COMPLETE | Stored as `http_pair`; listed in register, not pretty-printed in body |
| DOCX-26 | Automatic defect screenshot capture | Evidence | Should | 4 | NOT IMPLEMENTED | Storage/replay exist; auto-capture deferred |
| DOCX-27 | Real styled DOCX export | Export | Must | 3 | PARTIALLY COMPLETE | Existing `export.py` / docxtpl path; not redesigned this pass |
| DOCX-28 | Bundled PDF engine | Export | Must | 3 | PARTIALLY COMPLETE | WeasyPrint optional + minimal PDF fallback remain |
| DOCX-29 | XLSX export | Export | Should | 3 | NOT IMPLEMENTED | — |
| DOCX-30 | JSON data export | Export | Nice | 3 | PARTIALLY COMPLETE | SARIF/OSCAL/CSV exist; generic JSON report export not added |
| DOCX-31 | Tenant logo / cover title on built-ins | Branding | Must | 1 | VERIFIED COMPLETE | Branding from `ReportTemplate` applied to built-in cover |
| DOCX-32 | Page numbers / running footer | Branding | Must | 2 | PARTIALLY COMPLETE | CSS `@page` Page X of Y for print/PDF |
| DOCX-33 | DRAFT watermark until signed | Branding | Should | 2 | VERIFIED COMPLETE | `is_draft` watermark on generation |
| DOCX-34 | White-label branded emails | Branding | Nice | 5 | NOT IMPLEMENTED | Out of scope this pass |
| DOCX-35 | Visual template designer | Branding | Nice | 5 | PARTIALLY COMPLETE | Existing sandboxed tenant templates |
| DOCX-36 | Multi-language templates | Branding | Nice | 5 | NOT IMPLEMENTED | — |
| DOCX-37 | Authenticated testing | Testing | Should | 4 | NOT VERIFIED | Runner exists; not assessed against DOCX criteria here |
| DOCX-38 | Multi-role / access-control testing | Testing | Should | 4 | NOT IMPLEMENTED | — |
| DOCX-39 | Parameter tamper testing | Testing | Should | 4 | PARTIALLY COMPLETE | Proof replay exists; not full tamper suite |
| DOCX-40 | Testing checklists WSTG/ASVS | Testing | Should | 4 | PARTIALLY COMPLETE | Passed checks section; not full checklist UX |
| DOCX-41 | CERT-In compliance pack | Compliance | Should | 5 | VERIFIED COMPLETE | `packs/cert_in_2022.yaml` |
| DOCX-42 | OWASP Top 10 compliance pack | Compliance | Should | 5 | PARTIALLY COMPLETE | `owasp.yaml` + finding fields; not a hub framework pack |
| DOCX-43 | OWASP ASVS pack | Compliance | Nice | 5 | PARTIALLY COMPLETE | ASVS refs on findings; not a full pack |
| DOCX-44 | Two-way ticket sync | Collaboration | Should | 5 | PARTIALLY COMPLETE | Jira/GitHub exist, off by default |
| DOCX-45 | Client remediation portal | Collaboration | Nice | 5 | PARTIALLY COMPLETE | Portal routes exist; polish deferred |
| DOCX-46 | Dashboards | Collaboration | Nice | 5 | PARTIALLY COMPLETE | Trend + ageing reports; no interactive dashboard |

## Totals

| Disposition | Count (DOCX 1–46) |
| --- | ---: |
| VERIFIED COMPLETE | 18 |
| PARTIALLY COMPLETE | 18 |
| NOT IMPLEMENTED | 8 |
| NOT VERIFIED | 1 |
| BLOCKED | 0 |

Highest remaining Must gaps: DOCX-18, DOCX-21, DOCX-22 (structured finding fields / date checks), DOCX-27/28 (export polish).
