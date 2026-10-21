# Attestra Gap Register

Prioritized gaps between the consolidated DOCX / coverage baseline and verified implementation. Categories match the agent prompt.

## Priority legend

1. Critical security / tenant isolation  
2. Data integrity / incorrect compliance claims  
3. Core assessment lifecycle  
4. Framework mappings  
5. Report generation / evidence traceability  
6. Assessment–framework coverage  
7. Reliability / ops  
8. UI/UX and lower enhancements  

## Closed or reduced this pass

| Gap ID | Req | Priority | Was | Now | Strategy / acceptance |
| --- | --- | --- | --- | --- | --- |
| G-RPT-01 | DOCX-04,13,19,20,24,31 | 5 | STORED-NOT-RENDERED | VERIFIED COMPLETE | Template + context; tests in `test_report_coverage_enhancements.py` |
| G-RPT-02 | DOCX-14 | 5 | STORED-NOT-RENDERED | VERIFIED COMPLETE | New `retest` kind + template |
| G-RPT-03 | DOCX-01,02,07,08,12,33 | 5 | Partial/No | VERIFIED COMPLETE | Cover, TOC, disclaimer, environment, legend, DRAFT |
| G-RPT-04 | DOCX-06,09,10,11,15 | 5/8 | Partial | VERIFIED COMPLETE / PARTIAL | Test types, phases, standards, chart, conclusion |
| G-CFG-01 | Prompt §7.4 | 5 | Missing | VERIFIED COMPLETE | `template_config.yaml` + loader |
| G-FW-01 | BASE-FW-01 | 4 | Verified in packs | VERIFIED COMPLETE | Parametrized compliance report tests for all 9 |
| G-MX-01 | BASE-MX-01 | 6 | Missing doc | VERIFIED COMPLETE | Coverage matrix markdown |

## Open gaps (implement next)

| Gap ID | Req | Pri | Category | Severity | Evidence of gap | Strategy | Acceptance tests |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G-FIND-01 | DOCX-21 | 5 | Finding schema | Medium | No `impact` column | Alembic migration + UI/API + template | Create/update finding with impact; appears in technical report |
| G-FIND-02 | DOCX-22 | 5 | Finding schema | Medium | Only free-text `location` | JSON field for URL/method/param list | Structured rows render |
| G-FIND-03 | DOCX-23 | 5 | Finding schema | Low | No references field | Migration + report section | References printed |
| G-SIGN-01 | DOCX-18 | 2 | Sign-off integrity | Medium | No date cross-check | Validate cover/window/retest dates in `submit_report`/`sign_report` | Conflicting dates → ServiceError |
| G-EVID-01 | DOCX-25 | 5 | Evidence render | Low | http_pair only listed | Pretty-print JSON pair in finding detail | Request/response visible |
| G-EXP-01 | DOCX-27/28 | 5 | Export | Medium | Minimal/optional engines | Ship docxtpl template + WeasyPrint path docs | Golden DOCX/PDF fixtures |
| G-EXP-02 | DOCX-29 | 8 | Export | Low | No XLSX | openpyxl exporter | Downloadable workbook |
| G-TEST-01 | DOCX-37–40 | 3 | Testing coverage | Medium | Not DOCX-verified | Confirm runner auth profiles; checklist UX | E2E with fixtures |
| G-BOX-01 | DOCX-06 box | 8 | Engagement metadata | Low | No box-type field | Optional engagement field | Renders on cover |
| G-DIST-01 | DOCX-05 | 8 | Front matter | Low | No distribution list model | Optional JSON on Report/Engagement | Table on cover |

## Defective / not applicable

| Gap ID | Notes |
| --- | --- |
| — | No defective false-close on retest found; guard remains in `retest.py`. |
| G-NA-01 | Treating failed continuous scans as “clean” is forbidden by design; scan history labels failures explicitly. |

## Security notes

No security controls were weakened for tests. Screenshot embeds require on-disk hash match; mismatched files are omitted. Tenant branding logo remains sandboxed via existing template validation.
