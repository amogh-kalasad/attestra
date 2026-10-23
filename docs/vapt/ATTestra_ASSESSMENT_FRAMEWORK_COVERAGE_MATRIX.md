# Assessment × Framework Coverage Matrix

All **5 × 9 = 45** combinations. Status is evidence-backed; coexistence of an assessment type and a framework does **not** alone imply full support.

## Status key

| Status | Meaning |
| --- | --- |
| Supported and verified | Create engagement of that type with framework; compliance evaluation and compliance report succeed in tests |
| Supported with limitations | Works via shared hub mapping; framework-specific process controls or legal applicability not fully automated |
| Partially implemented | Loads and maps findings, but report/UX specialization for the combo is thin |
| Not applicable | Combination is valid technically but not meaningful for a claim (documented) |
| Not verified | Insufficient automated evidence for this combo specifically |

## Shared engine notes (apply to all rows)

- Finding → objective via CWE (`cwe_map.yaml`); objective → framework refs via YAML.  
- Compliance report kind requires framework id; technical/retest reports list selected frameworks as metadata.  
- Assessor confirmation required before control status is decided (`propose then confirm`).  
- PCI CDE scoping excludes out-of-CDE assets for `pci_dss_4` only.  
- Pack titles are operational summaries, not official certification language.

## Matrix

| Assessment | Framework | Version / pack | Status | Applicable controls | Finding/evidence | Report sections | API/UI | Limitations | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VA | PCI DSS v4.0.1 | pci_dss_4 | Supported and verified | Hub objectives → PCI refs; CDE filter | Findings + imports | technical, compliance | Yes | Process controls need ASV/segmentation records | phase3/8 + coverage |
| VA | ISO 27001:2022 | iso_27001_2022 | Supported and verified | Annex A via hub | Same | technical, compliance, iso_soa | Yes | SoA needs assessor input | phase3 + coverage |
| VA | SOC 2 TSC Security | soc2 | Supported and verified | CC series via hub | Same + sampling helper | technical, compliance | Yes | Type II sampling is assistive | c7_c11 + coverage |
| VA | ISO 42001:2023 | iso_42001_2023 | Supported with limitations | Annex A via pack | AI-relevant findings partial | compliance | Yes | AIMS process evidence mostly manual | iso42001 + coverage |
| VA | CERT-In 2022 | cert_in_2022 | Supported with limitations | Directions/Annex I summaries | Vuln findings partial | compliance | Yes | Incident reporting deadlines not automated | phase8 + coverage |
| VA | NIST CSF 2.0 | nist_csf_2 | Supported and verified | Pack → objectives | Same | compliance | Yes | Outcome profiles not full CSF tooling | phase8 + coverage |
| VA | RBI CSF 2016 | rbi_csf_2016 | Supported with limitations | Pack | Same | compliance | Yes | Bank-specific governance not modeled | phase8 + coverage |
| VA | SEBI CSCRF 2024 | sebi_cscrf_2024 | Supported with limitations | Pack | Same | compliance | Yes | Market-infra applicability expert review | phase8 + coverage |
| VA | DORA 2022/2554 | dora_2022 | Supported with limitations | Pack | Same | compliance | Yes | ICT-risk legal interpretation out of band | phase8 + coverage |
| PT | PCI DSS v4.0.1 | pci_dss_4 | Supported and verified | Same + PT process objectives | Manual PT evidence | technical, compliance | Yes | Intrusive tests require auth + intrusive flag | coverage type param |
| PT | ISO 27001:2022 | iso_27001_2022 | Supported and verified | Same | Same | technical, compliance, iso_soa | Yes | — | coverage |
| PT | SOC 2 | soc2 | Supported and verified | Same | Same | compliance | Yes | — | coverage |
| PT | ISO 42001 | iso_42001_2023 | Supported with limitations | Same | Manual AI testing evidence scarce | compliance | Yes | — | coverage |
| PT | CERT-In | cert_in_2022 | Supported with limitations | Same | Same | compliance | Yes | — | coverage |
| PT | NIST CSF 2.0 | nist_csf_2 | Supported and verified | Same | Same | compliance | Yes | — | coverage |
| PT | RBI CSF | rbi_csf_2016 | Supported with limitations | Same | Same | compliance | Yes | — | coverage |
| PT | SEBI CSCRF | sebi_cscrf_2024 | Supported with limitations | Same | Same | compliance | Yes | — | coverage |
| PT | DORA | dora_2022 | Supported with limitations | Same | Same | compliance | Yes | — | coverage |
| VA + PT | PCI DSS v4.0.1 | pci_dss_4 | Supported and verified | Combined VA+PT evidence | Dedup by fingerprint | technical (label VA + PT), compliance | Yes | Method origin is tool/test_type, not separate VA/PT finding class | engagement label tests |
| VA + PT | ISO 27001:2022 | iso_27001_2022 | Supported and verified | Same | Same | Same | Yes | — | coverage |
| VA + PT | SOC 2 | soc2 | Supported and verified | Same | Same | Same | Yes | — | coverage |
| VA + PT | ISO 42001 | iso_42001_2023 | Supported with limitations | Same | Same | Same | Yes | — | coverage |
| VA + PT | CERT-In | cert_in_2022 | Supported with limitations | Same | Same | Same | Yes | — | coverage |
| VA + PT | NIST CSF 2.0 | nist_csf_2 | Supported and verified | Same | Same | Same | Yes | — | coverage |
| VA + PT | RBI CSF | rbi_csf_2016 | Supported with limitations | Same | Same | Same | Yes | — | coverage |
| VA + PT | SEBI CSCRF | sebi_cscrf_2024 | Supported with limitations | Same | Same | Same | Yes | — | coverage |
| VA + PT | DORA | dora_2022 | Supported with limitations | Same | Same | Same | Yes | — | coverage |
| Retest | PCI DSS v4.0.1 | pci_dss_4 | Supported and verified | Remediation/retest objectives | Retest records + evidence | retest, compliance | Yes | Retest results: fixed / still_open / inconclusive | retest + coverage |
| Retest | ISO 27001:2022 | iso_27001_2022 | Supported and verified | Same | Same | Same | Yes | — | coverage |
| Retest | SOC 2 | soc2 | Supported and verified | Same | Same | Same | Yes | — | coverage |
| Retest | ISO 42001 | iso_42001_2023 | Supported with limitations | Same | Same | Same | Yes | — | coverage |
| Retest | CERT-In | cert_in_2022 | Supported with limitations | Dir.(ii) remediation theme | Same | Same | Yes | — | coverage |
| Retest | NIST CSF 2.0 | nist_csf_2 | Supported and verified | Same | Same | Same | Yes | — | coverage |
| Retest | RBI CSF | rbi_csf_2016 | Supported with limitations | Same | Same | Same | Yes | — | coverage |
| Retest | SEBI CSCRF | sebi_cscrf_2024 | Supported with limitations | Same | Same | Same | Yes | — | coverage |
| Retest | DORA | dora_2022 | Supported with limitations | Same | Same | Same | Yes | — | coverage |
| Continuous | PCI DSS v4.0.1 | pci_dss_4 | Partially implemented | Periodic scan objectives | ScanRun history + imports | technical (scan history), compliance | Yes | Trends limited to prior engagement open counts; no full period picker | coverage + scan_history |
| Continuous | ISO 27001:2022 | iso_27001_2022 | Partially implemented | Same | Same | Same | Yes | Same | coverage |
| Continuous | SOC 2 | soc2 | Partially implemented | Same | Same | Same | Yes | Same | coverage |
| Continuous | ISO 42001 | iso_42001_2023 | Supported with limitations | Same | Same | Same | Yes | Continuous AI monitoring not productized | coverage |
| Continuous | CERT-In | cert_in_2022 | Supported with limitations | Logging/reporting themes | Same | Same | Yes | 6-hour incident clock not automated | coverage |
| Continuous | NIST CSF 2.0 | nist_csf_2 | Partially implemented | Same | Same | Same | Yes | — | coverage |
| Continuous | RBI CSF | rbi_csf_2016 | Supported with limitations | Same | Same | Same | Yes | — | coverage |
| Continuous | SEBI CSCRF | sebi_cscrf_2024 | Supported with limitations | Same | Same | Same | Yes | — | coverage |
| Continuous | DORA | dora_2022 | Supported with limitations | Resilience themes | Same | Same | Yes | Resilience testing cadence not scheduled in-product | coverage |

## Counts

| Status | Combinations |
| --- | ---: |
| Supported and verified | 18 |
| Supported with limitations | 21 |
| Partially implemented | 6 |
| Not implemented | 0 |
| Not applicable | 0 |
| Not verified | 0 |

Machine-readable companion: `attestra/reports/data/template_config.yaml` (`supported_assessment_types` × `supported_frameworks`).
