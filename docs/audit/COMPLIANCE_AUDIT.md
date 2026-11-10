# Compliance and Reporting Audit

**Agent:** 5 — Compliance and Reporting Engineer  
**Scope:** Read-only inspection of framework catalogue, engine, reports, API, frontend, and Docker packaging.  
**Source of truth:** Runtime catalogue from `attestra.compliance.engine.load_library()` (hub `controls.yaml` + `data/packs/*.yaml`), cross-checked with `lat.md/compliance.md` and `docs/MASTER_IMPL_PHASE0_BASELINE.md`.  
**Date of inspection:** 2026-11-10  

No application code was changed. This file is the only deliverable.

---

## 1. Catalogue load verification

`load_library()` reads:

| Path | Role |
| --- | --- |
| `attestra/compliance/data/controls.yaml` | Hub frameworks + objectives + control titles |
| `attestra/compliance/data/cwe_map.yaml` | CWE → objectives (`strength` / `rationale`) |
| `attestra/compliance/data/packs/*.yaml` | Merged via `_merge_pack` (must reference existing objectives) |

**Live load result (this workspace):** exactly these ten IDs, matching the Phase 0 authoritative catalogue:

`asvs_4_0`, `cert_in_2022`, `dora_2022`, `iso_27001_2022`, `iso_42001_2023`, `nist_csf_2`, `pci_dss_4`, `rbi_csf_2016`, `sebi_cscrf_2024`, `soc2`

| Metric | Value |
| --- | --- |
| Frameworks | 10 |
| Hub objectives | 44 (18 finding, 26 process) |
| CWE mappings | 58 |
| Pack YAML files on disk | 7 under `attestra/compliance/data/packs/` |

Hub (core) frameworks live only in `controls.yaml`: `pci_dss_4`, `iso_27001_2022`, `soc2`.  
Pack frameworks: the other seven YAML files listed above.  
Every pack ref has a title; loader rejects unknown objectives and duplicate framework keys.

**Related catalogues (recommendations, not control registers):**  
`industries.yaml`, `countries.yaml`, `technical_scope.yaml`, `recommend_rules.yaml`, `owasp.yaml` — all present under `attestra/compliance/data/`.

---

## 2. Per-framework status table

Status meanings used below:

| Status | Meaning |
| --- | --- |
| **Loaded** | Present in `load_library().frameworks` with titled refs |
| **Assessable** | `services.compliance` / `evaluate` produces `ControlResult` rows |
| **Reportable** | Listed in `reports/data/template_config.yaml` `supported_frameworks` and usable with `kind=compliance` |
| **Specialized extras** | Framework-specific pack zip extras, sampling, SoA, timeline, etc. |

| Framework ID | Source | Display name | Unique refs | Linked objectives | Loaded | Assessable | Reportable | Specialized extras | Implementation notes |
| --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- |
| `pci_dss_4` | hub | PCI DSS v4.0.1 | 29 | 27 | Yes | Yes | Yes | Pack zip: scan calendar, ASV, segmentation CSVs; CDE scope filter | Strongest process automation (ASV, quarterly, segmentation). Titles paraphrased — external review pending (`REVIEW.md`). |
| `iso_27001_2022` | hub | ISO/IEC 27001:2022 Annex A | 20 | 24 | Yes | Yes | Yes | Pack zip: SoA, nonconformities, 9.2 audit samples; `iso_soa` report; editable `SoaEntry` | SoA storage is 27001-only (no framework column). |
| `soc2` | hub | SOC 2 Trust Services Criteria (Security) | 14 | 25 | Yes | Yes | Yes | `GET /api/engagements/{id}/soc2/sample`, CLI `soc2-sample`, `reports/soc2_sampling.py` | Pack zip meta labels SOC 2 but `_framework_extras` has no SOC 2 branch (sampling is a separate API). |
| `asvs_4_0` | pack | OWASP ASVS 4.0 | 14 (V1–V14) | 18 | Yes | Yes | Yes | Chapter-level register only | **No dedicated test file references `asvs_4_0`.** `test_nine_frameworks_load` asserts nine IDs and omits ASVS (still passes via `<=`). |
| `cert_in_2022` | pack | CERT-In Directions 2022 | 5 | 8 | Yes | Yes | Yes | Generic pack zip only | Operational duties (6-hour reporting, 180-day logs) are not automated clocks — scan evidence is partial by design. |
| `dora_2022` | pack | DORA (EU 2022/2554) | 7 | 18 | Yes | Yes | Yes | Generic pack zip only | Article-level summaries; legal interpretation out of band. Covered by `test_phase8_framework_packs`. |
| `iso_42001_2023` | pack | ISO/IEC 42001:2023 AI management system | 65 | 30 | Yes | Yes | Yes | Pack zip: check register, SoA draft CSV, OWASP LLM Top 10 map; `iso42001.py` helpers | Most controls use `assessor_evidence` (stay `not_assessed` until confirmed). Editable SoA **not** shared with 42001 (schema gap documented in `docs/ISO_42001.md`). |
| `nist_csf_2` | pack | NIST CSF 2.0 | 16 | 18 | Yes | Yes | Yes | Generic pack zip only | Outcome/profile tooling not productized; subset of CSF subcategory IDs. |
| `rbi_csf_2016` | pack | RBI Cyber Security Framework for Banks (2016) | 14 | 18 | Yes | Yes | Yes | Generic pack zip only | Annex 1 baseline subset; bank governance not modeled. |
| `sebi_cscrf_2024` | pack | SEBI CSCRF (2024) | 10 | 19 | Yes | Yes | Yes | Function-level register; **SEBI timeline** UI/API (`sebi_timeline.py`, `/engagements/{eid}/sebi-timeline`) | Function groupings, not full circular control text. |

### Control ref inventories (loaded)

- **pci_dss_4:** `1.2.1`, `1.3.1`, `2.2.1`, `3.5.1`, `4.2.1`, `6.2.4`, `6.3.1`, `6.3.2`, `6.3.3`, `6.4.1`, `6.4.2`, `6.5.1`, `7.2.1`, `8.3.1`, `8.4.2`, `8.6.2`, `10.2.1`, `10.4.1`, `11.3.1`, `11.3.1.1`, `11.3.1.2`, `11.3.2`, `11.4.1`–`11.4.6`, `12.3.1`
- **iso_27001_2022:** Annex A set + `Clause 6.1.2`, `Clause 8.2`, `Clause 10.2`
- **soc2:** `CC3.2`, `CC4.1`, `CC4.2`, `CC6.1`, `CC6.3`, `CC6.6`–`CC6.8`, `CC7.1`–`CC7.4`, `CC8.1`, `CC9.2`
- **asvs_4_0:** `V1`–`V14`
- **cert_in_2022:** `Dir.(i)`, `Dir.(ii)`, `Dir.(iv)`, `Dir.(v)`, `Annex I`
- **dora_2022:** `Art.6`, `Art.8`, `Art.9`, `Art.10`, `Art.24`, `Art.25`, `Art.28`
- **iso_42001_2023:** Clauses 4–10 + 38 Annex A controls (`A.2.2` … `A.10.4`) — 65 titled refs
- **nist_csf_2:** 16 subcategory-style IDs (e.g. `ID.RA-01`, `PR.PS-06`)
- **rbi_csf_2016:** `A1.1`, `A1.2`, `A1.4`–`A1.9`, `A1.12`, `A1.14`–`A1.17`, `A1.20`
- **sebi_cscrf_2024:** `GV.OV`, `GV.SC`, `ID.RA`, `PR.AA`, `PR.DS`, `PR.IP`, `PR.MA`, `PR.PT`, `DE.CM`, `RS.MI`

No unsupported / invented framework IDs were found in the runtime catalogue. Do not treat HIPAA, CRA, or other unlisted packs as present.

---

## 3. Assessment engine and mappings

| Capability | Location | Evidence |
| --- | --- | --- |
| Hub-and-spoke CWE → objective → framework | `engine.py` `objectives_for`, `evaluate` | Working for all loaded frameworks |
| Mapping strength + rationale (C7) | `cwe_map.yaml`, `mappings_for_objective`, compliance template Mapping column | Present; tested in `tests/test_c7_c11_mapping_soc2.py`, `tests/test_library_integrity.py` |
| Propose-then-confirm | `ControlAssessment`, `services.confirm_control` | Auditor/admin only; blocks `met` with open med+ findings unless override |
| PCI CDE scoping | `in_framework_scope` | Only `pci_dss_4`; out-of-CDE assets excluded |
| Process rules | `_process_status` | `has_imports`, authorization, PT, ASV, segmentation, quarterly, risk assessment, `assessor_evidence` |
| Shared sampling table | `compliance/sampling.py` | Used by ISO 9.2 draw and SOC 2 Type II sample |
| OSCAL / SCF import | `compliance/libraries/{oscal,scf,common}.py`, CLI `library-import` | Can write new packs; not a substitute for the ten catalogue IDs |
| OWASP Top 10 / ASVS / WSTG labels on findings | `owasp.py` + `owasp.yaml` | Finding enrichment; separate from ASVS framework pack |
| External review log | `compliance/data/REVIEW.md` | Reviewer still **pending** |

Caveat (also in `lat.md/compliance.md`): control titles are paraphrased; licensed standard text must be verified before production audit use.

---

## 4. Report generation inventory

### Report kinds (`attestra/reports/render.py` + `template_config.yaml`)

| Kind | Template | Framework-aware | Notes |
| --- | --- | --- | --- |
| `technical` | `templates/technical.html.j2` | Lists engagement frameworks | Full VAPT technical report |
| `executive` | `executive.html.j2` | Indirect | Summary / top risks |
| `compliance` | `compliance.html.j2` | **Required** `--framework` / query | Per-framework control roll-up + evidence index |
| `iso_soa` | `iso_soa.html.j2` | Framework arg supported | Editable SoA data is 27001-keyed; 42001 uses roll-up / draft CSV |
| `owasp_top10` | `owasp_top10.html.j2` | LLM Top 10 when `iso_42001_2023` in engagement | Web Top 10 always |
| `retest` | `retest.html.j2` | Indirect | Remediation verification |
| `ageing` | `ageing.html.j2` | Indirect | SLA / ageing |
| `closure_letter` | `closure_letter.html.j2` | Indirect | Letter |
| `attestation_letter` | `attestation_letter.html.j2` | Indirect | Safe-to-host style; not a certification claim |

### Export / pack surfaces

| Output | Module / route | Framework tie-in |
| --- | --- | --- |
| HTML / PDF / DOCX | `render.py`, `pdf.py`, `docx_export.py` | Framework display names via `load_library` / `labels.framework_label` |
| Framework evidence ZIP | `reports/packs.py` → `GET /api/engagements/{eid}/packs/{framework}` | All catalogue IDs; extras only for PCI, ISO 27001, ISO 42001 |
| SOC 2 sample CSV/JSON | `reports/soc2_sampling.py` → API + CLI | `soc2` only |
| OSCAL assessment-results | `reports/oscal.py` | Per engagement framework |
| SARIF / CSV / engagement export | `sarif.py`, `findings_csv.py`, `engagement_export.py` | Export walks `eng.frameworks` for compliance sections |
| SEBI timeline | `compliance/sebi_timeline.py` + web route | Engagement milestones for CSCRF testing cadence |
| Template config | `reports/data/template_config.yaml` | `supported_frameworks` lists all **10** catalogue IDs |

`template_config.yaml` `supported_frameworks` order:  
`pci_dss_4`, `iso_27001_2022`, `soc2`, `iso_42001_2023`, `cert_in_2022`, `nist_csf_2`, `rbi_csf_2016`, `sebi_cscrf_2024`, `dora_2022`, `asvs_4_0`.

---

## 5. API and worker exposure

| Endpoint / entry | Role | Catalogue coverage |
| --- | --- | --- |
| `GET /api/frameworks` | Name map from `load_library()` | All 10 |
| `GET /api/catalog`, `GET /api/profile/catalogues` | Recommend catalogues | Industries/countries/scopes |
| `POST /api/frameworks/recommend` | Advisory recommendations | Only IDs in `load_library()` (verified for banking/IN sample) |
| `GET /api/engagements/{eid}/compliance?framework=` | Control roll-up | Any library framework; OpenAPI **description** still uses stale `models.FRAMEWORKS` (3 hub IDs only) |
| `POST /api/engagements/{eid}/compliance/confirm` | Assessor confirm | Same |
| `GET /api/engagements/{eid}/packs/{framework}` | Evidence zip | Same |
| `GET /api/engagements/{eid}/soc2/sample` | Type II sampling | `soc2` |
| ISO SoA API helpers | `iso_soa` / generate | 27001-oriented storage |
| CLI `compliance`, `compliance-export`, `library-import`, `soc2-sample`, `report … --framework` | Operator surfaces | Library-backed |

Engagement create/update validates frameworks with `tuple(load_library().frameworks) or FRAMEWORKS` (`services.py`) — runtime catalogue wins.

**Workers:** `attestra/jobs/**` has no direct compliance imports. Workers share the same installed package; quarterly PCI schedules and report generation run through services that call the library when needed. Framework YAML must be inside the image for both API and worker roles (single Dockerfile image, two CMDs).

**Stale constant:** `attestra/models.py`  
`FRAMEWORKS = ("pci_dss_4", "iso_27001_2022", "soc2")`  
Comment acknowledges packs add more at load time, but API OpenAPI text still advertises only these three.

---

## 6. Frontend selection

| UI | Behavior |
| --- | --- |
| New engagement (`new_engagement.html` + `static/attestra.js`) | Heading **Compliance Frameworks to Report Against**; checkboxes for every `load_library()` framework; recommend via `POST /api/frameworks/recommend`; Industry/Country required for recommend |
| Edit engagement (`engagement.html`) | Same full `fw_names` checkbox set; report form framework select limited to **engagement’s** selected frameworks |
| Engagement overview / home | Chips via `fw_name` filter |
| Login marketing pills | All library display names |
| Portal | Defaults framework from engagement or first selected |
| SEBI timeline page | `GET /engagements/{eid}/sebi-timeline` |
| ISO SoA page | Warns if engagement lacks ISO 27001 |

Recommendations never invent IDs outside the library (`lat.md/compliance.md`, `recommend.py`).

---

## 7. Tests touching the catalogue

| Test module | Coverage |
| --- | --- |
| `tests/test_library_integrity.py` | CWE strength/rationale; every ref titled; Phase 3 PCI/ISO/SOC refs |
| `tests/test_phase8_framework_packs.py` | Packs: cert_in, rbi, sebi, dora, nist + core three; roll-up; report render for RBI |
| `tests/test_report_coverage_enhancements.py` | `test_nine_frameworks_load` — **nine** IDs (omits `asvs_4_0`) |
| `tests/test_c7_c11_mapping_soc2.py` | Mapping strength + SOC 2 sample |
| `tests/test_control_libraries.py` | OSCAL/SCF import paths |
| `tests/test_phase0_integrity.py` | Confirm gates; cert_in / dora used in scenarios |
| `tests/test_compliance_reports.py` | Older PCI/ISO compliance report integrity |

**Gap:** no test module asserts `asvs_4_0` load, roll-up uniqueness, or compliance report render (despite `lat.md/tests.md` describing ASVS coverage). ISO 42001 is only weakly asserted via “nine frameworks” / report coverage lists — dedicated `test_iso42001_pack.py` named in lat is **not** present under `tests/`.

---

## 8. Docker / packaging — what must be in the image

Dockerfile builds a wheel from `COPY attestra ./attestra` then installs wheels into the runtime image (source tree is **not** retained). Therefore **setuptools `package-data`** is the inclusion contract.

Current `[tool.setuptools.package-data]` (`pyproject.toml`):

```
attestra = [
  "compliance/data/*.yaml",
  "compliance/data/packs/*.yaml",
  "compliance/data/*.md",
  "reports/templates/*.j2",
  "reports/templates/docx/*",
  "web/templates/*.html",
  "web/static/*.css",
  "web/static/*.js",
  "web/static/fonts/*.woff2",
  "reports/fonts/*.ttf",
  "reports/fonts/*.md",
]
```

### Included (required for compliance engine + UI)

| Artifact | Matched by package-data? |
| --- | --- |
| `compliance/data/controls.yaml`, `cwe_map.yaml`, `owasp.yaml` | Yes (`*.yaml`) |
| `compliance/data/industries.yaml`, `countries.yaml`, `technical_scope.yaml`, `recommend_rules.yaml` | Yes |
| `compliance/data/packs/*.yaml` (all 7 packs) | Yes |
| `compliance/data/REVIEW.md` | Yes (`*.md`) |
| `reports/templates/*.j2` (incl. `compliance`, `iso_soa`, `owasp_top10`) | Yes |
| Web templates/static for framework selection | Yes |

### Missing from wheel (runtime risk)

| Artifact | Needed by | Matched? |
| --- | --- | --- |
| **`reports/data/template_config.yaml`** | `reports/template_config.py` (`load_template_config`) — assessment types, **supported_frameworks**, kind sections, disclaimer | **No** |

**COMPLIANCE-G01:** Add `reports/data/*.yaml` (or at least `reports/data/template_config.yaml`) to `[tool.setuptools.package-data]` so Docker API/worker images retain report metadata and the documented ten-framework `supported_frameworks` list.

Also confirm after any packaging change that `importlib.resources` / installed path still finds:

- all seven pack YAMLs  
- recommend YAML catalogues  
- Jinja compliance templates  
- report fonts  

Workers and API use the same image; no separate compliance volume is defined in Helm for YAML packs — packs must ship inside the package.

---

## 9. Gaps (COMPLIANCE-G01…)

| ID | Severity | Finding | Evidence |
| --- | --- | --- | --- |
| **COMPLIANCE-G01** | High (deploy) | `reports/data/template_config.yaml` not in setuptools package-data → absent from pip wheel / Docker image | `pyproject.toml` package-data vs `template_config.py` path |
| **COMPLIANCE-G02** | Medium | `models.FRAMEWORKS` lists only 3 hub IDs; OpenAPI description for `/compliance` understates catalogue | `models.py:65`, `api.py` Query description |
| **COMPLIANCE-G03** | Medium | No automated test references `asvs_4_0`; “nine frameworks” test omits ASVS | Grep of `tests/`; `test_report_coverage_enhancements.py` |
| **COMPLIANCE-G04** | Medium | Editable SoA (`SoaEntry`) has no `framework` column — ISO 42001 SoA not independently editable alongside 27001 | `models.SoaEntry` columns; `docs/ISO_42001.md` |
| **COMPLIANCE-G05** | Low | Framework pack ZIP `_framework_extras` only special-cases PCI, ISO 27001, ISO 42001; SOC 2 / SEBI / others get generic INDEX+CSV only | `reports/packs.py` |
| **COMPLIANCE-G06** | Low | Pack frameworks are **partial registers** (chapter/article/function level), not full normative control sets; process/legal duties often `not_assessed` without assessor evidence | Pack YAML headers; CERT-In/DORA/RBI/SEBI comments |
| **COMPLIANCE-G07** | Low | External standards review still pending | `compliance/data/REVIEW.md` |
| **COMPLIANCE-G08** | Info | `lat.md/tests.md` cites ASVS / `test_iso42001_pack.py` coverage that is missing or incomplete in `tests/` | lat vs filesystem |
| **COMPLIANCE-G09** | Info | CERT-In 6-hour incident clock and similar regulatory timers are not automated | Pack design + prior VAPT coverage matrix |

None of G02–G09 invent missing catalogue IDs; all ten required IDs **are** loadable today.

---

## 10. Summary

Attestra’s compliance engine **does load the full ten-framework catalogue** required by the Phase 0 baseline and agent brief:

1. **Core (hub YAML):** `pci_dss_4`, `iso_27001_2022`, `soc2`  
2. **Packs:** `asvs_4_0`, `cert_in_2022`, `dora_2022`, `iso_42001_2023`, `nist_csf_2`, `rbi_csf_2016`, `sebi_cscrf_2024`

Assessment, recommend, engagement validation, frontend selection, compliance HTML reports, and generic evidence packs work against that catalogue. PCI, ISO 27001, SOC 2, and ISO 42001 have the deepest specialized tooling; India/EU packs are thinner, chapter/article-level registers with honest “partial / needs assessor” behavior.

**Do not claim** full normative coverage, certification readiness, or automated CERT-In/DORA legal compliance. Titles are paraphrased pending external review.

**Highest-priority packaging fix for Docker:** ship `reports/data/template_config.yaml` in the wheel (**COMPLIANCE-G01**). Next: align `FRAMEWORKS` / OpenAPI text with `load_library()`, add ASVS (+ stronger 42001) tests, and optionally schema-split SoA by framework.

---

*End of compliance audit.*
