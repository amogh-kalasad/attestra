# Attestra — Gap analysis vs "Security Testing & Compliance Platform Architecture v2"

Date: 2026-10-14 (IST). Spec dated Oct 13 2026. Code: Attestra working tree v0.1.0, reviewed read-only (no code changes).

## Summary

**Overall: 31% done** (mean of 13 areas, each weighted equally). Item-weighted: 36% across 88 requirements.

Method: per requirement Done=1, Done-untested=0.75, Partial=0.5, Stub=0.25, Not done=0; area % = mean of its items; overall = mean of area %.

Status counts: Done 19, Done-untested 3, Partial 19, Stub 3, Not done 44

| Area | Items | % done |
|---|---|---|
| Scope & authorization gate | 9 | 36% |
| Scanners & runners | 8 | 25% |
| Findings, dedup & risk | 9 | 53% |
| Lifecycle & SLA | 7 | 57% |
| Platform infrastructure | 8 | 19% |
| Identity, RBAC & tenancy | 5 | 10% |
| UI | 4 | 44% |
| Interchange formats | 4 | 25% |
| AI / LLM | 2 | 0% |
| Legal & process | 3 | 17% |
| Compliance crosswalk | 11 | 45% |
| Reports & signing | 10 | 50% |
| Evidence & audit | 8 | 28% |

**Tests:** `pytest` in the working tree (TEMP set to a local temp dir): **34 passed, 0 failed**, 1 deprecation warning, ~6 s.

**Key fact:** Attestra is an *import-and-report* layer. It never runs scanners (importers/__init__.py), so runners, OPA, Temporal, kill switch and egress controls have nothing to act on yet.

## Requirement register

### Scope & authorization gate — 36%

| # | Requirement | Doc section | Status | Evidence (file:func/line, tests) |
|---|---|---|---|---|
| S1 | No valid signed authorization -> no scan/import | Guardrails; Entities/Authorization | **Done** | services.py:import_results L285-286; tests test_services.py:10,17 |
| S2 | Authorization record: doc, sha256, signer, RoE, expiry | Entities | **Done** | models.py Authorization L98; services.add_authorization L128; test_scope.py:35 |
| S3 | Allow-list ScopeRule (asset/pattern, allow/deny, rate_limit) | Entities/ScopeRule | **Partial** | Assets act as allow-list + per-environment auth (services.py L292-300, match_asset L267); no deny rules/patterns/rate_limit; test_scope.py:59,68,76 |
| S4 | Test-window enforcement | Guardrails | **Partial** | Authorization signed_on..expires_on checked (models.py is_valid); engagement window_start/end stored but never enforced |
| S5 | OPA/Rego policy check on every job dispatch | Guardrails; Tech stack | **Not done** | No OPA; plain Python checks; no job dispatch exists |
| S6 | Target ownership verification (DNS TXT/HTTP file/cloud link) | Guardrails | **Not done** | none |
| S7 | Kill switch (client + lead halt, logged) | Guardrails | **Not done** | nothing to halt; no runners |
| S8 | Safe-by-default profiles; intrusive off unless RoE | Guardrails | **Stub** | Asset.intrusive_allowed flag (models.py) stored only, not enforced |
| S9 | Rate limits for production | Guardrails | **Not done** | none |

### Scanners & runners — 25%

| # | Requirement | Doc section | Status | Evidence (file:func/line, tests) |
|---|---|---|---|---|
| R1 | Scanner adapters/parsers (ZAP, Nuclei, Trivy, SARIF) | OSS landscape/Scanners | **Done** | importers/{zap,nuclei,trivy,sarif}.py; tests test_importers.py (6 tests) |
| R2 | Other scanners (OpenVAS, naabu/Nmap, Grype/Syft, Checkov, Prowler, kube-bench, OpenSCAP/Lynis, testssl, Gitleaks, MobSF) | Scanners | **Partial** | Only via SARIF (Semgrep/Checkov/Gitleaks emit SARIF); no native parsers for others |
| R3 | Platform RUNS scanners in isolated egress-locked runners | Target architecture | **Not done** | importers/__init__.py docstring: 'Attestra does not run scanners' — import-only |
| R4 | Kubernetes Jobs + Go on-prem runner agent (mTLS) | Tech stack | **Not done** | none |
| R5 | Per-runner egress IP / network policy | Guardrails | **Not done** | none |
| R6 | Continuous mode / scheduled rescans / CI-CD gates | Flow; Tech stack | **Not done** | 'continuous' is only an engagement type enum |
| R7 | Temporal resumable engagement workflow | E2E flow; Tech stack | **Not done** | none |
| R8 | ScanRun record with tool_version/profile, raw artifact + sha256 | Entities | **Partial** | ImportRun (models.py L143) stores raw file + sha256, no tool_version/profile/start/end |

### Findings, dedup & risk — 53%

| # | Requirement | Doc section | Status | Evidence (file:func/line, tests) |
|---|---|---|---|---|
| F1 | Common normalized finding schema | Data model | **Done** | importers/base.py NormalizedFinding; models.Finding |
| F2 | Fingerprint dedup across tools/runs | Finding fields | **Done** | fingerprint.py fingerprint(); test_services.py:29,38,87 |
| F3 | Risk = CVSS x (1+EPSS) x wKEV x wAsset x wExposure | Risk score | **Done** | scoring.py risk_score L37-48 (weights 1.5, 0.6-1.4, 1.3 exactly per doc); test_services.py:46,56 |
| F4 | CVSS v4 vector/score | Finding fields | **Partial** | cvss_score/cvss_vector stored as given; no v4 parsing/calculation |
| F5 | EPSS + CISA KEV enrichment | Prioritization data | **Done** | services.enrich L387; test_services.py:56 (operator-supplied files, no auto-fetch) |
| F6 | NVD/CVE auto-lookup | Prioritization data | **Not done** | none |
| F7 | Classification: owasp_top10, asvs_ref, wstg_ref | Finding fields | **Stub** | Only TEST_TYPES standard labels in models.py; no per-finding OWASP/ASVS/WSTG fields |
| F8 | Per-tenant tunable weights | Risk score | **Not done** | weights hard-coded |
| F9 | Per-tenant suppression rules / FP rate per tool | Risks | **Not done** | none |

### Lifecycle & SLA — 57%

| # | Requirement | Doc section | Status | Evidence (file:func/line, tests) |
|---|---|---|---|---|
| L1 | Status lifecycle new->triaged->validated->accepted/FP->fixed->retest_passed | Finding fields | **Done** | models.TRANSITIONS; services.transition L430; test_services.py:66,78 |
| L2 | Every transition: actor, time, reason | Finding fields | **Done** | audit.record in transition; reason required for FP/accept (L438) |
| L3 | SLA due from policy (critical 30d) | Finding fields | **Done-untested** | scoring.sla_due + config.SLA_DAYS; no dedicated test |
| L4 | Ageing report / SLA breach tracking | Crosswalk | **Not done** | none |
| L5 | Risk acceptance with owner, expiry, rationale | Crosswalk 12.3.1 | **Partial** | risk_accepted status + note; no owner/expiry |
| L6 | Ticket integration (Jira/GitHub) | Interchange | **Stub** | ticket_ref field only |
| L7 | Human validation fields (validated_by, method, evidence) | Finding fields | **Partial** | validated_by set; no validation_method |

### Platform infrastructure — 19%

| # | Requirement | Doc section | Status | Evidence (file:func/line, tests) |
|---|---|---|---|---|
| P1 | PostgreSQL 16 with RLS | Tech stack | **Partial** | SQLAlchemy, SQLite default, optional psycopg; no RLS; no Alembic (db.py ad-hoc migration) |
| P2 | OpenSearch | Tech stack | **Not done** | none |
| P3 | S3 Object Lock / SeaweedFS WORM storage | Tech stack | **Not done** | local filesystem data/ (services._store) |
| P4 | Vault/OpenBao/KMS per-tenant keys | Tech stack | **Not done** | none |
| P5 | Kubernetes deployment, SaaS + on-prem | Tech stack | **Not done** | no Dockerfile/Helm |
| P6 | Observability (OTel/Prometheus/Grafana/Loki) | Tech stack | **Not done** | only /api/health |
| P7 | DefectDojo / CISO Assistant integration | OSS landscape | **Not done** | custom models + own YAML libraries instead |
| P8 | FastAPI REST API | Tech stack | **Done** | api.py; test_api.py:8 |

### Identity, RBAC & tenancy — 10%

| # | Requirement | Doc section | Status | Evidence (file:func/line, tests) |
|---|---|---|---|---|
| T1 | Tenant entity with data_region, plan; hard isolation | Entities | **Partial** | models.Tenant (name/industry/contact only); no data_region/plan; no query scoping |
| T2 | SSO/MFA via Keycloak (OIDC/SAML) | Platform security | **Not done** | api.py L3-4: actor from X-Attestra-Actor header; UI cookie name |
| T3 | RBAC: tester, reviewer, client viewer, auditor RO | Platform security | **Not done** | no roles; any header value accepted |
| T4 | Per-tenant storage prefixes, keys, runner pools | Guardrails | **Not done** | none |
| T5 | Client portal / auditor view | Tech stack | **Not done** | single internal UI |

### UI — 44%

| # | Requirement | Doc section | Status | Evidence (file:func/line, tests) |
|---|---|---|---|---|
| U1 | Web UI: engagements, scope, imports, findings, compliance, reports | Tech stack/Frontend | **Done** | web/ui.py + 4 templates; test_scope.py:106 |
| U2 | React + TypeScript + shadcn tester workbench | Tech stack | **Not done** | server-rendered Jinja instead |
| U3 | Trend dashboards / search | Tech stack | **Not done** | none |
| U4 | CLI incl. demo | n/a (extra) | **Done-untested** | cli.py; demo exercised manually |

### Interchange formats — 25%

| # | Requirement | Doc section | Status | Evidence (file:func/line, tests) |
|---|---|---|---|---|
| X1 | In: SARIF, native outputs | Interchange | **Done** | importers; test_importers.py |
| X2 | In: CycloneDX SBOM / Dependency-Track / DefectDojo formats | Interchange | **Not done** | none |
| X3 | Out: OSCAL AR/POA&M, SARIF, CSV | Interchange; Report catalog | **Not done** | none |
| X4 | Out: DOCX (docxtpl) / PDF (Gotenberg) | Generation pipeline | **Not done** | HTML (Jinja) only, reports/render.py |

### AI / LLM — 0%

| # | Requirement | Doc section | Status | Evidence (file:func/line, tests) |
|---|---|---|---|---|
| A1 | LLM narrative/write-up drafting marked AI-generated | Generation pipeline | **Not done** | no LLM code |
| A2 | LLM triage / dedup hints / mapping suggestions | Tech stack | **Not done** | none |

### Legal & process — 17%

| # | Requirement | Doc section | Status | Evidence (file:func/line, tests) |
|---|---|---|---|---|
| G1 | RoE / authorization templates, legal pack | Guardrails; Next steps | **Partial** | tests/fixtures/authorization.txt sample + RoE text field; no templates |
| G2 | License review (AGPL/GPL/NPSL) | Risks | **Not done** | nothing vendored, so currently clean |
| G3 | v2.1 packs (CERT-In, RBI, SEBI, HIPAA, NIST CSF, DORA, CRA) | v2.1 | **Not done** | FRAMEWORKS = pci_dss_4, iso_27001_2022, soc2 only |

### Compliance crosswalk — 45%

| # | Requirement | Doc section | Status | Evidence (file:func/line, tests) |
|---|---|---|---|---|
| C1 | Hub CWE->objective->framework mapping | How mapping works | **Done** | engine.py:44-51; test_library_integrity |
| C2 | Status roll-up + process controls | Mapping step 4-5 | **Done** | engine.py:80-118; test_compliance_reports.py::test_pci_rollup_status_values, test_pci_open_critical_findings_lead_to_not_met |
| C3 | Assessor confirmation with rationale | Mapping step 5 | **Done** | services.confirm_control; test_compliance_reports.py::test_assessor_confirm_override, test_confirm_requires_rationale |
| C4 | PCI DSS 4.0.1 refs coverage (19/19; 29 refs) | Crosswalk | **Done** | controls.yaml; test_control_libraries.py::test_pci_crosswalk_coverage |
| C5 | ISO 27001:2022 refs coverage (12/12; 20 refs) | Crosswalk | **Done** | controls.yaml; test_control_libraries.py::test_iso_crosswalk_coverage |
| C6 | SOC 2 refs coverage (11/11; 14 refs) | Crosswalk | **Done** | controls.yaml; test_control_libraries.py::test_soc2_crosswalk_coverage |
| C7 | Mapping strength + rationale | Entities/Mapping | **Done** | compliance/engine.py:mappings_for_objective, ControlResult.mapping_*; API /compliance, CLI, compliance.html.j2 Mapping column; tests/test_c7_c11_mapping_soc2.py |
| C8 | CISO Assistant/OSCAL/SCF libraries | Mapping step 2-3 | **Done** | compliance/libraries/ (oscal.py, scf.py, common.py); cli `library-import`; test_control_libraries.py |
| C9 | PCI quarterly calendar, segmentation, ASV import | PCI features | **Done** | services.pci_scan_calendar, import_asv_results, importers/asv.py, migration 0009; /engagements/{id}/pci; test_c9_c10_pci_iso |
| C10 | ISO SoA, NC/CA, 9.2 sampling | ISO features | **Done** | SoaEntry, Nonconformity workflow, AuditSample (migration 0010); packs iso/*; /engagements/{id}/iso; test_c9_c10_pci_iso |
| C11 | SOC 2 Type II population/sample export | SOC2 features | **Done** | reports/soc2_sampling.py (seeded, SAMPLE_SIZE_TABLE); GET /api/engagements/{id}/soc2/sample (json/csv); CLI soc2-sample; tests/test_c7_c11_mapping_soc2.py |

### Reports & signing — 50%

| # | Requirement | Doc section | Status | Evidence (file:func/line, tests) |
|---|---|---|---|---|
| Q1 | Technical/executive/compliance reports (HTML) | Report catalog | **Done** | render.py; tests |
| Q2 | Versioning, SHA-256, immutable once signed | Pipeline 4 | **Done** | render.py:73-113 |
| Q3 | Four-eyes (author != approver) | Pipeline 3 | **Partial** | 2 steps not 3; no QA-reject loop |
| Q4 | cosign/X.509 signature | Pipeline 4 | **Partial** | HMAC local key, signing.py |
| Q5 | Tamper verify endpoint | Evidence chain | **Done** | api.py:257; test |
| Q6 | Retest/closure letter | Report catalog | **Not done** |  |
| Q7 | Letter of attestation | Report catalog | **Not done** |  |
| Q8 | PCI binder / ISO register / SOC2 period pack | Report catalog | **Partial** | generic compliance pack only |
| Q9 | Exec trend vs last cycle | Report catalog | **Partial** | top-5 only |
| Q10 | Client portal publishing | Pipeline 4 | **Not done** |  |

### Evidence & audit — 28%

| # | Requirement | Doc section | Status | Evidence (file:func/line, tests) |
|---|---|---|---|---|
| E1 | Hash at capture (evidence/imports/auth) | Evidence chain | **Done-untested** | services.py:43-58 (imports tested) |
| E2 | WORM storage | Evidence chain | **Partial** | content-addressed + chmod 0444, local disk |
| E3 | Masking of PAN/creds/PII | Evidence chain | **Not done** |  |
| E4 | Per-tenant encryption keys | Evidence chain | **Not done** |  |
| E5 | Retention per framework/tenant | Evidence chain | **Not done** |  |
| E6 | Append-only hash-chained audit log + verify | Evidence chain | **Done** | audit.py; test_services.py:94 |
| E7 | Audit covers downloads | Evidence chain | **Not done** | api.py:262 |
| E8 | Audit export for auditors | Evidence chain | **Not done** |  |

## What the Desktop predecessor already has that can fill gaps

Source: the Desktop predecessor implementation audit.

| Attestra gap | Predecessor asset | Caveat from that audit |
|---|---|---|
| S3/S4/S5 scope gate at dispatch | `core/authorization.py` fail-closed URL/path/image scope, re-authorized at run and resume (`engine.py:100-129`), tested | Image scope prefix-match bug (`authorization.py:382`); SSRF list narrow |
| R5 egress / SSRF safety | `core/dns_pin.py`, `core/http_safe.py` DNS/IP pinning + redirect re-auth, tested | ZAP is pinned only pre-flight, no egress confinement |
| R3 real scanner execution | `scanners/{trivy,semgrep,nuclei,zap}.py` + registry, argv-only subprocesses; Nuclei active-template gate (`nuclei_policy.py`) | Floating image tags; ZAP/Nuclei live runs not in tests; cancel doesn't kill subprocess |
| R7 durable jobs / S7 kill switch | durable jobs with cancel + recovery state | Cooperative cancel only |
| Q6 retest | retest outcomes with false-`verified_fixed` guards | ZAP correlation asset-blind |
| F7 OWASP refs | `owasp/mapping.py` WSTG/ASVS labels, tested | labels only |

Suggested path: port the predecessor's authorization + dns_pin + scanner adapters as Attestra's runner plane, emitting files Attestra already imports; fix the image-scope bug and ZAP egress first.

## Recommended next 5 tasks

1. Runner plane: reuse the predecessor scanners behind an Attestra job API, gated by the scope check (authorization valid + window + allow-list + intrusive flag), plus a kill switch.
2. Real identity: Keycloak OIDC + roles (tester/reviewer/lead/client/auditor) replacing the X-Attestra-Actor header; tenant scoping on every query.
3. Close crosswalk gaps (PCI 11.3.x/11.4.x/12.3.1, ISO A.8.22/6.1.2, SOC2 CC7.4/CC6.8/CC3.2) with strength+rationale per mapping; get QSA review.
4. Retest/closure letter + letter of attestation; 3-step four-eyes with reject loop; DOCX/PDF output and X.509/cosign signing.
5. Evidence hardening: masking at capture, S3 Object Lock/SeaweedFS backend, retention policy, audit-log download events + export.

---

# Appendix — Compliance / reports / evidence worker detail

# Gap analysis – part: tests, compliance, reports, evidence & audit
Checked against the architecture doc (v2: PCI, ISO 27001, SOC 2) on 2026-10-14. Code reviewed read-only in the Attestra working tree.
Legend: **Done** = built + tested · **Done-untested** = built, no test · **Partial** · **Stub** · **Not done**

## 1. Test run
- Command: `set TEMP=<local-temp> & .venv\Scripts\python.exe -m pytest -q -p no:cacheprovider` (from repo root)
- Result: **34 passed, 0 failed**, 1 warning (Starlette/httpx deprecation in fastapi.testclient), 5.9 s.
- Relevant tests: `tests/test_compliance_reports.py` (library integrity, PCI roll-up, CDE scoping, ISO merge, assessor override, four-eyes/sign/tamper, report versions + compliance pack), `tests/test_services.py:94` (audit chain tamper).

## 2. Compliance crosswalk
Library: `attestra/compliance/data/controls.yaml` (16 hub objectives: 12 finding-based, 4 process-based), CWE map `cwe_map.yaml`, engine `attestra/compliance/engine.py`.

| Framework | Refs in code | Refs the doc requires | Doc refs covered | Missing |
|---|---|---|---|---|
| PCI DSS 4.0.1 | 14 | 19 (counting 2.2.x as one) | **10/19 (53%)** | 11.3.1.1, 11.3.1.2, 11.3.2 (ASV import), 11.4.2, 11.4.3, 11.4.5, 11.4.6 (segmentation), 6.4.2, 12.3.1 |
| ISO 27001:2022 | 13 Annex A + Clause 10.2 | 12 | **9/12 (75%)** | A.8.22, Clause 6.1.2, Clause 8.2 (A.8.28 linked only to secure coding, not supply chain) |
| SOC 2 TSC | 9 | 11 | **8/11 (73%)** | CC7.4, CC6.8, CC3.2 |

Extra refs in code that the doc doesn't list: PCI 8.3.1, 7.2.1, 8.6.2, 10.2.1; ISO A.8.5, A.8.3, A.8.12, A.5.17, A.8.15; SOC2 CC7.2.

| Requirement | Status | Where |
|---|---|---|
| Hub-and-spoke CWE → objective → framework | Done | engine.py:44-51, controls.yaml:20-150 |
| Status roll-up (crit/high→not met, medium→partial) | Done | engine.py:80-90 |
| Process controls from engagement record | Done | engine.py:93-118 |
| Assessor confirms; confirmed status overrides proposal | Done | engine.py:176-179, services.py:480-501 |
| PCI CDE scoping via `in_cde` | Done | engine.py:54-59 |
| Mapping strength / rationale per mapping | Not done | controls.yaml has no strength/rationale fields |
| Loading from CISO Assistant / OSCAL / SCF | Not done | static YAML only |
| PCI quarterly scan calendar, rescan-until-clean | Not done | – |
| Segmentation tests per CDE boundary | Not done | – |
| ASV report import | Not done | – |
| ISO SoA view | Partial | compliance report lists Annex A statuses (templates/compliance.html.j2); not an SoA |
| ISO nonconformity/corrective-action records (10.2) | Partial | only as a control status (controls.yaml:134-141) |
| ISO 9.2 per-control evidence pack with sampling | Not done | – |
| SOC 2 Type II period population/sample export | Not done | – |
| Risk acceptance with owner/expiry (12.3.1) | Not done | lifecycle has risk_accepted status only (models.py:58-68) |

**Evidence packs:** one generic "compliance" HTML report per framework (render.py:61-99, compliance.html.j2) = **Partial**. PCI evidence binder by requirement, ISO evidence register, SOC 2 period pack = **Not done** as separate outputs.

## 3. Reports
| Requirement | Status | Where |
|---|---|---|
| Technical, executive, compliance reports | Done (HTML only) | render.py:19, templates/*.html.j2 |
| Exec trend vs last cycle, readiness % | Partial | top-5 + counts in render.py:41-56; no trend |
| DOCX via docxtpl / PDF via Gotenberg | Not done | output is `.html` (render.py:88) |
| Versioning | Done | render.py:73-80 |
| SHA-256 at generation, file made read-only | Done | render.py:84-90 |
| Four-eyes (approver ≠ author) | Done | render.py:102-110; tested |
| Three roles (tester submits → QA approves → lead signs) | Partial | only 2 steps: generate + approve-and-sign; no QA-reject loop |
| Signing | Partial | HMAC-SHA256 with a local key (signing.py:17-46), not cosign/X.509; not verifiable by a customer |
| Tamper check before sign + verify endpoint | Done | render.py:111-113, 120-131; api.py:257 |
| Immutable once signed | Done | render.py:107-108 |
| Retest / closure letter | Not done | retest exists only as finding status `retest_passed` (models.py:65-66, services.py:441-446) |
| Letter of attestation | Not done | – |
| OSCAL / SARIF / CSV export | Not done | – |
| LLM-drafted narrative marked AI-generated | Not done | – |
| Client portal publishing | Not done | download only (api.py:262) |

## 4. Evidence & audit chain
| Requirement | Status | Where |
|---|---|---|
| Hash at capture (evidence, raw scans, authorizations) | Done-untested for evidence; Done for imports | services.py:43-58, 152-153, 303-305, 450-459 |
| Write-once storage | Partial | content-addressed, no overwrite, chmod 0444 (services.py:51-58) – local disk, not S3 Object Lock/WORM; chmod is close to a no-op on Windows |
| Masking of card numbers/credentials/PII at capture | Not done | no masking code anywhere |
| Per-tenant encryption keys (KMS/Vault) | Not done | – |
| Retention per framework/tenant | Not done | – |
| Append-only hash-chained audit log | Done | audit.py:16-45; tested test_services.py:94 |
| Covers scans, status changes, approvals | Done | audit.record calls across services.py, render.py:98,116 |
| Covers downloads | Not done | api.py:262-268 doesn't log |
| Audit verify | Done | audit.py:36-45, api.py:271, cli `verify-audit` |
| Audit export for auditors | Not done | – |
| DB-level append-only enforcement | Not done | normal table (models.py:242-254); chain only detects edits |

## Rough completion for this scope
Compliance mapping ~60% · Evidence packs ~20% · Reports ~45% · Evidence/audit ~45%.
