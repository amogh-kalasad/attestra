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
