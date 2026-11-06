# World-Class VA + PT — Phase 2 Finding Validation Engine

**Source:** `Downloads/# MASTER PROMPT WORLD-CLASS VAPT PL.txt`  
**Prior:** `docs/WORLDCLASS_VAPT_PHASE1_AUDIT.md`  
**Date:** 2026-11-05

Product wording: **security testing** / **VA + PT**. Do not put the historical internal “elite” label in customer-facing reports or docs.

---

## What shipped

1. **`attestra/finding_validation/`** — general classifiers (no hardcoded ENG1 finding IDs).
2. **`Finding.validation_status` + `validation_reasons`** — separate from workflow `status`.
3. **Import wiring** — `services.import_results` classifies on create/merge; reconciles after HTTP pair capture.
4. **Automated testing create gate** — `should_create_elite_finding` blocks likely FP; maps validation class onto the finding.
5. **ZAP evidence** — importer/proof capture surface request/response headers when the report includes them (traditional-json often still omits messages; known limitation).

### Validation classes

| Status | Meaning |
| --- | --- |
| `unvalidated` | Scanner/import alert; not confirmed |
| `confirmed` | Evidence-backed confirmation (automated path) |
| `needs_manual_validation` | Analyst review required |
| `potential` | Indicators without full proof |
| `false_positive` | Validation class (workflow FP still via transition) |
| `informational` | Hardening/noise, not a confirmed vuln |
| `not_reproducible` | Claim contradicted by evidence |
| `accepted_risk` | Reserved for risk-acceptance mapping |

Workflow `status` (`new` / `triaged` / `validated` / …) is unchanged by classifiers.

### ENG1 v21 anchors addressed (general rules)

| Issue | Rule |
| --- | --- |
| CORS on `/cdn-cgi/challenge-platform` | informational |
| SameSite on `cf_clearance` / CF cookies | informational |
| Permissions-Policy missing on cdn-cgi | informational |
| HSTS missing vs evidence with max-age | not_reproducible (classify + reconcile) |
| HSTS missing, no SSL-strip PoC | severity Low (not Medium/CVSS 5.0); unvalidated |
| HSTS missing + HTTP→HTTPS / HTTPS-only evidence, no SSL-strip PoC | informational, severity Low (grade −20 skipped via validation_status) |
| SPF on host without MX (subdomain) | informational (apex/root often owns mail posture) |
| DANE/TLSA missing | informational (impractical without DNSSEC / Cloudflare) |
| Weak ciphers without suite names | needs_manual_validation |
| XSS-Protection → CWE-79 / Injection | informational, CWE 693, A05, severity info |

### Grade choice (HSTS −20)

Severity/risk honesty first. Classify + `normalize_severity_for_import` / webcheck+Observatory defaults keep missing-HSTS at **Low**. When classify marks the finding **informational** (HTTPS redirect / HTTPS-only without SSL-strip PoC), existing grade rules skip the HSTS-missing −20. Plain **unvalidated** Low HSTS-missing still takes −20.

---

## Files

- `attestra/finding_validation/*`
- `attestra/models.py` (fields)
- `attestra/services.py` (import + reconcile)
- `attestra/automated_vapt/integrations/attestra_findings.py`
- `attestra/automated_vapt/core/orchestrator.py`
- `attestra/importers/zap.py`, `attestra/proof/capture.py`, `attestra/runner/scanners/zap.py`
- `attestra/api.py`, `attestra/reports/labels.py`
- `lat.md/findings.md`, `architecture.md`, `tests.md`, runner/import-pipeline notes
- Tests (local): `tests/test_finding_validation.py`

---

## Limits

- ZAP packaged `-J` traditional-json often has no message bodies; contradiction reconcile needs captured HTTP pairs (e.g. Nuclei) or traditional-json-plus.
- Remediation text for Permissions-Policy (CSP snippets) is Phase 7.
- Site-grade Pass/Fail contradictions are Phase 5.
- Report cards do not yet highlight `validation_status` as a primary chip (Phase 8).

---

## Stop

Phase 2 complete for review. Next on request: **Phase 3 — Penetration Testing Coverage Engine**.
