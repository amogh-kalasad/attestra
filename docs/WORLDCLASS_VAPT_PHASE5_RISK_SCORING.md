# World-Class VA + PT — Phase 5 Risk Scoring Engine

**Source:** `Downloads/# MASTER PROMPT WORLD-CLASS VAPT PL.txt`  
**Prior:** `docs/WORLDCLASS_VAPT_PHASE4_COVERAGE_ENGINE.md`  
**Date:** 2026-11-05

Product wording: **security testing** / **VA + PT**. Do not equate priority ranking with CVSS.

---

## What this phase separates

| Concept | Field(s) | Meaning |
| --- | --- | --- |
| **Technical severity** | `Finding.severity`, `cvss_score`, `cvss_vector`, `cvss_version` | CVSS-driven severity of record |
| **Priority / business risk** | `Finding.risk_score`, `Finding.business_risk` | Work-order ranking with asset/exposure/EPSS/KEV modifiers |

`risk_score` is **not** a second CVSS. Reports and API label it as Priority / Business risk.

---

## CVSS of record

- `cvss_score` is never rewritten by `rescore()`.
- `cvss_vector` is validated as empty or CVSS 3.x / soft-accepted 4.0 on write (`validate_cvss_vector` / `soft_cvss_vector`). CVSS 4.0 is stored for display; scores are not invented from the vector without an official calculator.
- `cvss_version` is parsed from the vector prefix (e.g. `CVSS:3.1/...` → `3.1`) via `cvss_version_from_vector` and stored on import.
- When a real `cvss_score` is present, import may align `severity` via `align_severity_with_cvss` (unless severity was explicitly overridden).
- Technical report finding cards show CVSS version + vector alongside the score, and label `risk_score` as Priority / Business risk.

---

## Priority formula (unchanged math, clearer role)

```
risk_score = base × (1 + EPSS) × kev_factor × asset_weight × exposure_weight
```

- `base` = `cvss_score` when present, else default CVSS for the severity label
- Info with no CVSS on internet/CDE assets uses `INFO_INTERNET_BASE` (1.0)
- `kev_factor` = 1.5 when CISA KEV, else 1.0
- `asset_weight` = 0.6…1.4 from criticality (tenant overrides via Phase 7.4 tuning)
- `exposure_weight` = 1.3 for internet or CDE (defaults; tenant overrides supported)

Breakdown: `explain_risk_modifiers(...)` (also exposed on API as `risk_modifiers`).

---

## Business risk bands

`business_risk_band(risk_score)` maps the **priority score** (not CVSS) to:

| Band | Threshold on `risk_score` |
| --- | --- |
| `critical` | ≥ 9.0 |
| `high` | ≥ 7.0 |
| `medium` | ≥ 4.0 |
| `low` | > 0.0 |
| `info` | = 0.0 |

`rescore(f)` sets `risk_score` and persisted `business_risk` from that helper.

---

## Informational observations

When `validation_status == informational` (Phase 2):

1. **Technical severity:** stays `info` unless a real `cvss_score` maps a band via `severity_from_cvss`.
2. **Priority / business risk:** always uses the **info base** (does not inflate as if confirmed).
3. `explain_risk_modifiers` sets `informational_capped=True` and documents the cap in `notes`.

---

## API surface (`_finding_dict`)

Exposes: `cvss_version`, `cvss_vector`, `cvss_score`, `severity` (technical), `risk_score`, `business_risk`, `risk_modifiers`.

---

## Site grade honesty (HSTS)

`grade.py` does not apply the HSTS-missing penalty when the claiming finding is `not_reproducible` / `informational` (or related validation FP) or when engagement evidence shows `Strict-Transport-Security` with max-age. The check still counts as tested (pass), not `not_tested`.

**Gemini grade choice:** missing-HSTS severity defaults to Low (not Medium/CVSS 5.0) without an SSL-strip PoC. HTTPS-redirect / HTTPS-only cases classify as `informational` and therefore skip −20. Unvalidated Low HSTS-missing still applies −20 — severity honesty first; grade softens only through `validation_status`.

## Report honesty

Technical summary open-vuln KPIs exclude informational / not_reproducible validation observations. Risk legend distinguishes CVSS technical severity from priority/business risk.

---

## Primary files

- `attestra/scoring.py` — `validate_cvss_vector` / `soft_cvss_vector` (3.x + 4.0), `cvss_version_from_vector`, `align_severity_with_cvss`, `risk_score`, `business_risk_band`, `explain_risk_modifiers`
- `attestra/services.py` — `import_results` (version + align + preserve score), `rescore`
- `attestra/models.py` — `Finding.business_risk`, `Finding.cvss_version`
- `attestra/api.py` — `_finding_dict` (`cvss_version`, `business_risk`, `risk_modifiers`)
- `attestra/grade.py` — HSTS contradiction / validation_status honesty
- `attestra/reports/render.py`, `templates/technical.html.j2`, DOCX/PDF legends
- `attestra/web/templates/finding.html` — technical severity vs priority + CVSS version/vector
- `docs/WORLDCLASS_VAPT_PHASE5_RISK_SCORING.md` (this file)
- Tests (local): `tests/test_risk_scoring_phase5.py`, `tests/test_risk_scoring_phase5_grade.py`

---

## Stop

Phase 5 complete for review. Next on request: **Phase 6 — Finding Normalization and Deduplication**.

---

## Limits (later)

- Full official CVSS 4.0 calculator is not implemented; v4 vectors are soft-accepted for storage/display and scanner-provided scores are kept — scores are never invented from a v4 vector alone.
- Further site-grade Pass/Fail polish beyond the HSTS evidence/validation skip remains optional.

---

## Stop

Phase 5 risk scoring separation complete for review. Next on request: **Phase 6 — Finding Normalization and Deduplication**.
