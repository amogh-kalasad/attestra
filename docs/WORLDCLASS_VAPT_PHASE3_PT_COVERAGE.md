# World-Class VA + PT — Phase 3 Penetration Testing Coverage

**Source:** `Downloads/# MASTER PROMPT WORLD-CLASS VAPT PL.txt`  
**Prior:** `docs/WORLDCLASS_VAPT_PHASE1_AUDIT.md`, `docs/WORLDCLASS_VAPT_PHASE2_VALIDATION.md`  
**Date:** 2026-11-05

Product wording: **security testing** / **VA + PT**. Do not put historical internal labels in customer-facing reports or docs.

---

## What shipped

### 1. Checklist honesty
- `update_checklist_item` refuses `passed` when notes contain incomplete-coverage markers (`not covered`, `not tested`, `skipped`, `limited`, `forms not covered`, `blind`).
- Auto-apply never upgrades `blocked`→`passed` without evidence.
- Limited T21 XSS/SQLi probes record **`blocked`**, not **`passed`**, when notes admit gaps (ENG1 honesty fix).
- Limited INJ/XSS/FILE canaries similarly stay **`blocked`** on clean runs (“limited common-path … full coverage not tested”).

### 2. Safe PT probe expansions (non-destructive)
| Catalogue id | Category | Module |
| --- | --- | --- |
| T03 (extended) | Authentication | account enumeration differential, auth-state after cookie clear |
| T04–T06 | Authorization | IDOR/BOLA, roles, tenant (+ privilege helpers) |
| SESSION | Session | cookie flags, session presence, JWT `alg=none` (decode only) |
| INJ | Injection | ATTSTRA_CANARY reflected probes (max 4 GETs) |
| XSS | XSS | reflected canary only (no stored writes) |
| FILE | File | fake traversal; find only with sensitive content markers |
| T07 / disclosure | Infra observation | security-header / CORS observe helpers |

Deferred by policy: password spray, MFA abuse, destructive reset, time-based SQLi campaigns, stored XSS writes, file uploads.

### 3. Coverage matrix + snapshot
- `attestra/automated_vapt/testing/coverage_matrix.py` — Phase 3 category → capability → implemented/partial/deferred.
- `attestra/automated_vapt/coverage/` — `CoverageSnapshot` + `build_coverage_snapshot` (checklist + routes + automated case totals).
- `services.engagement_coverage_snapshot` for Phase 4/8 report wiring.
- Existing `auth_web/coverage.py` route/element summary remains the auth-web inventory source.

### Rule kept
Skipped / blocked / deferred / not executed → **never** `passed`.

---

## Files (primary)

- `attestra/auth_web/checklists.py`, `checklist_auto.py`
- `attestra/automated_vapt/testing/` — session, injection, xss, file, reflection, coverage_matrix, authn/authz/privilege expansions
- `attestra/automated_vapt/core/test_registry.py`, `orchestrator.py`
- `attestra/automated_vapt/coverage/`
- `attestra/services.py`
- `lat.md/architecture.md`, `lat.md/tests.md`
- Tests (local, uncommitted by habit): `tests/test_pt_coverage_phase3.py`, `tests/automated_vapt/test_phase3_safe_probes.py`

---

## Limits (Phase 4+)

- Full endpoint × method × param × role **execution ledger** still shallow (Phase 4).
- Report “Security testing coverage” chapter polish is Phase 8.
- Business-logic workflows remain largely deferred (app-specific).
- Catalogue T08–T18 remain validation/evidence/integration (not live PT modules).

---

## Stop

Phase 3 complete for review. Next on request: **Phase 4 — Coverage and Test Execution Engine**.
