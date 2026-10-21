# Gap Implementation Plan — Progress

Source: `Attestra_Gap_Implementation_Plan.docx` (21 Oct 2026). 58 items across Phases 0–6.

## Phase 0 — Critical integrity & security (6/6 done)

| ID | Item | Status | Evidence |
| --- | --- | --- | --- |
| P0-1 | Auditor ownership of control confirmations | Done | `compliance.confirm` = auditor/admin; `confirm_control(role=...)`; tests |
| P0-2 | Block `met` while open findings | Done | Refuse unless `allow_open_findings_override`; tests |
| P0-3 | Require risk-acceptance record | Done | Bare transition refused; UI accept-risk form; tests |
| P0-4 | Share page untested ≠ A+/100 | Done | `share/service.py` + `share_public.html` + badge |
| P0-5 | Protect `/metrics` | Done | Default 401; token / admin session / `ALLOW_ANON` |
| P0-6 | Risk acceptance ≠ met for CC3.2 / Art.6 | Done | `has_risk_assessment` → partial |

Tests: `tests/test_phase0_integrity.py` (+ updated observability / compliance tests).

## Phase 1 — Stability / UX (partial)

| ID | Item | Status |
| --- | --- | --- |
| P1-1 | Report re-export HTTP 500 | Done — atomic replace of read-only exports |
| P1-3 | Findings CSV empty target | Done — `joinedload(asset)` + identifier |
| P1-5 | Select all frameworks | Done — robust JS + Clear |
| P1-2, P1-4, P1-6–P1-15 | Remaining medium/UX | Pending |

Tests: `tests/test_phase1_stability.py`.

## Phase 2 — Report front matter / fields

Largely delivered earlier (cover, TOC, document control, CVSS vector, retest kind, screenshots, disclaimer). Remaining: Impact/References migrations, box-type, date sanity, HTTP pair pretty-print.

## Phases 3–6

Not started in this pass (exports UI polish, workflow verify, auth testing, ASVS/portal/dashboards).

## How to verify

```bash
pytest -q tests/test_phase0_integrity.py tests/test_phase1_stability.py tests/test_observability.py
lat check
```
