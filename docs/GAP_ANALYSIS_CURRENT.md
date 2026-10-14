# Attestra — Gap analysis (implementation guide)

**Date:** 2026-10-14  
**Spec:** [`docs/IMPLEMENTATION_GUIDE.md`](IMPLEMENTATION_GUIDE.md) (Phases 0–8)  
**Codebase:** `attestra` v0.1.0 (local working tree)  
**Validation:** `pytest -q` → **228 passed, 1 skipped**; `ruff check attestra tests` clean; `lat check` clean  

This document supersedes the *status* of the older architecture-oriented [`GAP_ANALYSIS.md`](GAP_ANALYSIS.md) for **implementation progress**. Keep that file for historical comparison against the v2 architecture narrative; use **this file** for “what is done / what is pending” against the phased implementation guide.

---

## 1. Executive summary

| Band | Phases | Status |
| --- | --- | --- |
| **Done (local)** | 0 – Foundations | Complete |
| **Done (local)** | 1 – Runner plane | Complete (live scanner E2E optional / skipped without tools) |
| **Done (local)** | 2 – Identity, roles, tenancy | Complete (full Keycloak UI login still optional) |
| **Done (local)** | 3 – Compliance completeness | Complete (human QSA sign-off on library still pending) |
| **Done (local)** | 4 – Reports, letters, signing | Complete (WeasyPrint/DOCX rich path optional) |
| **Done (local)** | 5 – Evidence hardening | Complete (S3 live integration optional) |
| **Pending / blocked** | 6 – Production infrastructure | Not started (needs infra approval) |
| **Pending** | 7 – Product polish & integrations | Not started |
| **Pending / blocked** | 8 – GA & external validation | Blocked on 0–7 + external work |

**Rough completion vs guide steps P0.1–P5.6:** ~**54 / 54** marked implemented in the traceability matrix (with residual VERIFY / process items noted below).  
**Remaining guide steps P6–P8:** largely **not implemented** / infra-blocked.

**Next approved phase:** Phase 6 (production infrastructure), when you give go-ahead.

---

## 2. Scorecard by phase

| Phase | Theme | Guide steps | Done | Partial / residual | Pending |
| --- | --- | ---: | ---: | --- | --- |
| 0 | Foundations | 6 | 6 | CI not verified on GitHub Actions remote | — |
| 1 | Runner plane | 15 | 15 | Image digests are placeholders; live E2E skipped without tools | — |
| 2 | Identity / tenancy | 7 | 7 | OIDC claim validation present; full IdP PKCE UI when Keycloak ready | — |
| 3 | Compliance library | 10 | 10 | External QSA/ISO review recorded as *pending* in `REVIEW.md` | Human review |
| 4 | Reports & signing | 8 | 8 | WeasyPrint optional; OSCAL uses minimal structure schema not full NIST | — |
| 5 | Evidence hardening | 6 | 6 | S3 live MinIO integration optional | — |
| 6 | Production infra | 7 | 0 | — | All |
| 7 | Polish / integrations | 5 | 0 | — | All |
| 8 | GA / external | 5 | 0 | — | All |

---

## 3. What is done (Phases 0–5)

### Phase 0 — Foundations

| Item | Evidence |
| --- | --- |
| Pytest suite + fixtures | `tests/`, `tests/fixtures/` |
| Alembic | `alembic.ini`, `migrations/versions/0001_baseline.py` … `0005_*.py` |
| Ruff + CI workflow | `pyproject.toml` `[tool.ruff]`, `.github/workflows/ci.yml` |
| Security docs | `SECURITY.md`, `docs/THREAT_MODEL.md` |

### Phase 1 — Runner plane

| Item | Evidence |
| --- | --- |
| Scope / SSRF / DNS pin / safe HTTP | `attestra/runner/authorization.py`, `dns_pin.py`, `http_safe.py` |
| Scanner adapters + digests | `attestra/runner/scanners/*`, `SCANNER_IMAGES` |
| Gate, ScanRun, ScopeRule, Jobs | `gate.py`, models + mig `0002`, `attestra/jobs/*` |
| Kill switch, ownership | halt/resume, `ownership.py` |
| Scan API/UI + worker CLI | `api.py`, `web/ui.py`, `attestra worker` |

### Phase 2 — Identity, roles, tenancy

| Item | Evidence |
| --- | --- |
| Users, API keys, scrypt | `attestra/auth/keys.py`, models, mig `0003` |
| Six roles + `require(permission)` | `attestra/auth/roles.py`, `api.py` |
| Bearer / session (header actor removed) | `get_principal`, `/login`, CLI `--api-key` |
| Tenant scoping + storage prefixes | `services.scoped`, `_store(.../tenants/<id>/...)`, `migrate-storage` |
| Rate limit + security headers | `attestra/api_security.py` |
| OIDC behind flag | `attestra/auth/oidc.py`, optional `oidc` extra |

### Phase 3 — Compliance completeness

| Item | Evidence |
| --- | --- |
| Expanded PCI / ISO / SOC 2 library | `compliance/data/controls.yaml` |
| Mapping strength + rationale + integrity test | `cwe_map.yaml`, `tests/test_library_integrity.py` |
| Risk acceptance + expiry | `RiskAcceptance`, `expire-risk` CLI |
| ASV, segmentation, ScanSchedule, Nonconformity | models + services + UI/API |
| OWASP refs on findings | `compliance/owasp.py`, Finding columns |
| SoA / ageing reports | `iso_soa`, `ageing` templates |
| Library export + review stub | `compliance-export`, `compliance/data/REVIEW.md` |

### Phase 4 — Reports, letters, signing

| Item | Evidence |
| --- | --- |
| Submit → QA → sign (+ reject) | `submit_report`, `qa_approve`, `qa_reject`, `sign_report` |
| Retest false-close guard | `attestra/retest.py`, `Retest` model |
| Closure / attestation letters | `closure_letter`, `attestation_letter` kinds |
| DOCX / PDF export | `reports/export.py` (+ optional `docs` extra) |
| Ed25519 signing (HMAC fallback) | `reports/signing.py`, `cryptography` dependency |
| Framework packs | `reports/packs.py` |
| Executive trend SVG | `executive.html.j2` + `_context` |
| SARIF / CSV / OSCAL | `reports/sarif.py`, `oscal.py` |

### Migrations shipped

| Revision | Contents |
| --- | --- |
| `0001_baseline` | Core v0.1 schema |
| `0002_runner` | ScanRun, ScopeRule, Job, ownership columns |
| `0003_users` | User, ApiKey, TenantMembership, report user ids, tenant fields |
| `0004_compliance` | RiskAcceptance, ASV, segmentation, schedules, NC, OWASP cols |
| `0005_reports` | Retest, report workflow/QA/algorithm/export paths |
| `0006_evidence` | Evidence masking column, RetentionPolicy, report legal_hold, audit triggers |

### Phase 5 — Evidence hardening

| Item | Evidence |
| --- | --- |
| Masking at capture | `attestra/evidence/mask.py`; wired in `add_evidence` / import store |
| Storage Protocol | `attestra/storage/` local + optional S3 (`ATTESTRA_STORAGE`) |
| Retention + purge | `RetentionPolicy`, `attestra/ops/retention.py`, `attestra purge` |
| Append-only audit + export | SQLite triggers, download events, `GET /api/audit/export` |
| Backup/restore | `attestra/ops/backup.py`, `attestra backup` / `restore` |
| Feed refresh | `attestra enrich --refresh`, `ops/feeds.py`, catalog dates in reports |

---

## 4. Residuals inside “done” phases (not blockers for Phase 6)

These are implemented enough to mark the phase complete, but still have VERIFY / process follow-ups:

| Residual | Phase | Notes |
| --- | --- | --- |
| GitHub Actions green on remote | 0 | Workflow present; confirm after push |
| Scanner image digests | 1 | Placeholders — replace with real pinned digests before prod scans |
| Live scanner E2E | 1 | `@pytest.mark.integration` skipped without binaries |
| Full Keycloak login UI / PKCE | 2 | Flag + claim validation exist; wire UI when IdP is provisioned |
| Rotate `ATTESTRA_*` secrets | 2 | Dev defaults must change for shared deploy |
| QSA / ISO library sign-off | 3 | `REVIEW.md` reviewer fields still *pending* |
| WeasyPrint on Windows | 4 | Falls back to minimal PDF without GTK |
| Full NIST OSCAL JSON Schema | 4 | Minimal structural schema under `tests/schemas/` |
| Postgres RLS | — | Deferred to Phase 6 (app-layer `scoped()` is in place) |

---

## 5. What is pending

### Phase 6 — Production infrastructure (next)

| Step | Requirement | Status |
| --- | --- | --- |
| 6.1 | PostgreSQL 16 default + RLS | **Pending / infra** |
| 6.2 | Temporal workflows | **Pending / infra** |
| 6.3 | OPA/Rego scope policy | **Pending / infra** |
| 6.4 | Keycloak MFA default + Vault/OpenBao keys | **Pending / infra** |
| 6.5 | Dockerfile + Helm + NetworkPolicy | **Pending / infra** |
| 6.6 | OpenTelemetry / Prometheus / Grafana | **Pending / infra** |
| 6.7 | CI/CD import gates + scheduler UI polish | **Pending** |

### Phase 7 — Product polish and integrations

| Step | Requirement | Status |
| --- | --- | --- |
| 7.1 | Client portal / auditor read-only views | **Pending** |
| 7.2 | Jira/GitHub ticket sync + CycloneDX/SBOM importers | **Pending** |
| 7.3 | More scanner adapters (Prowler, kube-bench, etc.) | **Pending** |
| 7.4 | Per-tenant risk weights, suppressions | **Pending** |
| 7.5 | Legal pack + `docs/LICENSES.md` | **Pending** |

### Phase 8 — GA and external validation

| Step | Requirement | Status |
| --- | --- | --- |
| 8.1 | Third-party pentest of Attestra | **Blocked** (external) |
| 8.2 | Load test (locust/k6) on staging | **Blocked** (needs Phase 6 staging) |
| 8.3 | GA release / tag / CHANGELOG | **Pending** |
| 8.4 | v2.1 framework packs (CERT-In, RBI, …) | **Pending** |
| 8.5 | AI narratives (explicitly optional / default skip) | **Not started** (decide skip vs build) |

---

## 6. Security posture (current vs remaining)

| Concern | Then (pre Phase 2) | Now | Still open |
| --- | --- | --- | --- |
| Identity spoofing via free-text actor | Open | Mitigated (Bearer/session + user-id four-eyes) | Enable OIDC + rotate secrets for shared deploy |
| Out-of-scope / SSRF scanning | Open (no runner) | Mitigated in runner gate + SSRF/DNS pin | Live egress NetworkPolicy (Phase 6) |
| Cross-tenant leaks | Open | Mitigated in app (`scoped`, tenant storage) | Postgres RLS (Phase 6) |
| Evidence secrets in artifacts | Open | Mitigated (mask at capture) | Tune corpus / content-types as needed |
| Audit tampering | Partial (hash chain) | Mitigated (append-only triggers + download events + export) | Postgres revoke UPDATE/DELETE in deploy |
| Report signatures | HMAC-only | Ed25519 + HMAC fallback | Customer runbook for pub key verify |
| Backup integrity | Missing | Mitigated (manifest backup/restore) | Offline restore drills in ops |

---

## 7. Recommended sequence from here

1. **Pause for Phase 6 approval** — requires infra credentials / cluster decisions (Postgres RLS, Temporal, OPA, Keycloak, Vault, Helm).  
2. Phase 7 package-friendly items can partially start without K8s (legal pack, some importers).  
3. Phase 8 only after external pentest budget and a staging environment exist.

---

## 8. Traceability

| Document | Role |
| --- | --- |
| [`IMPLEMENTATION_GUIDE.md`](IMPLEMENTATION_GUIDE.md) | Authoritative phased steps |
| [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) | Per-step ID matrix (P0.1 … P8.*) |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Threats and mitigations |
| [`PHASES.md`](PHASES.md) / [`ROADMAP.md`](ROADMAP.md) | High-level roadmap |
| [`GAP_ANALYSIS.md`](GAP_ANALYSIS.md) | Older % scorecard vs architecture v2 (stale for runner/identity) |
| **This file** | Current done vs pending snapshot after Phases 0–5 |

---

## 9. One-line verdict

**Phases 0–5 are implemented and test-green locally; Phase 6 is next and needs infra approval; Phases 7–8 remain pending and mostly infrastructure- or externally blocked.**
