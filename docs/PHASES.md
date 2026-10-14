# Attestra - Phase Plan (Phase 0 to Phase 8)

Work through the phases in order. Each phase lists goal, tasks, dependencies, acceptance criteria and effort (ESTIMATE).

### Phase 0: Foundations and a safe baseline (start first)
**Goal:** a clean, repeatable base that can be changed safely.
**Depends on:** nothing.
1. Add schema migrations with Alembic and replace the ad-hoc migration in `db.py`. Files: `attestra/db.py`, new `migrations/`. Source: New.
2. Add CI with ruff and pytest (GitHub Actions). New file: `.github/workflows/ci.yml`. Source: Port (VAPT `ci.yml`).
3. Restore the tests to the GitHub copy. `tests/` was removed from `E:\GitHub\attestra` before the first push. Decide with the architecture owner whether tests belong in the repo (recommended: yes). Source: existing.
4. Add a `SECURITY.md` and a threat-model note covering the scope gate, signing key and audit chain. Source: New.
5. Fix the Starlette TestClient deprecation warning. Source: New.

**Acceptance:** CI is green on push. `alembic upgrade head` builds a fresh DB. 34 or more tests pass with no warnings promoted to errors.
**Tests:** a migration up/down test, the existing suite, and ruff.
**Effort:** 2–3 days (ESTIMATE).

### Phase 1: Runner plane, so Attestra runs scanners safely (highest risk)
**Goal:** Attestra itself dispatches Trivy, Semgrep, Nuclei and ZAP, and nothing can run without passing the scope gate.
**Depends on:** Phase 0.
1. Port the scope authorization module into `attestra/runner/authorization.py` and wire it to Attestra's Authorization, Asset and Engagement records. Source: Port `core/authorization.py`.
2. While porting, **fix the image-scope prefix bug**: exact match unless the entry ends in `*`. Source: Port + fix (VAPT audit R4).
3. Widen the SSRF policy: deny unless `ip.is_global`, unwrap IPv4-mapped IPv6, and block 100.64/10, 0.0.0.0/8 and `fd00:ec2::254`. Source: Port + fix (R10).
4. Port DNS/IP pinning and the safe HTTP client into `attestra/runner/{dns_pin,http_safe}.py`. Source: Port `core/dns_pin.py`, `core/http_safe.py`.
5. Port the subprocess base and the scanner adapters into `attestra/runner/scanners/{base,trivy,semgrep,nuclei,nuclei_policy,zap,registry}.py`. Adapters write raw output, and the existing `attestra/importers/*` parse it. Source: Port.
6. **Confine ZAP egress**: `--add-host host:pinned_ip`, a dedicated docker network or egress proxy that allows only the pinned IP and port, and a post-run check that every ZAP site URL is in scope (otherwise quarantine). Source: Port + fix (R1). New test: `tests/security/test_zap_pin_egress.py`.
7. **Pin scanner images by digest** and record tool name, version and digest on each run. Files: `attestra/config.py`, adapters. Source: Port + fix (R5).
8. Extend `ImportRun` into `ScanRun` with tool_version, profile, started_at, ended_at, raw_artifact_uri and raw_sha256. Hash the **full** raw output, not a truncated copy. Files: `models.py`, migration. Source: New.
9. Enforce the test window (`window_start`/`window_end`), the `intrusive_allowed` flag (which gates Nuclei active templates) and a per-asset rate limit, re-checked at dispatch **and** at resume. Files: `attestra/runner/gate.py`. Source: Port `engine.py` re-auth + New.
10. Add ScopeRule deny rules and patterns, as the spec's ScopeRule entity requires. Files: `models.py`, `services.py`. Source: New.
11. Port durable jobs into `attestra/jobs/` (enqueue, claim, recover, retry). Source: Port `jobs/durable.py`, `queue.py`, `instance_lock.py`.
12. **Kill switch:** an engagement-level halt that a lead or client can trigger. It sets a cancel flag, kills the scanner's process group immediately and writes an audit entry. Files: `attestra/jobs/`, `runner/scanners/base.py`, `api.py`. Source: Port + fix (R7).
13. Add the API and UI: `POST /engagements/{id}/scans`, scan status, and `POST /engagements/{id}/halt`. Source: New.
14. Target ownership verification: a DNS TXT record or HTTP well-known file token, which must pass before the first scan of an asset. Files: `attestra/runner/ownership.py`. Source: New.

**Acceptance:**
- Without a valid authorization, or outside the window, or for an off-list target, a scan is refused 100% of the time, with an audit entry for each refusal.
- The ZAP argv always contains the pin. A loopback DNS-rebind test and a 302-to-out-of-scope test show zero requests to the forbidden address.
- Halt kills a running scanner within 5 seconds.
- Every ScanRun carries the tool digest and the full-output sha256.
- An end-to-end run against local fixtures (Trivy fs, Semgrep, Nuclei and ZAP against a loopback test app) produces findings in Attestra.

**Tests:** port the VAPT security tests (`test_authorization`, `test_dns_ip_binding`, `test_redirect_reauth`, `test_nuclei_active_gate`) and add new tests for the kill switch, window and rate limit, plus a live loopback E2E. Never test against external targets.
**Effort:** 3–4 weeks (ESTIMATE). Porting saves roughly half compared with writing new (INFERENCE).

### Phase 2: Identity, roles and tenant isolation
**Goal:** real users, real roles, and no data leaking between clients.
**Depends on:** Phase 0. It can overlap the end of Phase 1.
1. Replace the `X-Attestra-Actor` header with authenticated users. Start with API keys and hashed passwords (port the VAPT `auth/keys.py` and `require_role`), then add OIDC. Files: `api.py`, `web/ui.py`, new `attestra/auth/`. Source: Port.
2. Add roles from the spec: tester, reviewer (QA), engagement lead, client viewer and auditor (read-only), plus admin. Every route carries a `require_role` check. Source: Port + New.
3. Add `tenant_id` scoping to every query through one helper, `services.scoped(...)`. Add Tenant `data_region` and `plan`. Files: `models.py`, `services.py`. Source: New.
4. Use per-tenant storage prefixes for evidence, raw files and reports. Files: `services._store`. Source: New.
5. Add a rate limit and security headers. Source: Port `api/security.py`.
6. Add Keycloak OIDC (auth code + PKCE, state/nonce, issuer and audience checks) behind a flag. Source: New (VAPT only has a stub).

**Acceptance:** anonymous requests to protected routes get 401. A cross-tenant read test returns 403 or 404 for every list and get endpoint. The role matrix is tested, and four-eyes cannot be bypassed by sending a different name.
**Tests:** a parametrized route × role × tenant matrix and OIDC tests against a mocked IdP.
**Effort:** 2–3 weeks (ESTIMATE).

### Phase 3: Compliance completeness
**Goal:** a mapping library that a QSA or ISO auditor can accept.
**Depends on:** Phase 2, so that assessor identity is real.
1. Add the missing PCI refs: 11.3.1.1, 11.3.1.2, 11.3.2 (ASV import), 11.4.2, 11.4.3, 11.4.5, 11.4.6, 6.4.2 and 12.3.1. File: `compliance/data/controls.yaml`. Source: New.
2. Add the missing ISO refs (A.8.22, Clause 6.1.2, Clause 8.2, A.5.21 supply chain) and the missing SOC 2 refs (CC7.4, CC6.8, CC3.2).
3. Give every mapping `strength` (full/partial) and a `rationale`, and add a library integrity test that fails if either is missing. Files: `controls.yaml`, `cwe_map.yaml`, `engine.py`.
4. Risk acceptance with an owner, expiry and rationale, which auto-expires back to open. Files: `models.py`, `services.py`.
5. ASV report import (attach and record attestation) and segmentation test records per CDE boundary.
6. A PCI quarterly scan calendar with "rescan until clean" tracking. This needs the Phase 1 scheduler.
7. Add `owasp_top10`, `asvs_ref` and `wstg_ref` to findings. Source: Port `owasp/mapping.py`.
8. An ISO SoA view and nonconformity/corrective-action records linked to findings and retests.
9. An ageing report and SLA breach list.
10. Get a QSA or ISO lead auditor to review the library. This is a process task.

**Acceptance:** doc coverage reaches PCI 19/19, ISO 12/12 and SOC 2 11/11. 100% of mappings have strength and rationale. Expired risk acceptances reopen automatically. Reviewer sign-off is recorded.
**Tests:** library integrity, roll-up cases for each new control, and risk-acceptance expiry.
**Effort:** 2–3 weeks of engineering plus external review time (ESTIMATE).

### Phase 4: Reports, letters and signing
**Goal:** the full report catalog in client-ready formats.
**Depends on:** Phases 2 and 3. Retest letters also need Phase 1.
1. A three-step workflow: tester submits, QA approves or rejects (rejection goes back to the tester), and the lead signs. File: `reports/render.py`.
2. Retest runs with false-fix guards. A finding becomes fixed only if the retest **actually fetched the affected asset**; otherwise it is "inconclusive". Use asset-aware correlation keys for DAST. Source: Port `findings/lifecycle.py` + fix (R2, R3).
3. A retest/closure letter and a letter of attestation (no vulnerability detail). New templates.
4. DOCX via docxtpl and PDF via Gotenberg, or WeasyPrint as a lighter local option (INFERENCE: decide with the architecture owner).
5. Replace HMAC with X.509 or cosign signatures that a customer can verify. File: `reports/signing.py`.
6. Framework packs: a PCI binder indexed by requirement, an ISO Annex A evidence register, and a SOC 2 period population and sample export (CSV).
7. Executive trend against the last cycle.
8. Exports: OSCAL Assessment Results and POA&M, SARIF, and CSV. Source: Port `reporting/sarif.py` + New.

**Acceptance:** every catalog item except CERT-In generates. A signature verifies with standard tooling outside Attestra. A QA reject loop works. A retest with an unreached asset never becomes fixed. OSCAL output validates against the NIST schema.
**Tests:** golden-file rendering, signature verification, a false-fixed regression test, and schema validation.
**Effort:** 3–4 weeks (ESTIMATE).

### Phase 5: Evidence hardening
**Goal:** evidence that is masked, immutable and retained correctly.
**Depends on:** Phase 2 (tenants) and Phase 1 (raw artifacts).
1. Mask card numbers (Luhn-checked), credentials, tokens and PII at capture, before hashing and storing, keeping a record that masking was applied. File: new `attestra/evidence/mask.py`.
2. A storage backend interface (local and S3 Object Lock or SeaweedFS). File: new `attestra/storage/`.
3. Retention policies per framework and tenant (PCI default ≥ 1 year) and a purge job that writes audit entries.
4. Audit download events, audit export (JSON/CSV with chain proof), and DB-level append-only enforcement (trigger or revoked UPDATE/DELETE).
5. Backup that covers the DB, evidence and reports, with a sha256 manifest and no silent fallback. Source: Port `ops/retention.py` + fix (R8).
6. KEV and EPSS refresh command, with the catalog date printed in reports. Source: Port + fix (R6).

**Acceptance:** a seeded test of 1,000 PAN/credential strings shows 0 left unmasked. Evidence cannot be overwritten in the S3 Object Lock test. Every download appears in the audit log. A restore passes the manifest check.
**Tests:** masking corpus, storage immutability, retention purge, backup/restore.
**Effort:** 2–3 weeks (ESTIMATE).

### Phase 6: Production infrastructure
**Goal:** a deployment that can run as SaaS or on-prem.
**Depends on:** Phases 1–5.
1. PostgreSQL 16 by default, with row-level security per tenant as a second layer under Phase 2 scoping.
2. Temporal for the engagement workflow (scope → scan → triage → validate → map → report → retest), replacing the ported durable jobs.
3. OPA/Rego scope policy, with the Phase 1 Python gate moved into Rego and the same test cases kept.
4. Keycloak as the default IdP with MFA. Vault or OpenBao for per-tenant keys used to encrypt raw evidence.
5. Containers and Helm. Scanners run as Kubernetes Jobs with NetworkPolicy and a per-runner egress IP. A Go on-prem runner agent (outbound mTLS) later.
6. Observability: OpenTelemetry, Prometheus, Grafana, Loki. Optionally OpenSearch for search and trends.
7. Scheduled scans and CI/CD gates (GitHub Actions and GitLab templates).

**Acceptance:** a Helm install on a clean cluster passes a smoke E2E. A cross-tenant SQL query returns 0 rows under RLS. Workflows resume after a pod kill. The OPA policy suite passes.
**Effort:** 6–10 weeks (ESTIMATE, the largest phase).

### Phase 7: Product polish and integrations
**Depends on:** Phase 6.
1. A client portal and auditor read-only view. React/TypeScript is in the spec, but keep Jinja until there's a real need (INFERENCE).
2. Jira and GitHub ticket sync for `ticket_ref`. CycloneDX SBOM and Dependency-Track import.
3. More scanners (Prowler, kube-bench, testssl.sh, Gitleaks, Checkov, naabu). Run GPL/AGPL tools (OpenVAS, MobSF) only as separate services.
4. Per-tenant risk weights and suppression rules, plus false-positive rate per tool.
5. Legal pack (RoE and authorization templates) and a license review (AGPL/GPL/NPSL).

**Effort:** 4–6 weeks (ESTIMATE).

### Phase 8: GA, then optional extras
1. A third-party pentest of Attestra itself, fixing everything critical or high. A load test.
2. v2.1 framework packs (CERT-In, RBI, SEBI CSCRF, DORA, NIST CSF 2.0) as YAML libraries only.
3. **AI (optional, last).** The user prefers **no LLM or paid AI unless the architecture owner requires it**. If required, add draft narratives marked "AI-generated" until a reviewer edits them, with no client data used for training and an off switch. Otherwise use template-based narratives.

**Effort:** GA hardening 2–3 weeks. AI 2 weeks if needed (ESTIMATE).

---


## 4. Milestone checklist

| Phase | Name | Overall % done after the phase (target, ESTIMATE) | Done? |
|---|---|---|---|
| Now | v0.1.0 import-and-report | 31% | ✅ |
| 0 | Foundations (CI, migrations, tests in repo) | 33% | ☐ |
| 1 | Runner plane and safety | 48% | ☐ |
| 2 | Identity, roles, tenancy | 56% | ☐ |
| 3 | Compliance completeness | 64% | ☐ |
| 4 | Reports, letters, signing | 73% | ☐ |
| 5 | Evidence hardening | 80% | ☐ |
| 6 | Production infra | 90% | ☐ |
| 7 | Polish and integrations | 96% | ☐ |
| 8 | GA (AI optional) | 100% (≈98% without AI) | ☐ |

The percentages use the same scoring method as `GAP_ANALYSIS.md`. They are projections (INFERENCE). Re-run the gap analysis at the end of each phase.

Total effort: about 6–9 months for one developer, or about 3–4 months for a team of 3–4 (ESTIMATE).

---

